package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// LogAlertHandler implements AlertHandler using structured logging
type LogAlertHandler struct {
	logger *zap.Logger
	mutex  sync.RWMutex

	// Alert suppression to prevent spam
	lastAlerts       map[string]time.Time
	suppressDuration time.Duration
}

// NewLogAlertHandler creates a new log-based alert handler
func NewLogAlertHandler(logger *zap.Logger, suppressDuration time.Duration) *LogAlertHandler {
	if suppressDuration == 0 {
		suppressDuration = 5 * time.Minute // Default suppression
	}

	return &LogAlertHandler{
		logger:           logger,
		lastAlerts:       make(map[string]time.Time),
		suppressDuration: suppressDuration,
	}
}

// SendAlert sends an alert using structured logging
func (lah *LogAlertHandler) SendAlert(ctx context.Context, level AlertLevel, component, message string) error {
	alertKey := fmt.Sprintf("%s:%s:%s", level, component, message)

	lah.mutex.Lock()
	defer lah.mutex.Unlock()

	// Check if we should suppress this alert
	if lastTime, exists := lah.lastAlerts[alertKey]; exists {
		if time.Since(lastTime) < lah.suppressDuration {
			// Alert suppressed
			return nil
		}
	}

	// Record this alert time
	lah.lastAlerts[alertKey] = time.Now()

	// Clean up old alert records periodically
	if len(lah.lastAlerts) > 100 {
		lah.cleanupOldAlerts()
	}

	// Send the alert based on level
	switch level {
	case AlertLevelCritical:
		lah.logger.Error("CRITICAL ALERT",
			zap.String("component", component),
			zap.String("message", message),
			zap.String("alert_level", string(level)),
			zap.String("correlation_id", getCorrelationIDFromContext(ctx)),
		)
	case AlertLevelWarning:
		lah.logger.Warn("WARNING ALERT",
			zap.String("component", component),
			zap.String("message", message),
			zap.String("alert_level", string(level)),
			zap.String("correlation_id", getCorrelationIDFromContext(ctx)),
		)
	case AlertLevelInfo:
		lah.logger.Info("INFO ALERT",
			zap.String("component", component),
			zap.String("message", message),
			zap.String("alert_level", string(level)),
			zap.String("correlation_id", getCorrelationIDFromContext(ctx)),
		)
	default:
		lah.logger.Info("UNKNOWN ALERT LEVEL",
			zap.String("component", component),
			zap.String("message", message),
			zap.String("alert_level", string(level)),
			zap.String("correlation_id", getCorrelationIDFromContext(ctx)),
		)
	}

	return nil
}

// cleanupOldAlerts removes old alert records to prevent memory leaks
func (lah *LogAlertHandler) cleanupOldAlerts() {
	cutoff := time.Now().Add(-lah.suppressDuration * 2)

	for key, alertTime := range lah.lastAlerts {
		if alertTime.Before(cutoff) {
			delete(lah.lastAlerts, key)
		}
	}
}

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const correlationIDKey contextKey = "correlation_id"

// getCorrelationIDFromContext extracts correlation ID from context
func getCorrelationIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	if correlationID, ok := ctx.Value(correlationIDKey).(string); ok {
		return correlationID
	}

	return ""
}

// MultiAlertHandler combines multiple alert handlers
type MultiAlertHandler struct {
	handlers []AlertHandler
	logger   *zap.Logger
}

// NewMultiAlertHandler creates a new multi-alert handler
func NewMultiAlertHandler(logger *zap.Logger, handlers ...AlertHandler) *MultiAlertHandler {
	return &MultiAlertHandler{
		handlers: handlers,
		logger:   logger,
	}
}

// SendAlert sends alerts to all configured handlers
func (mah *MultiAlertHandler) SendAlert(ctx context.Context, level AlertLevel, component, message string) error {
	var errors []error

	for i, handler := range mah.handlers {
		if err := handler.SendAlert(ctx, level, component, message); err != nil {
			mah.logger.Error("Alert handler failed",
				zap.Int("handler_index", i),
				zap.Error(err),
				zap.String("component", component),
				zap.String("message", message),
			)
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("alert handler failures: %v", errors)
	}

	return nil
}

// HealthCheckAlerter monitors health checks and sends alerts on failures
type HealthCheckAlerter struct {
	healthChecker *HealthChecker
	alertHandler  AlertHandler
	logger        *zap.Logger

	// Component alert levels
	componentLevels map[string]AlertLevel

	// Failure tracking
	failureCounts map[string]int
	maxFailures   int
	mutex         sync.RWMutex
}

// NewHealthCheckAlerter creates a new health check alerter
func NewHealthCheckAlerter(healthChecker *HealthChecker, alertHandler AlertHandler, logger *zap.Logger) *HealthCheckAlerter {
	return &HealthCheckAlerter{
		healthChecker:   healthChecker,
		alertHandler:    alertHandler,
		logger:          logger,
		componentLevels: make(map[string]AlertLevel),
		failureCounts:   make(map[string]int),
		maxFailures:     3, // Alert after 3 consecutive failures
	}
}

// SetComponentAlertLevel sets the alert level for a specific component
func (hca *HealthCheckAlerter) SetComponentAlertLevel(component string, level AlertLevel) {
	hca.mutex.Lock()
	defer hca.mutex.Unlock()
	hca.componentLevels[component] = level
}

// CheckAndAlert performs health checks and sends alerts for failures
func (hca *HealthCheckAlerter) CheckAndAlert(ctx context.Context) error {
	// Run all health checks
	hca.healthChecker.RunAllChecks(ctx)

	// Get check results
	checks := hca.healthChecker.GetChecks()

	hca.mutex.Lock()
	defer hca.mutex.Unlock()

	for name, check := range checks {
		if check.Status == StatusUnhealthy {
			// Increment failure count
			hca.failureCounts[name]++

			// Send alert if we've reached the failure threshold
			if hca.failureCounts[name] >= hca.maxFailures {
				alertLevel := AlertLevelWarning
				if level, exists := hca.componentLevels[name]; exists {
					alertLevel = level
				}

				message := fmt.Sprintf("Health check failed %d times: %s",
					hca.failureCounts[name], check.Message)

				if err := hca.alertHandler.SendAlert(ctx, alertLevel, name, message); err != nil {
					hca.logger.Error("Failed to send health check alert",
						zap.String("component", name),
						zap.Error(err),
					)
				}
			}
		} else {
			// Reset failure count on success
			if hca.failureCounts[name] > 0 {
				// Send recovery alert if we had failures before
				if hca.failureCounts[name] >= hca.maxFailures {
					message := fmt.Sprintf("Health check recovered after %d failures: %s",
						hca.failureCounts[name], check.Message)

					if err := hca.alertHandler.SendAlert(ctx, AlertLevelInfo, name, message); err != nil {
						hca.logger.Error("Failed to send recovery alert",
							zap.String("component", name),
							zap.Error(err),
						)
					}
				}

				hca.failureCounts[name] = 0
			}
		}
	}

	return nil
}

// GetFailureCounts returns the current failure counts for all components
func (hca *HealthCheckAlerter) GetFailureCounts() map[string]int {
	hca.mutex.RLock()
	defer hca.mutex.RUnlock()

	counts := make(map[string]int)
	for name, count := range hca.failureCounts {
		counts[name] = count
	}

	return counts
}

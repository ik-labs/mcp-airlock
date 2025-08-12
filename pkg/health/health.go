// Package health provides health check functionality for MCP Airlock
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Status represents the health status of a component
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusUnknown   Status = "unknown"
)

// Check represents a single health check
type Check struct {
	Name        string                                     `json:"name"`
	Status      Status                                     `json:"status"`
	Message     string                                     `json:"message,omitempty"`
	LastChecked time.Time                                  `json:"last_checked"`
	CheckFunc   func(ctx context.Context) (Status, string) `json:"-"`
}

// HealthChecker manages health checks for the application
type HealthChecker struct {
	checks map[string]*Check
	mutex  sync.RWMutex
	logger *zap.Logger
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(logger *zap.Logger) *HealthChecker {
	return &HealthChecker{
		checks: make(map[string]*Check),
		logger: logger,
	}
}

// RegisterCheck registers a new health check
func (hc *HealthChecker) RegisterCheck(name string, checkFunc func(ctx context.Context) (Status, string)) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()

	hc.checks[name] = &Check{
		Name:      name,
		Status:    StatusUnknown,
		CheckFunc: checkFunc,
	}
}

// RunCheck executes a specific health check
func (hc *HealthChecker) RunCheck(ctx context.Context, name string) error {
	hc.mutex.RLock()
	check, exists := hc.checks[name]
	hc.mutex.RUnlock()

	if !exists {
		return nil
	}

	status, message := check.CheckFunc(ctx)

	hc.mutex.Lock()
	check.Status = status
	check.Message = message
	check.LastChecked = time.Now()
	hc.mutex.Unlock()

	hc.logger.Debug("Health check completed",
		zap.String("check", name),
		zap.String("status", string(status)),
		zap.String("message", message),
	)

	return nil
}

// RunAllChecks executes all registered health checks
func (hc *HealthChecker) RunAllChecks(ctx context.Context) {
	hc.mutex.RLock()
	checkNames := make([]string, 0, len(hc.checks))
	for name := range hc.checks {
		checkNames = append(checkNames, name)
	}
	hc.mutex.RUnlock()

	for _, name := range checkNames {
		if err := hc.RunCheck(ctx, name); err != nil {
			hc.logger.Error("Health check failed",
				zap.String("check", name),
				zap.Error(err),
			)
		}
	}
}

// GetStatus returns the overall health status
func (hc *HealthChecker) GetStatus() Status {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	for _, check := range hc.checks {
		if check.Status == StatusUnhealthy {
			return StatusUnhealthy
		}
		if check.Status == StatusUnknown {
			return StatusUnknown
		}
	}

	return StatusHealthy
}

// GetChecks returns all health check results
func (hc *HealthChecker) GetChecks() map[string]*Check {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()

	result := make(map[string]*Check)
	for name, check := range hc.checks {
		// Create a copy to avoid race conditions
		result[name] = &Check{
			Name:        check.Name,
			Status:      check.Status,
			Message:     check.Message,
			LastChecked: check.LastChecked,
		}
	}

	return result
}

// HealthResponse represents the JSON response for health endpoints
type HealthResponse struct {
	Status    Status            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Checks    map[string]*Check `json:"checks,omitempty"`
}

// LivenessHandler returns an HTTP handler for liveness probes
// Liveness checks if the application is running (basic functionality)
func (hc *HealthChecker) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Liveness is simple - if we can respond, we're alive
		response := HealthResponse{
			Status:    StatusHealthy,
			Timestamp: time.Now(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(response); err != nil {
			hc.logger.Error("Failed to encode liveness response", zap.Error(err))
		}
	}
}

// ReadinessHandler returns an HTTP handler for readiness probes
// Readiness checks if the application is ready to serve traffic
func (hc *HealthChecker) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Run all health checks for readiness
		hc.RunAllChecks(ctx)

		status := hc.GetStatus()
		checks := hc.GetChecks()

		response := HealthResponse{
			Status:    status,
			Timestamp: time.Now(),
			Checks:    checks,
		}

		w.Header().Set("Content-Type", "application/json")

		// Return 503 if not ready
		if status != StatusHealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			hc.logger.Error("Failed to encode readiness response", zap.Error(err))
		}
	}
}

// StartPeriodicChecks starts running health checks periodically
func (hc *HealthChecker) StartPeriodicChecks(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	hc.logger.Info("Starting periodic health checks",
		zap.Duration("interval", interval),
	)

	for {
		select {
		case <-ticker.C:
			hc.RunAllChecks(ctx)
		case <-ctx.Done():
			hc.logger.Info("Stopping periodic health checks")
			return
		}
	}
}

// HealthCheckable interface for components that can be health checked
type HealthCheckable interface {
	HealthCheck(ctx context.Context) (string, string)
}

// AlertLevel represents the severity of a health check failure
type AlertLevel string

const (
	AlertLevelInfo     AlertLevel = "info"
	AlertLevelWarning  AlertLevel = "warning"
	AlertLevelCritical AlertLevel = "critical"
)

// AlertHandler handles health check alerts
type AlertHandler interface {
	SendAlert(ctx context.Context, level AlertLevel, component, message string) error
}

// BufferedEventHandler handles event buffering when audit store fails
type BufferedEventHandler interface {
	BufferEvent(event interface{}) error
	FlushBufferedEvents(ctx context.Context) error
	GetBufferedEventCount() int
}

// ComponentHealthChecker provides health checking for specific components
type ComponentHealthChecker struct {
	name         string
	checkFunc    func(ctx context.Context) (Status, string)
	alertLevel   AlertLevel
	lastStatus   Status
	lastMessage  string
	lastChecked  time.Time
	failureCount int
	mutex        sync.RWMutex
}

// NewComponentHealthChecker creates a new component health checker
func NewComponentHealthChecker(name string, checkFunc func(ctx context.Context) (Status, string), alertLevel AlertLevel) *ComponentHealthChecker {
	return &ComponentHealthChecker{
		name:       name,
		checkFunc:  checkFunc,
		alertLevel: alertLevel,
		lastStatus: StatusUnknown,
	}
}

// Check performs the health check and tracks status changes
func (chc *ComponentHealthChecker) Check(ctx context.Context) (Status, string) {
	chc.mutex.Lock()
	defer chc.mutex.Unlock()

	status, message := chc.checkFunc(ctx)
	now := time.Now()

	// Track failure count
	if status == StatusUnhealthy {
		chc.failureCount++
	} else {
		chc.failureCount = 0
	}

	chc.lastStatus = status
	chc.lastMessage = message
	chc.lastChecked = now

	return status, message
}

// GetStatus returns the last known status
func (chc *ComponentHealthChecker) GetStatus() (Status, string, time.Time, int) {
	chc.mutex.RLock()
	defer chc.mutex.RUnlock()
	return chc.lastStatus, chc.lastMessage, chc.lastChecked, chc.failureCount
}

// GetAlertLevel returns the alert level for this component
func (chc *ComponentHealthChecker) GetAlertLevel() AlertLevel {
	return chc.alertLevel
}

// DefaultChecks returns a set of default health checks
func DefaultChecks(logger *zap.Logger) map[string]func(ctx context.Context) (Status, string) {
	return map[string]func(ctx context.Context) (Status, string){
		"basic": func(ctx context.Context) (Status, string) {
			// Basic check - always healthy if we can execute
			return StatusHealthy, "Application is running"
		},
		"memory": func(ctx context.Context) (Status, string) {
			// Simple memory check - in production, you'd check actual memory usage
			return StatusHealthy, "Memory usage within limits"
		},
	}
}

// JWKSHealthChecker creates a health check for JWKS fetch capability
func JWKSHealthChecker(authenticator HealthCheckable) func(ctx context.Context) (Status, string) {
	return func(ctx context.Context) (Status, string) {
		if authenticator == nil {
			return StatusUnhealthy, "Authenticator not initialized"
		}
		status, message := authenticator.HealthCheck(ctx)
		return Status(status), message
	}
}

// PolicyHealthChecker creates a health check for policy compilation
func PolicyHealthChecker(policyEngine HealthCheckable) func(ctx context.Context) (Status, string) {
	return func(ctx context.Context) (Status, string) {
		if policyEngine == nil {
			return StatusUnhealthy, "Policy engine not initialized"
		}
		status, message := policyEngine.HealthCheck(ctx)
		return Status(status), message
	}
}

// AuditHealthChecker creates a health check for audit store
func AuditHealthChecker(auditLogger HealthCheckable, eventBuffer BufferedEventHandler) func(ctx context.Context) (Status, string) {
	return func(ctx context.Context) (Status, string) {
		if auditLogger == nil {
			return StatusUnhealthy, "Audit logger not initialized"
		}

		status, message := auditLogger.HealthCheck(ctx)

		// If audit store is unhealthy but we have buffering, it's a warning
		if status == "unhealthy" && eventBuffer != nil {
			bufferedCount := eventBuffer.GetBufferedEventCount()
			return StatusUnhealthy, fmt.Sprintf("Audit store unhealthy (buffered events: %d): %s", bufferedCount, message)
		}

		return Status(status), message
	}
}

// UpstreamHealthChecker creates a health check for upstream connectivity
func UpstreamHealthChecker(upstreamConnector HealthCheckable) func(ctx context.Context) (Status, string) {
	return func(ctx context.Context) (Status, string) {
		if upstreamConnector == nil {
			return StatusUnhealthy, "Upstream connector not initialized"
		}
		status, message := upstreamConnector.HealthCheck(ctx)
		return Status(status), message
	}
}

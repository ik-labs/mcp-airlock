// Package errors provides graceful degradation logic for system failures
package errors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DegradationMode represents different levels of service degradation
type DegradationMode int

const (
	// ModeNormal - all systems operational
	ModeNormal DegradationMode = iota
	// ModeAuditBuffering - audit store down, buffering events
	ModeAuditBuffering
	// ModePolicyLKG - policy engine down, using Last-Known-Good
	ModePolicyLKG
	// ModeEmergency - multiple systems down, minimal functionality
	ModeEmergency
)

// String returns the string representation of degradation mode
func (m DegradationMode) String() string {
	switch m {
	case ModeNormal:
		return "normal"
	case ModeAuditBuffering:
		return "audit_buffering"
	case ModePolicyLKG:
		return "policy_lkg"
	case ModeEmergency:
		return "emergency"
	default:
		return "unknown"
	}
}

// DegradationManager manages graceful degradation of services
type DegradationManager struct {
	logger *zap.Logger
	mu     sync.RWMutex

	// Current degradation state
	mode         DegradationMode
	degradations map[string]*ServiceDegradation

	// Event buffering for audit failures
	auditBuffer    []AuditEvent
	maxBufferSize  int
	bufferMu       sync.Mutex
	bufferOverflow bool

	// Alerting
	alertCallback AlertCallback
	lastAlert     map[string]time.Time
	alertCooldown time.Duration

	// Health monitoring
	healthChecks  map[string]HealthCheck
	checkInterval time.Duration
	stopChan      chan struct{}
}

// ServiceDegradation tracks degradation state for a service
type ServiceDegradation struct {
	ServiceName   string
	Mode          DegradationMode
	StartTime     time.Time
	LastError     error
	FailureCount  int
	LastSuccess   time.Time
	RecoveryCount int
}

// AuditEvent represents an audit event for buffering
type AuditEvent struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	CorrelationID string                 `json:"correlation_id"`
	Action        string                 `json:"action"`
	Subject       string                 `json:"subject"`
	Tenant        string                 `json:"tenant"`
	Decision      string                 `json:"decision"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// AlertCallback is called when critical alerts need to be sent
type AlertCallback func(ctx context.Context, alert *Alert)

// Alert represents a critical system alert
type Alert struct {
	Level       AlertLevel             `json:"level"`
	Service     string                 `json:"service"`
	Message     string                 `json:"message"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
	Correlation string                 `json:"correlation_id"`
}

// AlertLevel represents the severity of an alert
type AlertLevel int

const (
	AlertInfo AlertLevel = iota
	AlertWarning
	AlertCritical
	AlertEmergency
)

// String returns the string representation of alert level
func (l AlertLevel) String() string {
	switch l {
	case AlertInfo:
		return "info"
	case AlertWarning:
		return "warning"
	case AlertCritical:
		return "critical"
	case AlertEmergency:
		return "emergency"
	default:
		return "unknown"
	}
}

// HealthCheck represents a health check function
type HealthCheck func(ctx context.Context) error

// DegradationConfig defines configuration for degradation management
type DegradationConfig struct {
	MaxAuditBufferSize  int           `yaml:"max_audit_buffer_size" json:"max_audit_buffer_size"`
	AlertCooldown       time.Duration `yaml:"alert_cooldown" json:"alert_cooldown"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
}

// DefaultDegradationConfig returns default degradation configuration
func DefaultDegradationConfig() *DegradationConfig {
	return &DegradationConfig{
		MaxAuditBufferSize:  10000, // 10k events
		AlertCooldown:       5 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
	}
}

// NewDegradationManager creates a new degradation manager
func NewDegradationManager(logger *zap.Logger, config *DegradationConfig, alertCallback AlertCallback) *DegradationManager {
	if config == nil {
		config = DefaultDegradationConfig()
	}

	return &DegradationManager{
		logger:        logger,
		mode:          ModeNormal,
		degradations:  make(map[string]*ServiceDegradation),
		auditBuffer:   make([]AuditEvent, 0, config.MaxAuditBufferSize),
		maxBufferSize: config.MaxAuditBufferSize,
		alertCallback: alertCallback,
		lastAlert:     make(map[string]time.Time),
		alertCooldown: config.AlertCooldown,
		healthChecks:  make(map[string]HealthCheck),
		checkInterval: config.HealthCheckInterval,
		stopChan:      make(chan struct{}),
	}
}

// RegisterHealthCheck registers a health check for a service
func (dm *DegradationManager) RegisterHealthCheck(serviceName string, check HealthCheck) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.healthChecks[serviceName] = check
}

// Start begins health monitoring
func (dm *DegradationManager) Start(ctx context.Context) {
	go dm.runHealthChecks(ctx)
}

// Stop stops health monitoring
func (dm *DegradationManager) Stop() {
	close(dm.stopChan)
}

// GetMode returns the current degradation mode
func (dm *DegradationManager) GetMode() DegradationMode {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.mode
}

// RecordServiceFailure records a service failure and updates degradation state
func (dm *DegradationManager) RecordServiceFailure(serviceName string, err error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	degradation, exists := dm.degradations[serviceName]
	if !exists {
		degradation = &ServiceDegradation{
			ServiceName: serviceName,
			StartTime:   time.Now(),
		}
		dm.degradations[serviceName] = degradation
	}

	degradation.LastError = err
	degradation.FailureCount++

	// Update degradation mode based on service
	dm.updateDegradationMode(serviceName, err)

	// Send alert if needed
	dm.sendAlertIfNeeded(serviceName, AlertCritical, fmt.Sprintf("Service failure: %v", err))

	dm.logger.Error("Service failure recorded",
		zap.String("service", serviceName),
		zap.Error(err),
		zap.Int("failure_count", degradation.FailureCount),
		zap.String("degradation_mode", dm.mode.String()),
	)
}

// RecordServiceRecovery records a service recovery
func (dm *DegradationManager) RecordServiceRecovery(serviceName string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	degradation, exists := dm.degradations[serviceName]
	if !exists {
		return
	}

	degradation.LastSuccess = time.Now()
	degradation.RecoveryCount++

	// Check if we can improve degradation mode
	dm.checkRecovery()

	dm.logger.Info("Service recovery recorded",
		zap.String("service", serviceName),
		zap.Int("recovery_count", degradation.RecoveryCount),
		zap.String("degradation_mode", dm.mode.String()),
	)
}

// BufferAuditEvent buffers an audit event when audit store is unavailable
func (dm *DegradationManager) BufferAuditEvent(event AuditEvent) error {
	dm.bufferMu.Lock()
	defer dm.bufferMu.Unlock()

	// Check buffer capacity
	if len(dm.auditBuffer) >= dm.maxBufferSize {
		if !dm.bufferOverflow {
			dm.bufferOverflow = true
			dm.sendAlertIfNeeded("audit_buffer", AlertEmergency, "Audit buffer overflow - events being dropped")
		}
		return fmt.Errorf("audit buffer overflow: max size %d exceeded", dm.maxBufferSize)
	}

	dm.auditBuffer = append(dm.auditBuffer, event)

	// Alert on buffer growth
	bufferSize := len(dm.auditBuffer)
	if bufferSize > 0 && bufferSize%1000 == 0 {
		dm.sendAlertIfNeeded("audit_buffer", AlertWarning, fmt.Sprintf("Audit buffer size: %d events", bufferSize))
	}

	return nil
}

// FlushAuditBuffer returns and clears the audit buffer
func (dm *DegradationManager) FlushAuditBuffer() []AuditEvent {
	dm.bufferMu.Lock()
	defer dm.bufferMu.Unlock()

	if len(dm.auditBuffer) == 0 {
		return nil
	}

	events := make([]AuditEvent, len(dm.auditBuffer))
	copy(events, dm.auditBuffer)

	// Clear buffer
	dm.auditBuffer = dm.auditBuffer[:0]
	dm.bufferOverflow = false

	dm.logger.Info("Audit buffer flushed",
		zap.Int("event_count", len(events)),
	)

	return events
}

// GetAuditBufferSize returns the current audit buffer size
func (dm *DegradationManager) GetAuditBufferSize() int {
	dm.bufferMu.Lock()
	defer dm.bufferMu.Unlock()
	return len(dm.auditBuffer)
}

// IsAuditBuffering returns true if audit events are being buffered
func (dm *DegradationManager) IsAuditBuffering() bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.mode == ModeAuditBuffering || dm.mode == ModeEmergency
}

// updateDegradationMode updates the overall degradation mode
func (dm *DegradationManager) updateDegradationMode(serviceName string, _ error) {
	switch serviceName {
	case "audit":
		switch dm.mode {
		case ModeNormal:
			dm.mode = ModeAuditBuffering
		case ModePolicyLKG:
			dm.mode = ModeEmergency
		}

	case "policy":
		switch dm.mode {
		case ModeNormal:
			dm.mode = ModePolicyLKG
		case ModeAuditBuffering:
			dm.mode = ModeEmergency
		}

	case "upstream":
		// Upstream failures don't change degradation mode
		// They're handled by circuit breakers

	default:
		// Other service failures
		if dm.mode == ModeNormal {
			// Stay in normal mode for non-critical services
		}
	}
}

// checkRecovery checks if services have recovered and updates mode
func (dm *DegradationManager) checkRecovery() {
	auditHealthy := dm.isServiceHealthy("audit")
	policyHealthy := dm.isServiceHealthy("policy")

	switch dm.mode {
	case ModeEmergency:
		if auditHealthy && policyHealthy {
			dm.mode = ModeNormal
		} else if auditHealthy {
			dm.mode = ModePolicyLKG
		} else if policyHealthy {
			dm.mode = ModeAuditBuffering
		}

	case ModeAuditBuffering:
		if auditHealthy {
			dm.mode = ModeNormal
		}

	case ModePolicyLKG:
		if policyHealthy {
			dm.mode = ModeNormal
		}
	}
}

// isServiceHealthy checks if a service is currently healthy
func (dm *DegradationManager) isServiceHealthy(serviceName string) bool {
	degradation, exists := dm.degradations[serviceName]
	if !exists {
		return true // No recorded failures
	}

	// Consider healthy if last success is more recent than last error
	return degradation.LastSuccess.After(degradation.StartTime)
}

// sendAlertIfNeeded sends an alert if cooldown period has passed
func (dm *DegradationManager) sendAlertIfNeeded(service string, level AlertLevel, message string) {
	if dm.alertCallback == nil {
		return
	}

	alertKey := fmt.Sprintf("%s:%s", service, level.String())
	lastAlert, exists := dm.lastAlert[alertKey]

	if exists && time.Since(lastAlert) < dm.alertCooldown {
		return // Still in cooldown
	}

	alert := &Alert{
		Level:     level,
		Service:   service,
		Message:   message,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"degradation_mode": dm.mode.String(),
		},
	}

	// Send alert in goroutine to avoid blocking
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		dm.alertCallback(ctx, alert)
	}()

	dm.lastAlert[alertKey] = time.Now()
}

// runHealthChecks runs periodic health checks
func (dm *DegradationManager) runHealthChecks(ctx context.Context) {
	ticker := time.NewTicker(dm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dm.performHealthChecks(ctx)
		case <-dm.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// performHealthChecks executes all registered health checks
func (dm *DegradationManager) performHealthChecks(ctx context.Context) {
	dm.mu.RLock()
	checks := make(map[string]HealthCheck)
	for name, check := range dm.healthChecks {
		checks[name] = check
	}
	dm.mu.RUnlock()

	for serviceName, check := range checks {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := check(checkCtx)
		cancel()

		if err != nil {
			dm.RecordServiceFailure(serviceName, err)
		} else {
			dm.RecordServiceRecovery(serviceName)
		}
	}
}

// GetDegradationStatus returns the current degradation status
func (dm *DegradationManager) GetDegradationStatus() map[string]interface{} {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	status := map[string]interface{}{
		"mode":              dm.mode.String(),
		"audit_buffer_size": dm.GetAuditBufferSize(),
		"buffer_overflow":   dm.bufferOverflow,
		"services":          make(map[string]interface{}),
	}

	services := status["services"].(map[string]interface{})
	for name, degradation := range dm.degradations {
		services[name] = map[string]interface{}{
			"failure_count":  degradation.FailureCount,
			"recovery_count": degradation.RecoveryCount,
			"last_error":     degradation.LastError.Error(),
			"last_success":   degradation.LastSuccess,
			"start_time":     degradation.StartTime,
		}
	}

	return status
}

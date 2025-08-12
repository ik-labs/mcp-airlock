package errors

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestDegradationModeString(t *testing.T) {
	tests := []struct {
		mode     DegradationMode
		expected string
	}{
		{ModeNormal, "normal"},
		{ModeAuditBuffering, "audit_buffering"},
		{ModePolicyLKG, "policy_lkg"},
		{ModeEmergency, "emergency"},
		{DegradationMode(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.mode.String()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestAlertLevelString(t *testing.T) {
	tests := []struct {
		level    AlertLevel
		expected string
	}{
		{AlertInfo, "info"},
		{AlertWarning, "warning"},
		{AlertCritical, "critical"},
		{AlertEmergency, "emergency"},
		{AlertLevel(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestDefaultDegradationConfig(t *testing.T) {
	config := DefaultDegradationConfig()

	if config.MaxAuditBufferSize != 10000 {
		t.Errorf("expected MaxAuditBufferSize 10000, got %d", config.MaxAuditBufferSize)
	}

	if config.AlertCooldown != 5*time.Minute {
		t.Errorf("expected AlertCooldown 5m, got %v", config.AlertCooldown)
	}

	if config.HealthCheckInterval != 30*time.Second {
		t.Errorf("expected HealthCheckInterval 30s, got %v", config.HealthCheckInterval)
	}
}

func TestNewDegradationManager(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultDegradationConfig()

	alertCallback := func(ctx context.Context, alert *Alert) {
		// Alert callback for testing
	}

	dm := NewDegradationManager(logger, config, alertCallback)

	if dm.GetMode() != ModeNormal {
		t.Errorf("expected initial mode normal, got %v", dm.GetMode())
	}

	if dm.GetAuditBufferSize() != 0 {
		t.Errorf("expected initial buffer size 0, got %d", dm.GetAuditBufferSize())
	}
}

func TestRecordServiceFailure(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &DegradationConfig{
		MaxAuditBufferSize:  1000,
		AlertCooldown:       1 * time.Millisecond, // Short cooldown for testing
		HealthCheckInterval: 1 * time.Second,
	}

	var alertReceived *Alert
	alertCallback := func(ctx context.Context, alert *Alert) {
		alertReceived = alert
	}

	dm := NewDegradationManager(logger, config, alertCallback)

	// Record audit service failure
	testErr := errors.New("audit store connection failed")
	dm.RecordServiceFailure("audit", testErr)

	// Should transition to audit buffering mode
	if dm.GetMode() != ModeAuditBuffering {
		t.Errorf("expected mode audit_buffering, got %v", dm.GetMode())
	}

	// Should have sent alert
	time.Sleep(10 * time.Millisecond) // Allow goroutine to complete
	if alertReceived == nil {
		t.Error("expected alert to be sent")
	} else {
		if alertReceived.Level != AlertCritical {
			t.Errorf("expected critical alert, got %v", alertReceived.Level)
		}
		if alertReceived.Service != "audit" {
			t.Errorf("expected service 'audit', got %q", alertReceived.Service)
		}
	}
}

func TestRecordServiceRecovery(t *testing.T) {
	logger := zaptest.NewLogger(t)
	dm := NewDegradationManager(logger, nil, nil)

	// First record a failure
	testErr := errors.New("audit store connection failed")
	dm.RecordServiceFailure("audit", testErr)

	if dm.GetMode() != ModeAuditBuffering {
		t.Errorf("expected mode audit_buffering after failure, got %v", dm.GetMode())
	}

	// Then record recovery
	dm.RecordServiceRecovery("audit")

	if dm.GetMode() != ModeNormal {
		t.Errorf("expected mode normal after recovery, got %v", dm.GetMode())
	}
}

func TestMultipleServiceFailures(t *testing.T) {
	logger := zaptest.NewLogger(t)
	dm := NewDegradationManager(logger, nil, nil)

	// Record audit failure
	dm.RecordServiceFailure("audit", errors.New("audit failed"))
	if dm.GetMode() != ModeAuditBuffering {
		t.Errorf("expected mode audit_buffering, got %v", dm.GetMode())
	}

	// Record policy failure - should go to emergency mode
	dm.RecordServiceFailure("policy", errors.New("policy failed"))
	if dm.GetMode() != ModeEmergency {
		t.Errorf("expected mode emergency, got %v", dm.GetMode())
	}
}

func TestBufferAuditEvent(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &DegradationConfig{
		MaxAuditBufferSize:  3, // Small buffer for testing
		AlertCooldown:       1 * time.Millisecond,
		HealthCheckInterval: 1 * time.Second,
	}

	var alerts []*Alert
	var alertMu sync.Mutex
	alertCallback := func(ctx context.Context, alert *Alert) {
		alertMu.Lock()
		alerts = append(alerts, alert)
		alertMu.Unlock()
	}

	dm := NewDegradationManager(logger, config, alertCallback)

	// Buffer some events
	for i := 0; i < 3; i++ {
		event := AuditEvent{
			ID:            "event-" + string(rune(i+'1')),
			Timestamp:     time.Now(),
			CorrelationID: "corr-" + string(rune(i+'1')),
			Action:        "test_action",
			Subject:       "test_subject",
			Tenant:        "test_tenant",
		}

		err := dm.BufferAuditEvent(event)
		if err != nil {
			t.Errorf("unexpected error buffering event %d: %v", i, err)
		}
	}

	if dm.GetAuditBufferSize() != 3 {
		t.Errorf("expected buffer size 3, got %d", dm.GetAuditBufferSize())
	}

	// Try to buffer one more - should fail and trigger overflow alert
	overflowEvent := AuditEvent{
		ID:            "overflow-event",
		Timestamp:     time.Now(),
		CorrelationID: "overflow-corr",
		Action:        "test_action",
		Subject:       "test_subject",
		Tenant:        "test_tenant",
	}

	err := dm.BufferAuditEvent(overflowEvent)
	if err == nil {
		t.Error("expected error when buffer overflows")
	}

	// Check for overflow alert
	time.Sleep(10 * time.Millisecond)
	alertMu.Lock()
	foundOverflowAlert := false
	for _, alert := range alerts {
		if alert.Level == AlertEmergency && alert.Service == "audit_buffer" {
			foundOverflowAlert = true
			break
		}
	}
	alertMu.Unlock()

	if !foundOverflowAlert {
		t.Error("expected overflow alert to be sent")
	}
}

func TestFlushAuditBuffer(t *testing.T) {
	logger := zaptest.NewLogger(t)
	dm := NewDegradationManager(logger, nil, nil)

	// Buffer some events
	events := []AuditEvent{
		{
			ID:            "event-1",
			Timestamp:     time.Now(),
			CorrelationID: "corr-1",
			Action:        "test_action",
			Subject:       "test_subject",
			Tenant:        "test_tenant",
		},
		{
			ID:            "event-2",
			Timestamp:     time.Now(),
			CorrelationID: "corr-2",
			Action:        "test_action",
			Subject:       "test_subject",
			Tenant:        "test_tenant",
		},
	}

	for _, event := range events {
		err := dm.BufferAuditEvent(event)
		if err != nil {
			t.Errorf("unexpected error buffering event: %v", err)
		}
	}

	// Flush buffer
	flushedEvents := dm.FlushAuditBuffer()

	if len(flushedEvents) != 2 {
		t.Errorf("expected 2 flushed events, got %d", len(flushedEvents))
	}

	if dm.GetAuditBufferSize() != 0 {
		t.Errorf("expected buffer size 0 after flush, got %d", dm.GetAuditBufferSize())
	}

	// Verify event content
	for i, event := range flushedEvents {
		if event.ID != events[i].ID {
			t.Errorf("event %d: expected ID %q, got %q", i, events[i].ID, event.ID)
		}
	}

	// Flush empty buffer should return nil
	emptyFlush := dm.FlushAuditBuffer()
	if emptyFlush != nil {
		t.Errorf("expected nil when flushing empty buffer, got %v", emptyFlush)
	}
}

func TestIsAuditBuffering(t *testing.T) {
	logger := zaptest.NewLogger(t)
	dm := NewDegradationManager(logger, nil, nil)

	// Initially not buffering
	if dm.IsAuditBuffering() {
		t.Error("expected not buffering initially")
	}

	// After audit failure, should be buffering
	dm.RecordServiceFailure("audit", errors.New("audit failed"))
	if !dm.IsAuditBuffering() {
		t.Error("expected buffering after audit failure")
	}

	// In emergency mode, should also be buffering
	dm.RecordServiceFailure("policy", errors.New("policy failed"))
	if !dm.IsAuditBuffering() {
		t.Error("expected buffering in emergency mode")
	}
}

func TestHealthCheckRegistrationAndExecution(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &DegradationConfig{
		MaxAuditBufferSize:  1000,
		AlertCooldown:       1 * time.Second,
		HealthCheckInterval: 10 * time.Millisecond, // Fast for testing
	}

	dm := NewDegradationManager(logger, config, nil)

	// Register health checks
	auditHealthy := true
	auditCheck := func(ctx context.Context) error {
		if auditHealthy {
			return nil
		}
		return errors.New("audit unhealthy")
	}

	policyHealthy := true
	policyCheck := func(ctx context.Context) error {
		if policyHealthy {
			return nil
		}
		return errors.New("policy unhealthy")
	}

	dm.RegisterHealthCheck("audit", auditCheck)
	dm.RegisterHealthCheck("policy", policyCheck)

	// Start health monitoring
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dm.Start(ctx)

	// Wait for initial health checks
	time.Sleep(50 * time.Millisecond)

	// Should be in normal mode
	if dm.GetMode() != ModeNormal {
		t.Errorf("expected normal mode with healthy services, got %v", dm.GetMode())
	}

	// Make audit unhealthy
	auditHealthy = false
	time.Sleep(50 * time.Millisecond)

	// Should transition to audit buffering
	if dm.GetMode() != ModeAuditBuffering {
		t.Errorf("expected audit_buffering mode, got %v", dm.GetMode())
	}

	// Make policy unhealthy too
	policyHealthy = false
	time.Sleep(50 * time.Millisecond)

	// Should transition to emergency
	if dm.GetMode() != ModeEmergency {
		t.Errorf("expected emergency mode, got %v", dm.GetMode())
	}

	// Recover audit
	auditHealthy = true
	time.Sleep(50 * time.Millisecond)

	// Should transition to policy LKG
	if dm.GetMode() != ModePolicyLKG {
		t.Errorf("expected policy_lkg mode, got %v", dm.GetMode())
	}

	// Recover policy
	policyHealthy = true
	time.Sleep(50 * time.Millisecond)

	// Should return to normal
	if dm.GetMode() != ModeNormal {
		t.Errorf("expected normal mode after full recovery, got %v", dm.GetMode())
	}

	// Stop monitoring
	dm.Stop()
}

func TestGetDegradationStatus(t *testing.T) {
	logger := zaptest.NewLogger(t)
	dm := NewDegradationManager(logger, nil, nil)

	// Record some failures
	dm.RecordServiceFailure("audit", errors.New("audit failed"))
	dm.RecordServiceFailure("policy", errors.New("policy failed"))

	// Buffer some events
	event := AuditEvent{
		ID:            "test-event",
		Timestamp:     time.Now(),
		CorrelationID: "test-corr",
		Action:        "test_action",
		Subject:       "test_subject",
		Tenant:        "test_tenant",
	}
	dm.BufferAuditEvent(event)

	status := dm.GetDegradationStatus()

	// Check top-level fields
	if status["mode"] != "emergency" {
		t.Errorf("expected mode 'emergency', got %v", status["mode"])
	}

	if status["audit_buffer_size"] != 1 {
		t.Errorf("expected buffer size 1, got %v", status["audit_buffer_size"])
	}

	// Check services
	services, ok := status["services"].(map[string]interface{})
	if !ok {
		t.Fatal("expected services to be map[string]interface{}")
	}

	if len(services) != 2 {
		t.Errorf("expected 2 services, got %d", len(services))
	}

	// Check audit service
	auditService, exists := services["audit"]
	if !exists {
		t.Error("expected audit service in status")
	} else {
		auditMap, ok := auditService.(map[string]interface{})
		if !ok {
			t.Error("expected audit service to be map")
		} else {
			if auditMap["failure_count"] != 1 {
				t.Errorf("expected audit failure_count 1, got %v", auditMap["failure_count"])
			}
		}
	}
}

func TestAlertCooldown(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &DegradationConfig{
		MaxAuditBufferSize:  1000,
		AlertCooldown:       100 * time.Millisecond,
		HealthCheckInterval: 1 * time.Second,
	}

	var alertCount int
	var alertMu sync.Mutex
	alertCallback := func(ctx context.Context, alert *Alert) {
		alertMu.Lock()
		alertCount++
		alertMu.Unlock()
	}

	dm := NewDegradationManager(logger, config, alertCallback)

	// Record multiple failures quickly
	for i := 0; i < 5; i++ {
		dm.RecordServiceFailure("audit", errors.New("audit failed"))
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for alerts to be processed
	time.Sleep(50 * time.Millisecond)

	alertMu.Lock()
	initialCount := alertCount
	alertMu.Unlock()

	// Should have sent only one alert due to cooldown
	if initialCount != 1 {
		t.Errorf("expected 1 alert due to cooldown, got %d", initialCount)
	}

	// Wait for cooldown to expire
	time.Sleep(150 * time.Millisecond)

	// Record another failure
	dm.RecordServiceFailure("audit", errors.New("audit failed again"))
	time.Sleep(50 * time.Millisecond)

	alertMu.Lock()
	finalCount := alertCount
	alertMu.Unlock()

	// Should have sent another alert after cooldown
	if finalCount != 2 {
		t.Errorf("expected 2 alerts after cooldown, got %d", finalCount)
	}
}

// Benchmark tests
func BenchmarkBufferAuditEvent(b *testing.B) {
	logger := zaptest.NewLogger(b)
	dm := NewDegradationManager(logger, nil, nil)

	event := AuditEvent{
		ID:            "bench-event",
		Timestamp:     time.Now(),
		CorrelationID: "bench-corr",
		Action:        "bench_action",
		Subject:       "bench_subject",
		Tenant:        "bench_tenant",
		Metadata:      map[string]interface{}{"key": "value"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.BufferAuditEvent(event)
		if i%1000 == 999 {
			dm.FlushAuditBuffer() // Prevent buffer overflow
		}
	}
}

func BenchmarkRecordServiceFailure(b *testing.B) {
	logger := zaptest.NewLogger(b)
	dm := NewDegradationManager(logger, nil, nil)

	testErr := errors.New("benchmark error")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		serviceName := "service-" + string(rune(i%10+'0'))
		dm.RecordServiceFailure(serviceName, testErr)
	}
}

func BenchmarkGetDegradationStatus(b *testing.B) {
	logger := zaptest.NewLogger(b)
	dm := NewDegradationManager(logger, nil, nil)

	// Set up some state
	dm.RecordServiceFailure("audit", errors.New("test"))
	dm.RecordServiceFailure("policy", errors.New("test"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.GetDegradationStatus()
	}
}

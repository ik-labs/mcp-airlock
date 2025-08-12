package health

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
)

func TestLogAlertHandler_SendAlert(t *testing.T) {
	// Create logger with observer to capture log output
	core, recorded := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	handler := NewLogAlertHandler(logger, 1*time.Minute)

	ctx := context.Background()

	// Test critical alert
	err := handler.SendAlert(ctx, AlertLevelCritical, "test-component", "critical failure")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check that alert was logged
	logs := recorded.All()
	if len(logs) != 1 {
		t.Errorf("Expected 1 log entry, got %d", len(logs))
	}

	log := logs[0]
	if log.Level != zapcore.ErrorLevel {
		t.Errorf("Expected ERROR level for critical alert, got %s", log.Level)
	}

	if log.Message != "CRITICAL ALERT" {
		t.Errorf("Expected message 'CRITICAL ALERT', got %s", log.Message)
	}

	// Check fields
	fields := log.ContextMap()
	if fields["component"] != "test-component" {
		t.Errorf("Expected component 'test-component', got %v", fields["component"])
	}
	if fields["message"] != "critical failure" {
		t.Errorf("Expected message 'critical failure', got %v", fields["message"])
	}
	if fields["alert_level"] != string(AlertLevelCritical) {
		t.Errorf("Expected alert_level '%s', got %v", AlertLevelCritical, fields["alert_level"])
	}
}

func TestLogAlertHandler_AlertSuppression(t *testing.T) {
	core, recorded := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	handler := NewLogAlertHandler(logger, 100*time.Millisecond)

	ctx := context.Background()

	// Send first alert
	err := handler.SendAlert(ctx, AlertLevelWarning, "test-component", "warning message")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Send same alert immediately (should be suppressed)
	err = handler.SendAlert(ctx, AlertLevelWarning, "test-component", "warning message")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should only have one log entry (second was suppressed)
	logs := recorded.All()
	if len(logs) != 1 {
		t.Errorf("Expected 1 log entry due to suppression, got %d", len(logs))
	}

	// Wait for suppression period to expire
	time.Sleep(150 * time.Millisecond)

	// Send same alert again (should not be suppressed)
	err = handler.SendAlert(ctx, AlertLevelWarning, "test-component", "warning message")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should now have two log entries
	logs = recorded.All()
	if len(logs) != 2 {
		t.Errorf("Expected 2 log entries after suppression period, got %d", len(logs))
	}
}

func TestLogAlertHandler_DifferentAlertLevels(t *testing.T) {
	core, recorded := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	handler := NewLogAlertHandler(logger, 1*time.Minute)

	ctx := context.Background()

	// Test different alert levels
	testCases := []struct {
		level         AlertLevel
		expectedLevel zapcore.Level
	}{
		{AlertLevelCritical, zapcore.ErrorLevel},
		{AlertLevelWarning, zapcore.WarnLevel},
		{AlertLevelInfo, zapcore.InfoLevel},
	}

	for _, tc := range testCases {
		err := handler.SendAlert(ctx, tc.level, "component", "message")
		if err != nil {
			t.Errorf("Unexpected error for level %s: %v", tc.level, err)
		}
	}

	logs := recorded.All()
	if len(logs) != len(testCases) {
		t.Errorf("Expected %d log entries, got %d", len(testCases), len(logs))
	}

	for i, tc := range testCases {
		if logs[i].Level != tc.expectedLevel {
			t.Errorf("Expected log level %s for alert level %s, got %s",
				tc.expectedLevel, tc.level, logs[i].Level)
		}
	}
}

func TestMultiAlertHandler(t *testing.T) {
	core1, recorded1 := observer.New(zapcore.InfoLevel)
	logger1 := zap.New(core1)
	handler1 := NewLogAlertHandler(logger1, 1*time.Minute)

	core2, recorded2 := observer.New(zapcore.InfoLevel)
	logger2 := zap.New(core2)
	handler2 := NewLogAlertHandler(logger2, 1*time.Minute)

	multiHandler := NewMultiAlertHandler(logger1, handler1, handler2)

	ctx := context.Background()
	err := multiHandler.SendAlert(ctx, AlertLevelWarning, "component", "message")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Both handlers should have received the alert
	logs1 := recorded1.All()
	logs2 := recorded2.All()

	if len(logs1) != 1 {
		t.Errorf("Expected 1 log entry in handler1, got %d", len(logs1))
	}
	if len(logs2) != 1 {
		t.Errorf("Expected 1 log entry in handler2, got %d", len(logs2))
	}
}

func TestHealthCheckAlerter(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hc := NewHealthChecker(logger)

	core, recorded := observer.New(zapcore.InfoLevel)
	alertLogger := zap.New(core)
	alertHandler := NewLogAlertHandler(alertLogger, 1*time.Minute)

	alerter := NewHealthCheckAlerter(hc, alertHandler, logger)

	// Set component alert levels
	alerter.SetComponentAlertLevel("critical-component", AlertLevelCritical)
	alerter.SetComponentAlertLevel("warning-component", AlertLevelWarning)

	// Register health checks
	criticalFailureCount := 0
	hc.RegisterCheck("critical-component", func(ctx context.Context) (Status, string) {
		criticalFailureCount++
		if criticalFailureCount < 4 { // Fail for first 3 calls, recover on 4th
			return StatusUnhealthy, "component failing"
		}
		return StatusHealthy, "component recovered"
	})

	warningFailureCount := 0
	hc.RegisterCheck("warning-component", func(ctx context.Context) (Status, string) {
		warningFailureCount++
		if warningFailureCount < 10 { // Keep failing for the test
			return StatusUnhealthy, "warning condition"
		}
		return StatusHealthy, "warning recovered"
	})

	ctx := context.Background()

	// First check - should not alert yet (failure count < 3)
	err := alerter.CheckAndAlert(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	logs := recorded.All()
	if len(logs) != 0 {
		t.Errorf("Expected 0 alerts on first failure, got %d", len(logs))
	}

	// Second check - still no alert
	err = alerter.CheckAndAlert(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	logs = recorded.All()
	if len(logs) != 0 {
		t.Errorf("Expected 0 alerts on second failure, got %d", len(logs))
	}

	// Third check - should trigger alerts for both components
	err = alerter.CheckAndAlert(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	logs = recorded.All()
	if len(logs) < 2 {
		t.Errorf("Expected at least 2 alerts on third failure, got %d", len(logs))
	}

	// Check alert levels - look for the specific alert messages
	criticalAlert := false
	warningAlert := false

	for _, log := range logs {
		if strings.Contains(log.Message, "CRITICAL") && strings.Contains(log.ContextMap()["component"].(string), "critical-component") {
			criticalAlert = true
		}
		if strings.Contains(log.Message, "WARNING") && strings.Contains(log.ContextMap()["component"].(string), "warning-component") {
			warningAlert = true
		}
	}

	if !criticalAlert {
		t.Error("Expected critical alert for critical-component")
	}
	if !warningAlert {
		t.Error("Expected warning alert for warning-component")
	}

	// Fourth check - critical component recovers, should send recovery alert
	err = alerter.CheckAndAlert(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	logs = recorded.All()

	// Check for recovery alert in the logs
	recoveryAlert := false
	for _, log := range logs {
		if strings.Contains(log.Message, "INFO ALERT") {
			if component, ok := log.ContextMap()["component"].(string); ok && component == "critical-component" {
				if message, ok := log.ContextMap()["message"].(string); ok && strings.Contains(message, "recovered") {
					recoveryAlert = true
					break
				}
			}
		}
	}

	if !recoveryAlert {
		t.Error("Expected recovery alert after critical component health restored")
	}
}

func TestHealthCheckAlerter_GetFailureCounts(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hc := NewHealthChecker(logger)
	alertHandler := NewLogAlertHandler(logger, 1*time.Minute)
	alerter := NewHealthCheckAlerter(hc, alertHandler, logger)

	// Register failing health check
	hc.RegisterCheck("failing-component", func(ctx context.Context) (Status, string) {
		return StatusUnhealthy, "component failing"
	})

	ctx := context.Background()

	// Run checks multiple times
	for i := 0; i < 5; i++ {
		alerter.CheckAndAlert(ctx)
	}

	// Check failure counts
	failureCounts := alerter.GetFailureCounts()
	if count, exists := failureCounts["failing-component"]; !exists {
		t.Error("Expected failure count for failing-component")
	} else if count != 5 {
		t.Errorf("Expected failure count 5, got %d", count)
	}
}

func TestGetCorrelationIDFromContext(t *testing.T) {
	// Test with nil context
	correlationID := getCorrelationIDFromContext(nil)
	if correlationID != "" {
		t.Errorf("Expected empty correlation ID with nil context, got %s", correlationID)
	}

	// Test with context without correlation ID
	ctx := context.Background()
	correlationID = getCorrelationIDFromContext(ctx)
	if correlationID != "" {
		t.Errorf("Expected empty correlation ID without correlation_id in context, got %s", correlationID)
	}

	// Test with context with correlation ID
	ctx = context.WithValue(context.Background(), "correlation_id", "test-correlation-123")
	correlationID = getCorrelationIDFromContext(ctx)
	if correlationID != "test-correlation-123" {
		t.Errorf("Expected correlation ID 'test-correlation-123', got %s", correlationID)
	}

	// Test with context with non-string correlation ID
	ctx = context.WithValue(context.Background(), "correlation_id", 123)
	correlationID = getCorrelationIDFromContext(ctx)
	if correlationID != "" {
		t.Errorf("Expected empty correlation ID with non-string value, got %s", correlationID)
	}
}

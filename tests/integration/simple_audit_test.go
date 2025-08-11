package integration

import (
	"context"
	"testing"
	"time"

	"github.com/ik-labs/mcp-airlock/pkg/audit"
	"go.uber.org/zap/zaptest"
)

func TestAuditIntegrationSimple(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create mock audit logger to capture all events
	mockAuditLogger := audit.NewMockAuditLogger()
	securityAuditLogger := audit.NewSecurityAuditLogger(mockAuditLogger, logger)

	ctx := context.Background()
	correlationID := "test-correlation-id-simple"

	// Test complete audit trail for a simulated request
	t.Run("CompleteAuditTrail", func(t *testing.T) {
		mockAuditLogger.Reset()

		// 1. Authentication event
		err := securityAuditLogger.LogAuthenticationEvent(ctx, correlationID, "test-user", audit.DecisionAllow, "authentication_successful", 100*time.Millisecond, map[string]interface{}{
			"tenant": "test-tenant",
			"path":   "/api/test",
		})
		if err != nil {
			t.Fatalf("Authentication audit failed: %v", err)
		}

		// 2. Authorization event
		err = securityAuditLogger.LogAuthorizationEvent(ctx, correlationID, "test-tenant", "test-user", "/api/resource", audit.DecisionAllow, "policy_allowed", 50*time.Millisecond, map[string]interface{}{
			"rule_id": "rule-123",
		})
		if err != nil {
			t.Fatalf("Authorization audit failed: %v", err)
		}

		// 3. Redaction event
		err = securityAuditLogger.LogRedactionEvent(ctx, correlationID, "test-tenant", "test-user", "test-tool", "request", 2, map[string]int{"ssn": 2}, 25*time.Millisecond, 1024)
		if err != nil {
			t.Fatalf("Redaction audit failed: %v", err)
		}

		// 4. Resource access event
		err = securityAuditLogger.LogResourceAccessEvent(ctx, correlationID, "test-tenant", "test-user", "/api/resource", audit.ActionResourceRead, map[string]interface{}{
			"method": "GET",
		})
		if err != nil {
			t.Fatalf("Resource access audit failed: %v", err)
		}

		// 5. Security violation event
		err = securityAuditLogger.LogSecurityViolationEvent(ctx, correlationID, "test-tenant", "test-user", "Path traversal attempt detected", "/api/../etc/passwd", map[string]interface{}{
			"attempted_path": "/api/../etc/passwd",
			"violation_type": "path_traversal",
		})
		if err != nil {
			t.Fatalf("Security violation audit failed: %v", err)
		}

		// Verify complete audit trail
		events := mockAuditLogger.GetEvents()
		if len(events) != 5 {
			t.Errorf("Expected 5 audit events, got %d", len(events))
		}

		// Verify all events have the same correlation ID
		for i, event := range events {
			if event.CorrelationID != correlationID {
				t.Errorf("Event %d has wrong correlation ID: expected %s, got %s", i, correlationID, event.CorrelationID)
			}
		}

		// Verify event types are present
		expectedActions := []string{
			audit.ActionTokenValidate,
			audit.ActionPolicyEvaluate,
			audit.ActionRedactData,
			audit.ActionResourceRead,
			audit.EventTypeSecurityViolation,
		}

		for i, event := range events {
			if event.Action != expectedActions[i] {
				t.Errorf("Event %d has wrong action: expected %s, got %s", i, expectedActions[i], event.Action)
			}
		}

		// Verify structured logging with no raw sensitive data
		for i, event := range events {
			if event.Metadata != nil {
				for key, value := range event.Metadata {
					// Check that no raw sensitive data keys are present
					if key == "raw_data" || key == "sensitive_data" || key == "password" || key == "token" {
						t.Errorf("Event %d contains sensitive data key %s: %v", i, key, value)
					}

					// Check that values don't contain sensitive patterns
					if strValue, ok := value.(string); ok {
						if containsSensitiveData(strValue) {
							t.Errorf("Event %d contains sensitive data in value: %s", i, strValue)
						}
					}
				}
			}
		}

		// Verify redaction count is properly logged
		redactionEvent := events[2] // Third event should be redaction
		if redactionEvent.RedactionCount != 2 {
			t.Errorf("Expected redaction count 2, got %d", redactionEvent.RedactionCount)
		}

		// Verify security violation has proper metadata
		securityEvent := events[4] // Fifth event should be security violation
		if securityEvent.Decision != audit.DecisionDeny {
			t.Errorf("Expected security violation decision deny, got %s", securityEvent.Decision)
		}
		if violationType, ok := securityEvent.Metadata["violation_type"].(string); !ok || violationType != "path_traversal" {
			t.Errorf("Expected violation_type path_traversal, got %v", securityEvent.Metadata["violation_type"])
		}
	})

	// Test authentication failure audit
	t.Run("AuthenticationFailure", func(t *testing.T) {
		mockAuditLogger.Reset()

		err := securityAuditLogger.LogAuthenticationEvent(ctx, correlationID, "", audit.DecisionDeny, "invalid_token", 50*time.Millisecond, map[string]interface{}{
			"path":  "/api/test",
			"error": "token_validation_failed",
		})
		if err != nil {
			t.Fatalf("Authentication failure audit failed: %v", err)
		}

		events := mockAuditLogger.GetEvents()
		if len(events) != 1 {
			t.Errorf("Expected 1 audit event, got %d", len(events))
		}

		event := events[0]
		if event.Decision != audit.DecisionDeny {
			t.Errorf("Expected decision deny, got %s", event.Decision)
		}
		if event.Reason != "invalid_token" {
			t.Errorf("Expected reason invalid_token, got %s", event.Reason)
		}
	})

	// Test authorization failure audit
	t.Run("AuthorizationFailure", func(t *testing.T) {
		mockAuditLogger.Reset()

		err := securityAuditLogger.LogAuthorizationEvent(ctx, correlationID, "test-tenant", "test-user", "/api/admin", audit.DecisionDeny, "insufficient_permissions", 75*time.Millisecond, map[string]interface{}{
			"rule_id":         "rule-deny-456",
			"required_groups": []string{"admin"},
			"user_groups":     []string{"user"},
		})
		if err != nil {
			t.Fatalf("Authorization failure audit failed: %v", err)
		}

		events := mockAuditLogger.GetEvents()
		if len(events) != 1 {
			t.Errorf("Expected 1 audit event, got %d", len(events))
		}

		event := events[0]
		if event.Decision != audit.DecisionDeny {
			t.Errorf("Expected decision deny, got %s", event.Decision)
		}
		if event.Reason != "insufficient_permissions" {
			t.Errorf("Expected reason insufficient_permissions, got %s", event.Reason)
		}
		if event.Resource != "/api/admin" {
			t.Errorf("Expected resource /api/admin, got %s", event.Resource)
		}
	})

	// Test rate limiting audit
	t.Run("RateLimitViolation", func(t *testing.T) {
		mockAuditLogger.Reset()

		err := securityAuditLogger.LogRateLimitEvent(ctx, correlationID, "test-tenant", "test-user", map[string]interface{}{
			"limit":         100,
			"window":        "1m",
			"current_count": 101,
		})
		if err != nil {
			t.Fatalf("Rate limit audit failed: %v", err)
		}

		events := mockAuditLogger.GetEvents()
		if len(events) != 1 {
			t.Errorf("Expected 1 audit event, got %d", len(events))
		}

		event := events[0]
		if event.Action != audit.ActionRateLimitHit {
			t.Errorf("Expected action %s, got %s", audit.ActionRateLimitHit, event.Action)
		}
		if event.Decision != audit.DecisionDeny {
			t.Errorf("Expected decision deny, got %s", event.Decision)
		}
		if event.Reason != "Rate limit exceeded" {
			t.Errorf("Expected reason 'Rate limit exceeded', got %s", event.Reason)
		}
	})
}

// containsSensitiveData checks if a string contains sensitive data patterns
func containsSensitiveData(s string) bool {
	sensitivePatterns := []string{
		"123-45-6789", // SSN pattern
		"password",
		"secret",
		"token",
		"key",
	}

	for _, pattern := range sensitivePatterns {
		if len(s) > 0 && len(pattern) > 0 && s == pattern {
			return true
		}
	}
	return false
}

func TestAuditEventIntegrity(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := audit.NewMockAuditLogger()
	securityAuditLogger := audit.NewSecurityAuditLogger(mockAuditLogger, logger)

	ctx := context.Background()
	correlationID := "test-correlation-id-integrity"

	// Test that all required fields are populated correctly
	err := securityAuditLogger.LogAuthenticationEvent(ctx, correlationID, "test-user", audit.DecisionAllow, "authentication_successful", 100*time.Millisecond, map[string]interface{}{
		"tenant": "test-tenant",
		"path":   "/api/test",
	})
	if err != nil {
		t.Fatalf("Failed to log authentication event: %v", err)
	}

	events := mockAuditLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]

	// Verify all required fields are present and valid
	if event.ID == "" {
		t.Error("Event ID should not be empty")
	}
	if event.Timestamp.IsZero() {
		t.Error("Event timestamp should not be zero")
	}
	if event.CorrelationID != correlationID {
		t.Errorf("Expected correlation ID %s, got %s", correlationID, event.CorrelationID)
	}
	if event.Subject != "test-user" {
		t.Errorf("Expected subject test-user, got %s", event.Subject)
	}
	if event.Action != audit.ActionTokenValidate {
		t.Errorf("Expected action %s, got %s", audit.ActionTokenValidate, event.Action)
	}
	if event.Decision != audit.DecisionAllow {
		t.Errorf("Expected decision %s, got %s", audit.DecisionAllow, event.Decision)
	}
	if event.Reason != "authentication_successful" {
		t.Errorf("Expected reason authentication_successful, got %s", event.Reason)
	}
	if event.LatencyMs != 100 {
		t.Errorf("Expected latency 100ms, got %d", event.LatencyMs)
	}
	if event.Tenant != "test-tenant" {
		t.Errorf("Expected tenant test-tenant, got %s", event.Tenant)
	}

	// Verify metadata structure
	if event.Metadata == nil {
		t.Error("Event metadata should not be nil")
	} else {
		if path, ok := event.Metadata["path"].(string); !ok || path != "/api/test" {
			t.Errorf("Expected path /api/test in metadata, got %v", event.Metadata["path"])
		}
	}

	// Verify timestamp is recent (within last minute)
	if time.Since(event.Timestamp) > time.Minute {
		t.Errorf("Event timestamp is too old: %v", event.Timestamp)
	}
}

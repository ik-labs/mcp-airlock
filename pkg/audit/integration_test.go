package audit

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestSecurityAuditLogger_LogAuthenticationEvent(t *testing.T) {
	mockLogger := NewMockAuditLogger()
	logger := zaptest.NewLogger(t)
	securityLogger := NewSecurityAuditLogger(mockLogger, logger)

	ctx := context.Background()
	correlationID := "test-correlation-id"
	subject := "test-user"
	decision := DecisionAllow
	reason := "authentication_successful"
	latency := 100 * time.Millisecond
	metadata := map[string]interface{}{
		"tenant": "test-tenant",
		"path":   "/api/test",
	}

	err := securityLogger.LogAuthenticationEvent(ctx, correlationID, subject, decision, reason, latency, metadata)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	events := mockLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.CorrelationID != correlationID {
		t.Errorf("Expected correlation ID %s, got %s", correlationID, event.CorrelationID)
	}
	if event.Subject != subject {
		t.Errorf("Expected subject %s, got %s", subject, event.Subject)
	}
	if event.Action != ActionTokenValidate {
		t.Errorf("Expected action %s, got %s", ActionTokenValidate, event.Action)
	}
	if event.Decision != decision {
		t.Errorf("Expected decision %s, got %s", decision, event.Decision)
	}
	if event.Reason != reason {
		t.Errorf("Expected reason %s, got %s", reason, event.Reason)
	}
	if event.LatencyMs != latency.Milliseconds() {
		t.Errorf("Expected latency %d ms, got %d ms", latency.Milliseconds(), event.LatencyMs)
	}
	if event.Tenant != "test-tenant" {
		t.Errorf("Expected tenant test-tenant, got %s", event.Tenant)
	}
}

func TestSecurityAuditLogger_LogAuthorizationEvent(t *testing.T) {
	mockLogger := NewMockAuditLogger()
	logger := zaptest.NewLogger(t)
	securityLogger := NewSecurityAuditLogger(mockLogger, logger)

	ctx := context.Background()
	correlationID := "test-correlation-id"
	tenant := "test-tenant"
	subject := "test-user"
	resource := "/api/resource"
	decision := DecisionDeny
	reason := "insufficient_permissions"
	latency := 50 * time.Millisecond
	metadata := map[string]interface{}{
		"rule_id": "rule-123",
		"groups":  []string{"user", "read-only"},
	}

	err := securityLogger.LogAuthorizationEvent(ctx, correlationID, tenant, subject, resource, decision, reason, latency, metadata)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	events := mockLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.CorrelationID != correlationID {
		t.Errorf("Expected correlation ID %s, got %s", correlationID, event.CorrelationID)
	}
	if event.Tenant != tenant {
		t.Errorf("Expected tenant %s, got %s", tenant, event.Tenant)
	}
	if event.Subject != subject {
		t.Errorf("Expected subject %s, got %s", subject, event.Subject)
	}
	if event.Resource != resource {
		t.Errorf("Expected resource %s, got %s", resource, event.Resource)
	}
	if event.Action != ActionPolicyEvaluate {
		t.Errorf("Expected action %s, got %s", ActionPolicyEvaluate, event.Action)
	}
	if event.Decision != decision {
		t.Errorf("Expected decision %s, got %s", decision, event.Decision)
	}
	if event.Reason != reason {
		t.Errorf("Expected reason %s, got %s", reason, event.Reason)
	}
}

func TestSecurityAuditLogger_LogRedactionEvent(t *testing.T) {
	mockLogger := NewMockAuditLogger()
	logger := zaptest.NewLogger(t)
	securityLogger := NewSecurityAuditLogger(mockLogger, logger)

	ctx := context.Background()
	correlationID := "test-correlation-id"
	tenant := "test-tenant"
	subject := "test-user"
	tool := "test-tool"
	direction := "request"
	redactionCount := 3
	patternsHit := map[string]int{
		"ssn":   2,
		"email": 1,
	}
	processingTime := 25 * time.Millisecond
	dataSize := 1024

	err := securityLogger.LogRedactionEvent(ctx, correlationID, tenant, subject, tool, direction, redactionCount, patternsHit, processingTime, dataSize)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	events := mockLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.CorrelationID != correlationID {
		t.Errorf("Expected correlation ID %s, got %s", correlationID, event.CorrelationID)
	}
	if event.Action != ActionRedactData {
		t.Errorf("Expected action %s, got %s", ActionRedactData, event.Action)
	}
	if event.RedactionCount != redactionCount {
		t.Errorf("Expected redaction count %d, got %d", redactionCount, event.RedactionCount)
	}
	if event.Decision != DecisionAllow {
		t.Errorf("Expected decision %s, got %s", DecisionAllow, event.Decision)
	}

	// Check metadata
	if tool, ok := event.Metadata["tool"].(string); !ok || tool != "test-tool" {
		t.Errorf("Expected tool test-tool in metadata, got %v", event.Metadata["tool"])
	}
	if direction, ok := event.Metadata["direction"].(string); !ok || direction != "request" {
		t.Errorf("Expected direction request in metadata, got %v", event.Metadata["direction"])
	}
}

func TestSecurityAuditLogger_LogSecurityViolationEvent(t *testing.T) {
	mockLogger := NewMockAuditLogger()
	logger := zaptest.NewLogger(t)
	securityLogger := NewSecurityAuditLogger(mockLogger, logger)

	ctx := context.Background()
	correlationID := "test-correlation-id"
	tenant := "test-tenant"
	subject := "test-user"
	violation := "Path traversal attempt detected"
	resource := "/api/../etc/passwd"
	metadata := map[string]interface{}{
		"attempted_path": "/api/../etc/passwd",
		"violation_type": "path_traversal",
	}

	err := securityLogger.LogSecurityViolationEvent(ctx, correlationID, tenant, subject, violation, resource, metadata)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	events := mockLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.CorrelationID != correlationID {
		t.Errorf("Expected correlation ID %s, got %s", correlationID, event.CorrelationID)
	}
	if event.Action != EventTypeSecurityViolation {
		t.Errorf("Expected action %s, got %s", EventTypeSecurityViolation, event.Action)
	}
	if event.Decision != DecisionDeny {
		t.Errorf("Expected decision %s, got %s", DecisionDeny, event.Decision)
	}
	if event.Reason != violation {
		t.Errorf("Expected reason %s, got %s", violation, event.Reason)
	}
	if event.Resource != resource {
		t.Errorf("Expected resource %s, got %s", resource, event.Resource)
	}
}

func TestSecurityAuditLogger_LogRateLimitEvent(t *testing.T) {
	mockLogger := NewMockAuditLogger()
	logger := zaptest.NewLogger(t)
	securityLogger := NewSecurityAuditLogger(mockLogger, logger)

	ctx := context.Background()
	correlationID := "test-correlation-id"
	tenant := "test-tenant"
	subject := "test-user"
	metadata := map[string]interface{}{
		"limit":  100,
		"window": "1m",
	}

	err := securityLogger.LogRateLimitEvent(ctx, correlationID, tenant, subject, metadata)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	events := mockLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.CorrelationID != correlationID {
		t.Errorf("Expected correlation ID %s, got %s", correlationID, event.CorrelationID)
	}
	if event.Action != ActionRateLimitHit {
		t.Errorf("Expected action %s, got %s", ActionRateLimitHit, event.Action)
	}
	if event.Decision != DecisionDeny {
		t.Errorf("Expected decision %s, got %s", DecisionDeny, event.Decision)
	}
	if event.Reason != "Rate limit exceeded" {
		t.Errorf("Expected reason 'Rate limit exceeded', got %s", event.Reason)
	}
}

func TestSecurityAuditLogger_LogPathTraversalAttempt(t *testing.T) {
	mockLogger := NewMockAuditLogger()
	logger := zaptest.NewLogger(t)
	securityLogger := NewSecurityAuditLogger(mockLogger, logger)

	ctx := context.Background()
	correlationID := "test-correlation-id"
	tenant := "test-tenant"
	subject := "test-user"
	attemptedPath := "/api/../etc/passwd"
	resource := "/api/files"

	err := securityLogger.LogPathTraversalAttempt(ctx, correlationID, tenant, subject, attemptedPath, resource)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	events := mockLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.CorrelationID != correlationID {
		t.Errorf("Expected correlation ID %s, got %s", correlationID, event.CorrelationID)
	}
	if event.Action != EventTypeSecurityViolation {
		t.Errorf("Expected action %s, got %s", EventTypeSecurityViolation, event.Action)
	}
	if event.Decision != DecisionDeny {
		t.Errorf("Expected decision %s, got %s", DecisionDeny, event.Decision)
	}

	// Check metadata
	if attemptedPath, ok := event.Metadata["attempted_path"].(string); !ok || attemptedPath != "/api/../etc/passwd" {
		t.Errorf("Expected attempted_path /api/../etc/passwd in metadata, got %v", event.Metadata["attempted_path"])
	}
	if violationType, ok := event.Metadata["violation_type"].(string); !ok || violationType != "path_traversal" {
		t.Errorf("Expected violation_type path_traversal in metadata, got %v", event.Metadata["violation_type"])
	}
}

// TODO: Uncomment when redact, auth, and policy packages are implemented
/*
func TestAuditAdapters(t *testing.T) {
	mockLogger := NewMockAuditLogger()
	logger := zaptest.NewLogger(t)
	securityLogger := NewSecurityAuditLogger(mockLogger, logger)

	t.Run("RedactionAuditAdapter", func(t *testing.T) {
		adapter := NewRedactionAuditAdapter(securityLogger)

		event := &RedactionAuditEvent{
			CorrelationID:  "test-correlation-id",
			Tenant:         "test-tenant",
			Subject:        "test-user",
			Tool:           "test-tool",
			Direction:      "request",
			RedactionCount: 2,
			PatternsHit:    map[string]int{"ssn": 2},
			ProcessingTime: 30 * time.Millisecond,
			Timestamp:      time.Now(),
			DataSize:       512,
		}

		err := adapter.LogRedactionEvent(context.Background(), event)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		events := mockLogger.GetEvents()
		if len(events) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(events))
		}

		auditEvent := events[0]
		if auditEvent.Action != ActionRedactData {
			t.Errorf("Expected action %s, got %s", ActionRedactData, auditEvent.Action)
		}
		if auditEvent.RedactionCount != 2 {
			t.Errorf("Expected redaction count 2, got %d", auditEvent.RedactionCount)
		}
	})

	mockLogger.Reset()

	t.Run("AuthenticationAuditAdapter", func(t *testing.T) {
		adapter := NewAuthenticationAuditAdapter(securityLogger)

		event := &AuthenticationAuditEvent{
			ID:            "test-id",
			Timestamp:     time.Now(),
			CorrelationID: "test-correlation-id",
			Tenant:        "test-tenant",
			Subject:       "test-user",
			Action:        ActionTokenValidate,
			Resource:      "authentication",
			Decision:      DecisionAllow,
			Reason:        "authentication_successful",
			Metadata:      map[string]interface{}{"path": "/api/test"},
			LatencyMs:     100,
		}

		err := adapter.LogEvent(context.Background(), event)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		events := mockLogger.GetEvents()
		if len(events) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(events))
		}

		auditEvent := events[0]
		if auditEvent.Action != ActionTokenValidate {
			t.Errorf("Expected action %s, got %s", ActionTokenValidate, auditEvent.Action)
		}
		if auditEvent.Subject != "test-user" {
			t.Errorf("Expected subject test-user, got %s", auditEvent.Subject)
		}
	})

	mockLogger.Reset()

	t.Run("PolicyAuditAdapter", func(t *testing.T) {
		adapter := NewPolicyAuditAdapter(securityLogger)

		event := &PolicyAuditEvent{
			ID:            "test-id",
			Timestamp:     time.Now(),
			CorrelationID: "test-correlation-id",
			Tenant:        "test-tenant",
			Subject:       "test-user",
			Action:        ActionPolicyEvaluate,
			Resource:      "/api/resource",
			Decision:      DecisionDeny,
			Reason:        "insufficient_permissions",
			Metadata:      map[string]interface{}{"rule_id": "rule-123"},
			LatencyMs:     50,
		}

		err := adapter.LogEvent(context.Background(), event)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		events := mockLogger.GetEvents()
		if len(events) != 1 {
			t.Fatalf("Expected 1 event, got %d", len(events))
		}

		auditEvent := events[0]
		if auditEvent.Action != ActionPolicyEvaluate {
			t.Errorf("Expected action %s, got %s", ActionPolicyEvaluate, auditEvent.Action)
		}
		if auditEvent.Decision != DecisionDeny {
			t.Errorf("Expected decision %s, got %s", DecisionDeny, auditEvent.Decision)
		}
	})
}
*/

func TestCompleteAuditTrail(t *testing.T) {
	mockLogger := NewMockAuditLogger()
	logger := zaptest.NewLogger(t)
	securityLogger := NewSecurityAuditLogger(mockLogger, logger)

	ctx := context.Background()
	correlationID := "test-correlation-id"

	// Simulate a complete request flow with audit events

	// 1. Authentication event
	err := securityLogger.LogAuthenticationEvent(ctx, correlationID, "test-user", DecisionAllow, "authentication_successful", 100*time.Millisecond, map[string]interface{}{
		"tenant": "test-tenant",
		"path":   "/api/test",
	})
	if err != nil {
		t.Fatalf("Authentication audit failed: %v", err)
	}

	// 2. Authorization event
	err = securityLogger.LogAuthorizationEvent(ctx, correlationID, "test-tenant", "test-user", "/api/resource", DecisionAllow, "policy_allowed", 50*time.Millisecond, map[string]interface{}{
		"rule_id": "rule-123",
	})
	if err != nil {
		t.Fatalf("Authorization audit failed: %v", err)
	}

	// 3. Redaction event
	err = securityLogger.LogRedactionEvent(ctx, correlationID, "test-tenant", "test-user", "test-tool", "request", 2, map[string]int{"ssn": 2}, 25*time.Millisecond, 1024)
	if err != nil {
		t.Fatalf("Redaction audit failed: %v", err)
	}

	// 4. Resource access event
	err = securityLogger.LogResourceAccessEvent(ctx, correlationID, "test-tenant", "test-user", "/api/resource", ActionResourceRead, map[string]interface{}{
		"method": "GET",
	})
	if err != nil {
		t.Fatalf("Resource access audit failed: %v", err)
	}

	// Verify complete audit trail
	events := mockLogger.GetEvents()
	if len(events) != 4 {
		t.Fatalf("Expected 4 events in audit trail, got %d", len(events))
	}

	// Verify all events have the same correlation ID
	for i, event := range events {
		if event.CorrelationID != correlationID {
			t.Errorf("Event %d has wrong correlation ID: expected %s, got %s", i, correlationID, event.CorrelationID)
		}
	}

	// Verify event types
	expectedActions := []string{ActionTokenValidate, ActionPolicyEvaluate, ActionRedactData, ActionResourceRead}
	for i, event := range events {
		if event.Action != expectedActions[i] {
			t.Errorf("Event %d has wrong action: expected %s, got %s", i, expectedActions[i], event.Action)
		}
	}

	// Verify no sensitive data is logged
	for i, event := range events {
		// Check that no raw sensitive data is in the event
		if event.Metadata != nil {
			for key, value := range event.Metadata {
				if key == "raw_data" || key == "sensitive_data" {
					t.Errorf("Event %d contains sensitive data key %s: %v", i, key, value)
				}
			}
		}
	}
}

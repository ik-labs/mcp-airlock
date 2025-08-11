package audit

import (
	"context"
	"testing"
	"time"
)

func TestEventBuilder(t *testing.T) {
	correlationID := "test-corr-123"
	tenant := "test-tenant"
	subject := "user@example.com"
	resource := "mcp://repo/test.txt"

	event := NewEvent(ActionTokenValidate).
		WithCorrelationID(correlationID).
		WithTenant(tenant).
		WithSubject(subject).
		WithResource(resource).
		WithDecision(DecisionAllow).
		WithReason("valid token").
		WithLatency(50*time.Millisecond).
		WithRedactionCount(2).
		WithMetadata("key1", "value1").
		WithMetadata("key2", 42).
		Build()

	if event.Action != ActionTokenValidate {
		t.Errorf("Expected action %s, got %s", ActionTokenValidate, event.Action)
	}
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
	if event.Decision != DecisionAllow {
		t.Errorf("Expected decision %s, got %s", DecisionAllow, event.Decision)
	}
	if event.Reason != "valid token" {
		t.Errorf("Expected reason 'valid token', got '%s'", event.Reason)
	}
	if event.LatencyMs != 50 {
		t.Errorf("Expected latency 50ms, got %d", event.LatencyMs)
	}
	if event.RedactionCount != 2 {
		t.Errorf("Expected redaction count 2, got %d", event.RedactionCount)
	}
	if event.ID == "" {
		t.Error("Event ID should not be empty")
	}
	if event.Timestamp.IsZero() {
		t.Error("Event timestamp should not be zero")
	}
	if event.Metadata == nil {
		t.Error("Metadata should not be nil")
	}
	if event.Metadata["key1"] != "value1" {
		t.Errorf("Expected metadata key1='value1', got %v", event.Metadata["key1"])
	}
	if event.Metadata["key2"] != 42 {
		t.Errorf("Expected metadata key2=42, got %v", event.Metadata["key2"])
	}
}

func TestEventBuilder_WithMetadataMap(t *testing.T) {
	metadata := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	event := NewEvent(ActionPolicyEvaluate).
		WithMetadataMap(metadata).
		Build()

	for k, v := range metadata {
		if event.Metadata[k] != v {
			t.Errorf("Expected metadata %s=%v, got %v", k, v, event.Metadata[k])
		}
	}
}

func TestNewAuthenticationEvent(t *testing.T) {
	correlationID := "auth-corr-123"
	subject := "user@example.com"
	decision := DecisionAllow
	reason := "valid JWT token"

	event := NewAuthenticationEvent(correlationID, subject, decision, reason)

	if event.Action != ActionTokenValidate {
		t.Errorf("Expected action %s, got %s", ActionTokenValidate, event.Action)
	}
	if event.CorrelationID != correlationID {
		t.Errorf("Expected correlation ID %s, got %s", correlationID, event.CorrelationID)
	}
	if event.Subject != subject {
		t.Errorf("Expected subject %s, got %s", subject, event.Subject)
	}
	if event.Decision != decision {
		t.Errorf("Expected decision %s, got %s", decision, event.Decision)
	}
	if event.Reason != reason {
		t.Errorf("Expected reason %s, got %s", reason, event.Reason)
	}
}

func TestNewAuthorizationEvent(t *testing.T) {
	correlationID := "authz-corr-123"
	tenant := "tenant-1"
	subject := "user@example.com"
	resource := "mcp://repo/sensitive.txt"
	decision := DecisionDeny
	reason := "insufficient permissions"

	event := NewAuthorizationEvent(correlationID, tenant, subject, resource, decision, reason)

	if event.Action != ActionPolicyEvaluate {
		t.Errorf("Expected action %s, got %s", ActionPolicyEvaluate, event.Action)
	}
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
	if event.Decision != decision {
		t.Errorf("Expected decision %s, got %s", decision, event.Decision)
	}
	if event.Reason != reason {
		t.Errorf("Expected reason %s, got %s", reason, event.Reason)
	}
}

func TestNewResourceAccessEvent(t *testing.T) {
	correlationID := "resource-corr-123"
	tenant := "tenant-1"
	subject := "user@example.com"
	resource := "mcp://repo/public.txt"
	action := ActionResourceRead

	event := NewResourceAccessEvent(correlationID, tenant, subject, resource, action)

	if event.Action != action {
		t.Errorf("Expected action %s, got %s", action, event.Action)
	}
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
	if event.Decision != DecisionAllow {
		t.Errorf("Expected decision %s, got %s", DecisionAllow, event.Decision)
	}
}

func TestNewRedactionEvent(t *testing.T) {
	correlationID := "redact-corr-123"
	tenant := "tenant-1"
	redactionCount := 5

	event := NewRedactionEvent(correlationID, tenant, redactionCount)

	if event.Action != ActionRedactData {
		t.Errorf("Expected action %s, got %s", ActionRedactData, event.Action)
	}
	if event.CorrelationID != correlationID {
		t.Errorf("Expected correlation ID %s, got %s", correlationID, event.CorrelationID)
	}
	if event.Tenant != tenant {
		t.Errorf("Expected tenant %s, got %s", tenant, event.Tenant)
	}
	if event.RedactionCount != redactionCount {
		t.Errorf("Expected redaction count %d, got %d", redactionCount, event.RedactionCount)
	}
	if event.Decision != DecisionAllow {
		t.Errorf("Expected decision %s, got %s", DecisionAllow, event.Decision)
	}
	if event.Reason != "DLP patterns matched" {
		t.Errorf("Expected reason 'DLP patterns matched', got '%s'", event.Reason)
	}
}

func TestNewSecurityViolationEvent(t *testing.T) {
	correlationID := "violation-corr-123"
	tenant := "tenant-1"
	subject := "attacker@example.com"
	violation := "path traversal attempt"
	resource := "mcp://repo/../../../etc/passwd"

	event := NewSecurityViolationEvent(correlationID, tenant, subject, violation, resource)

	if event.Action != EventTypeSecurityViolation {
		t.Errorf("Expected action %s, got %s", EventTypeSecurityViolation, event.Action)
	}
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
	if event.Decision != DecisionDeny {
		t.Errorf("Expected decision %s, got %s", DecisionDeny, event.Decision)
	}
	if event.Reason != violation {
		t.Errorf("Expected reason %s, got %s", violation, event.Reason)
	}
}

func TestNewRateLimitEvent(t *testing.T) {
	correlationID := "rate-corr-123"
	tenant := "tenant-1"
	subject := "user@example.com"
	metadata := map[string]interface{}{
		"limit":     "200/min",
		"current":   250,
		"window":    "60s",
		"client_ip": "192.168.1.100",
	}

	event := NewRateLimitEvent(correlationID, tenant, subject, metadata)

	if event.Action != ActionRateLimitHit {
		t.Errorf("Expected action %s, got %s", ActionRateLimitHit, event.Action)
	}
	if event.CorrelationID != correlationID {
		t.Errorf("Expected correlation ID %s, got %s", correlationID, event.CorrelationID)
	}
	if event.Tenant != tenant {
		t.Errorf("Expected tenant %s, got %s", tenant, event.Tenant)
	}
	if event.Subject != subject {
		t.Errorf("Expected subject %s, got %s", subject, event.Subject)
	}
	if event.Decision != DecisionDeny {
		t.Errorf("Expected decision %s, got %s", DecisionDeny, event.Decision)
	}
	if event.Reason != "Rate limit exceeded" {
		t.Errorf("Expected reason 'Rate limit exceeded', got '%s'", event.Reason)
	}

	for k, v := range metadata {
		if event.Metadata[k] != v {
			t.Errorf("Expected metadata %s=%v, got %v", k, v, event.Metadata[k])
		}
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()

	// Test empty context
	if GetCorrelationID(ctx) != "" {
		t.Error("Empty context should return empty correlation ID")
	}
	if GetTenant(ctx) != "" {
		t.Error("Empty context should return empty tenant")
	}
	if GetSubject(ctx) != "" {
		t.Error("Empty context should return empty subject")
	}

	// Test with values
	correlationID := "test-corr-123"
	tenant := "test-tenant"
	subject := "test-user@example.com"

	ctx = WithCorrelationID(ctx, correlationID)
	ctx = WithTenant(ctx, tenant)
	ctx = WithSubject(ctx, subject)

	if GetCorrelationID(ctx) != correlationID {
		t.Errorf("Expected correlation ID %s, got %s", correlationID, GetCorrelationID(ctx))
	}
	if GetTenant(ctx) != tenant {
		t.Errorf("Expected tenant %s, got %s", tenant, GetTenant(ctx))
	}
	if GetSubject(ctx) != subject {
		t.Errorf("Expected subject %s, got %s", subject, GetSubject(ctx))
	}
}

func TestEventConstants(t *testing.T) {
	// Test that constants are defined and not empty
	constants := map[string]string{
		"EventTypeAuthentication":    EventTypeAuthentication,
		"EventTypeAuthorization":     EventTypeAuthorization,
		"EventTypePolicyDecision":    EventTypePolicyDecision,
		"EventTypeRedaction":         EventTypeRedaction,
		"EventTypeResourceAccess":    EventTypeResourceAccess,
		"EventTypeSecurityViolation": EventTypeSecurityViolation,
		"EventTypeSystemEvent":       EventTypeSystemEvent,
		"DecisionAllow":              DecisionAllow,
		"DecisionDeny":               DecisionDeny,
		"DecisionError":              DecisionError,
		"ActionLogin":                ActionLogin,
		"ActionLogout":               ActionLogout,
		"ActionTokenValidate":        ActionTokenValidate,
		"ActionPolicyEvaluate":       ActionPolicyEvaluate,
		"ActionResourceRead":         ActionResourceRead,
		"ActionResourceWrite":        ActionResourceWrite,
		"ActionToolCall":             ActionToolCall,
		"ActionRedactData":           ActionRedactData,
		"ActionRateLimitHit":         ActionRateLimitHit,
		"ActionPathTraversal":        ActionPathTraversal,
	}

	for name, value := range constants {
		if value == "" {
			t.Errorf("Constant %s should not be empty", name)
		}
	}
}

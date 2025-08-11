package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ik-labs/mcp-airlock/pkg/audit"
	"github.com/ik-labs/mcp-airlock/pkg/auth"
	"github.com/ik-labs/mcp-airlock/pkg/policy"
	"github.com/ik-labs/mcp-airlock/pkg/redact"
	"github.com/ik-labs/mcp-airlock/pkg/security"
	"go.uber.org/zap/zaptest"
)

// MockTokenValidator implements auth.TokenValidator for testing
type MockTokenValidator struct {
	shouldFail bool
}

func (m *MockTokenValidator) ValidateToken(ctx context.Context, tokenString string) (*auth.Claims, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("invalid token")
	}

	return &auth.Claims{
		Subject: "test-user",
		Tenant:  "test-tenant",
		Groups:  []string{"user", "read-only"},
	}, nil
}

// MockPolicyEngine implements policy.PolicyEngine for testing
type MockPolicyEngine struct {
	shouldDeny bool
}

func (m *MockPolicyEngine) Evaluate(ctx context.Context, input *policy.PolicyInput) (*policy.PolicyDecision, error) {
	if m.shouldDeny {
		return &policy.PolicyDecision{
			Allow:  false,
			Reason: "insufficient_permissions",
			RuleID: "rule-deny-123",
		}, nil
	}

	return &policy.PolicyDecision{
		Allow:  true,
		Reason: "policy_allowed",
		RuleID: "rule-allow-456",
	}, nil
}

func (m *MockPolicyEngine) LoadPolicy(ctx context.Context, policy string) error {
	return nil
}

func (m *MockPolicyEngine) ReloadPolicy(ctx context.Context) error {
	return nil
}

func (m *MockPolicyEngine) Close() error {
	return nil
}

// MockRedactor implements redact.RedactorInterface for testing
type MockRedactor struct {
	redactionCount int
}

func (m *MockRedactor) RedactRequest(ctx context.Context, data []byte) (*redact.RedactionResult, error) {
	return &redact.RedactionResult{
		Data:           data, // No actual redaction for testing
		RedactionCount: m.redactionCount,
		PatternsHit:    map[string]int{"ssn": m.redactionCount},
		ProcessingTime: 10 * time.Millisecond,
	}, nil
}

func (m *MockRedactor) RedactResponse(ctx context.Context, data []byte) (*redact.RedactionResult, error) {
	return m.RedactRequest(ctx, data)
}

func (m *MockRedactor) RedactStream(ctx context.Context, reader io.Reader, writer io.Writer) (*redact.RedactionResult, error) {
	return &redact.RedactionResult{
		Data:           []byte{},
		RedactionCount: m.redactionCount,
		PatternsHit:    map[string]int{"ssn": m.redactionCount},
		ProcessingTime: 10 * time.Millisecond,
	}, nil
}

func (m *MockRedactor) LoadPatterns(patterns []redact.Pattern) error {
	return nil
}

func (m *MockRedactor) GetPatterns() []redact.CompiledPattern {
	return []redact.CompiledPattern{}
}

func (m *MockRedactor) Stats() map[string]interface{} {
	return map[string]interface{}{
		"patterns_loaded":  1,
		"redactions_total": m.redactionCount,
	}
}

func TestCompleteAuditTrailIntegration(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create mock audit logger to capture all events
	mockAuditLogger := audit.NewMockAuditLogger()
	securityAuditLogger := audit.NewSecurityAuditLogger(mockAuditLogger, logger)

	// Create adapters for different middleware components
	authAdapter := audit.NewAuthenticationAuditAdapter(securityAuditLogger)
	policyAdapter := audit.NewPolicyAuditAdapter(securityAuditLogger)
	redactionAdapter := audit.NewRedactionAuditAdapter(securityAuditLogger)

	// Set up middleware components
	tokenValidator := &MockTokenValidator{shouldFail: false}
	authMiddleware := auth.NewMiddleware(tokenValidator, logger)
	authMiddleware.SetAuditLogger(authAdapter)

	policyEngine := &MockPolicyEngine{shouldDeny: false}
	policyMiddleware := policy.NewPolicyMiddleware(policyEngine, logger)
	policyMiddleware.SetAuditLogger(policyAdapter)

	redactor := &MockRedactor{redactionCount: 2}
	redactionMiddleware := redact.NewRedactionMiddleware(redactor, logger, nil)
	redactionMiddleware.SetAuditLogger(redactionAdapter)

	securityMiddleware := security.NewSecurityMiddleware(logger)
	securityMiddleware.SetAuditLogger(securityAuditLogger)

	// Create a test handler that simulates a complete request flow
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		correlationID := "test-correlation-id-integration"

		// Simulate policy evaluation
		reqCtx := &policy.RequestContext{
			Subject:   "test-user",
			Tenant:    "test-tenant",
			Groups:    []string{"user", "read-only"},
			Tool:      "test-tool",
			Resource:  "/api/resource",
			Method:    "GET",
			Headers:   map[string]string{"Content-Type": "application/json"},
			RequestID: correlationID,
			Timestamp: time.Now(),
		}

		result := policyMiddleware.EvaluateRequest(ctx, reqCtx)
		if result.Error != nil {
			http.Error(w, "Policy evaluation failed", http.StatusInternalServerError)
			return
		}

		if result.Decision != nil && !result.Decision.Allow {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		// Simulate redaction processing
		requestData := []byte(`{"user_id": "123", "ssn": "123-45-6789", "email": "user@example.com"}`)
		_, err := redactionMiddleware.ProcessRequest(ctx, requestData)
		if err != nil {
			http.Error(w, "Redaction failed", http.StatusInternalServerError)
			return
		}

		// Log resource access
		err = securityAuditLogger.LogResourceAccessEvent(ctx, correlationID, "test-tenant", "test-user", "/api/resource", audit.ActionResourceRead, map[string]interface{}{
			"method": "GET",
			"status": "success",
		})
		if err != nil {
			t.Logf("Failed to log resource access: %v", err)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success"}`))
	})

	// Chain all middleware together
	handler := securityMiddleware.HTTPMiddleware(
		authMiddleware.HTTPMiddleware(testHandler),
	)

	// Test successful request flow
	t.Run("SuccessfulRequestFlow", func(t *testing.T) {
		mockAuditLogger.Reset()

		req := httptest.NewRequest("GET", "/api/resource", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		req = req.WithContext(context.WithValue(req.Context(), "correlation_id", "test-correlation-id-integration"))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}

		// Verify complete audit trail
		events := mockAuditLogger.GetEvents()
		if len(events) < 3 {
			t.Errorf("Expected at least 3 audit events, got %d", len(events))
		}

		// Verify all events have the same correlation ID
		correlationID := "test-correlation-id-integration"
		for i, event := range events {
			if event.CorrelationID != correlationID {
				t.Errorf("Event %d has wrong correlation ID: expected %s, got %s", i, correlationID, event.CorrelationID)
			}
		}

		// Verify event types are present
		eventActions := make(map[string]bool)
		for _, event := range events {
			eventActions[event.Action] = true
		}

		expectedActions := []string{
			audit.ActionTokenValidate,
			audit.ActionPolicyEvaluate,
			audit.ActionRedactData,
			audit.ActionResourceRead,
		}

		for _, expectedAction := range expectedActions {
			if !eventActions[expectedAction] {
				t.Errorf("Expected audit event with action %s not found", expectedAction)
			}
		}

		// Verify no sensitive data is logged
		for i, event := range events {
			if event.Metadata != nil {
				for key, value := range event.Metadata {
					if key == "ssn" || key == "password" || key == "token" {
						t.Errorf("Event %d contains sensitive data key %s: %v", i, key, value)
					}
					if strValue, ok := value.(string); ok {
						if strings.Contains(strValue, "123-45-6789") || strings.Contains(strValue, "password") {
							t.Errorf("Event %d contains sensitive data in value: %s", i, strValue)
						}
					}
				}
			}
		}
	})

	// Test authentication failure
	t.Run("AuthenticationFailure", func(t *testing.T) {
		mockAuditLogger.Reset()
		tokenValidator.shouldFail = true
		defer func() { tokenValidator.shouldFail = false }()

		req := httptest.NewRequest("GET", "/api/resource", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		req = req.WithContext(context.WithValue(req.Context(), "correlation_id", "test-correlation-id-auth-fail"))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}

		// Verify authentication failure is audited
		events := mockAuditLogger.GetEvents()
		if len(events) == 0 {
			t.Error("Expected at least 1 audit event for authentication failure")
		}

		authEvent := events[0]
		if authEvent.Action != audit.ActionTokenValidate {
			t.Errorf("Expected authentication event, got %s", authEvent.Action)
		}
		if authEvent.Decision != audit.DecisionDeny {
			t.Errorf("Expected decision deny, got %s", authEvent.Decision)
		}
	})

	// Test authorization failure
	t.Run("AuthorizationFailure", func(t *testing.T) {
		mockAuditLogger.Reset()
		policyEngine.shouldDeny = true
		defer func() { policyEngine.shouldDeny = false }()

		req := httptest.NewRequest("GET", "/api/resource", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		req = req.WithContext(context.WithValue(req.Context(), "correlation_id", "test-correlation-id-authz-fail"))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected status 403, got %d", rr.Code)
		}

		// Verify both authentication success and authorization failure are audited
		events := mockAuditLogger.GetEvents()
		if len(events) < 2 {
			t.Errorf("Expected at least 2 audit events, got %d", len(events))
		}

		// Find the policy evaluation event
		var policyEvent *audit.AuditEvent
		for _, event := range events {
			if event.Action == audit.ActionPolicyEvaluate {
				policyEvent = event
				break
			}
		}

		if policyEvent == nil {
			t.Error("Expected policy evaluation event not found")
		} else {
			if policyEvent.Decision != audit.DecisionDeny {
				t.Errorf("Expected policy decision deny, got %s", policyEvent.Decision)
			}
			if policyEvent.Reason != "insufficient_permissions" {
				t.Errorf("Expected reason 'insufficient_permissions', got %s", policyEvent.Reason)
			}
		}
	})

	// Test security violation
	t.Run("SecurityViolation", func(t *testing.T) {
		mockAuditLogger.Reset()

		req := httptest.NewRequest("GET", "/api/../etc/passwd", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		req = req.WithContext(context.WithValue(req.Context(), "correlation_id", "test-correlation-id-security-violation"))

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}

		// Verify security violation is audited
		events := mockAuditLogger.GetEvents()
		if len(events) == 0 {
			t.Error("Expected at least 1 audit event for security violation")
		}

		// Find the security violation event
		var securityEvent *audit.AuditEvent
		for _, event := range events {
			if event.Action == audit.EventTypeSecurityViolation {
				securityEvent = event
				break
			}
		}

		if securityEvent == nil {
			t.Error("Expected security violation event not found")
		} else {
			if securityEvent.Decision != audit.DecisionDeny {
				t.Errorf("Expected security decision deny, got %s", securityEvent.Decision)
			}
			if !strings.Contains(securityEvent.Reason, "Path traversal") {
				t.Errorf("Expected path traversal reason, got %s", securityEvent.Reason)
			}
		}
	})
}

func TestAuditEventStructure(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := audit.NewMockAuditLogger()
	securityAuditLogger := audit.NewSecurityAuditLogger(mockAuditLogger, logger)

	ctx := context.Background()
	correlationID := "test-correlation-id-structure"

	// Test that all required fields are populated
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

	// Verify required fields
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
}

func TestRedactionCountAuditing(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := audit.NewMockAuditLogger()
	securityAuditLogger := audit.NewSecurityAuditLogger(mockAuditLogger, logger)

	ctx := context.Background()
	correlationID := "test-correlation-id-redaction"

	// Test redaction event with counts
	err := securityAuditLogger.LogRedactionEvent(ctx, correlationID, "test-tenant", "test-user", "test-tool", "request", 5, map[string]int{
		"ssn":   3,
		"email": 2,
	}, 50*time.Millisecond, 2048)
	if err != nil {
		t.Fatalf("Failed to log redaction event: %v", err)
	}

	events := mockAuditLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]

	// Verify redaction count is properly logged
	if event.RedactionCount != 5 {
		t.Errorf("Expected redaction count 5, got %d", event.RedactionCount)
	}

	// Verify patterns hit are in metadata (not as raw sensitive data)
	if event.Metadata == nil {
		t.Error("Event metadata should not be nil")
	} else {
		if patternsHit, ok := event.Metadata["patterns_hit"].(map[string]int); ok {
			if patternsHit["ssn"] != 3 {
				t.Errorf("Expected SSN pattern hit count 3, got %d", patternsHit["ssn"])
			}
			if patternsHit["email"] != 2 {
				t.Errorf("Expected email pattern hit count 2, got %d", patternsHit["email"])
			}
		} else {
			t.Error("Expected patterns_hit in metadata")
		}
	}

	// Verify no raw sensitive data is logged
	for key, value := range event.Metadata {
		if key == "raw_data" || key == "original_data" {
			t.Errorf("Event contains raw sensitive data key %s: %v", key, value)
		}
	}
}

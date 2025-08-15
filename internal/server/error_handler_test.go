package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgerrors "github.com/ik-labs/mcp-airlock/pkg/errors"
	"go.uber.org/zap/zaptest"
)

// Use context keys defined in context.go

func TestNewErrorHandler(t *testing.T) {
	logger := zaptest.NewLogger(t)
	degradationManager := pkgerrors.NewDegradationManager(logger, nil, nil)

	eh := NewErrorHandler(logger, degradationManager)

	if eh.logger != logger {
		t.Error("expected logger to be set")
	}

	if eh.degradationManager != degradationManager {
		t.Error("expected degradation manager to be set")
	}

	if eh.retryConfig == nil {
		t.Error("expected retry config to be set")
	}

	if eh.circuitConfig == nil {
		t.Error("expected circuit config to be set")
	}
}

func TestHandleError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger, nil)

	// Create context with correlation ID
	ctx := context.WithValue(context.Background(), correlationIDKey, "test-correlation")

	// Test with HTTP error
	httpErr := pkgerrors.NewAuthenticationError("invalid token", "test-correlation")
	recorder := httptest.NewRecorder()

	eh.HandleError(ctx, httpErr, recorder, "req-123")

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}

	// Test with non-HTTP error
	genericErr := fmt.Errorf("generic error")
	recorder2 := httptest.NewRecorder()

	eh.HandleError(ctx, genericErr, recorder2, "req-456")

	if recorder2.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, recorder2.Code)
	}
}

func TestHandleUpstreamError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	degradationManager := pkgerrors.NewDegradationManager(logger, nil, nil)
	eh := NewErrorHandler(logger, degradationManager)

	ctx := context.WithValue(context.Background(), correlationIDKey, "test-correlation")

	// Test retryable error
	retryableErr := pkgerrors.NewUpstreamFailureError(502, "test-correlation")
	result := eh.HandleUpstreamError(ctx, "test-upstream", retryableErr)

	if !errors.Is(result, retryableErr) {
		t.Errorf("expected same error returned, got %v", result)
	}

	// Test non-retryable error
	nonRetryableErr := pkgerrors.NewAuthenticationError("invalid", "test-correlation")
	result2 := eh.HandleUpstreamError(ctx, "test-upstream", nonRetryableErr)

	if !errors.Is(result2, nonRetryableErr) {
		t.Errorf("expected same error returned, got %v", result2)
	}
}

func TestHandleAuditError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	degradationManager := pkgerrors.NewDegradationManager(logger, nil, nil)
	eh := NewErrorHandler(logger, degradationManager)

	ctx := context.WithValue(context.Background(), correlationIDKey, "test-correlation")

	event := pkgerrors.AuditEvent{
		ID:            "test-event",
		Timestamp:     time.Now(),
		CorrelationID: "test-correlation",
		Action:        "test_action",
		Subject:       "test_subject",
		Tenant:        "test_tenant",
	}

	auditErr := fmt.Errorf("audit store connection failed")
	result := eh.HandleAuditError(ctx, event, auditErr)

	if !errors.Is(result, auditErr) {
		t.Errorf("expected same error returned, got %v", result)
	}

	// Check if degradation manager recorded the failure
	status := degradationManager.GetDegradationStatus()
	if status["mode"] != "audit_buffering" {
		t.Errorf("expected audit_buffering mode, got %v", status["mode"])
	}

	// Check if event was buffered
	if degradationManager.GetAuditBufferSize() != 1 {
		t.Errorf("expected 1 buffered event, got %d", degradationManager.GetAuditBufferSize())
	}
}

func TestRetryUpstreamCall(t *testing.T) {
	logger := zaptest.NewLogger(t)
	degradationManager := pkgerrors.NewDegradationManager(logger, nil, nil)
	eh := NewErrorHandler(logger, degradationManager)

	// Set fast retry config for testing
	eh.SetRetryConfig(&pkgerrors.RetryConfig{
		MaxAttempts:   2,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      10 * time.Millisecond,
		Multiplier:    2.0,
		JitterPercent: 0,
	})

	ctx := context.WithValue(context.Background(), correlationIDKey, "test-correlation")

	// Test successful call after retry
	attempts := 0
	successFn := func(ctx context.Context) error {
		attempts++
		if attempts < 2 {
			return pkgerrors.NewUpstreamFailureError(502, "test-correlation")
		}
		return nil
	}

	err := eh.RetryUpstreamCall(ctx, "test-upstream", successFn)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}

	// Test failed call
	failFn := func(ctx context.Context) error {
		return pkgerrors.NewUpstreamFailureError(502, "test-correlation")
	}

	err2 := eh.RetryUpstreamCall(ctx, "test-upstream", failFn)
	if err2 == nil {
		t.Error("expected error from failed call")
	}
}

func TestCreateErrors(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger, nil)

	ctx := context.WithValue(context.Background(), correlationIDKey, "test-correlation")
	ctx = context.WithValue(ctx, tenantKey, "test-tenant")

	// Test authentication error
	authErr := eh.CreateAuthenticationError(ctx, "invalid token")
	if authErr.HTTPStatus != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, authErr.HTTPStatus)
	}

	// Test policy denial error
	policyErr := eh.CreatePolicyDenialError(ctx, "access denied", "rule-123")
	if policyErr.HTTPStatus != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, policyErr.HTTPStatus)
	}

	// Test message too large error
	sizeErr := eh.CreateMessageTooLargeError(ctx, 256, 512)
	if sizeErr.HTTPStatus != http.StatusRequestEntityTooLarge {
		t.Errorf("expected status %d, got %d", http.StatusRequestEntityTooLarge, sizeErr.HTTPStatus)
	}

	// Test rate limit error
	rateLimitErr := eh.CreateRateLimitError(ctx, time.Minute)
	if rateLimitErr.HTTPStatus != http.StatusTooManyRequests {
		t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, rateLimitErr.HTTPStatus)
	}

	// Test timeout error
	timeoutErr := eh.CreateTimeoutError(ctx, 30)
	if timeoutErr.HTTPStatus != http.StatusGatewayTimeout {
		t.Errorf("expected status %d, got %d", http.StatusGatewayTimeout, timeoutErr.HTTPStatus)
	}
}

func TestValidateMessageSize(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger, nil)

	ctx := context.WithValue(context.Background(), correlationIDKey, "test-correlation")

	// Test valid size
	smallData := make([]byte, 100*1024) // 100KB
	err := eh.ValidateMessageSize(ctx, smallData, 256)
	if err != nil {
		t.Errorf("expected no error for valid size, got %v", err)
	}

	// Test oversized message
	largeData := make([]byte, 300*1024) // 300KB
	err2 := eh.ValidateMessageSize(ctx, largeData, 256)
	if err2 == nil {
		t.Error("expected error for oversized message")
	}

	var httpErr *pkgerrors.HTTPError
	if errors.As(err2, &httpErr) {
		if httpErr.HTTPStatus != http.StatusRequestEntityTooLarge {
			t.Errorf("expected status %d, got %d", http.StatusRequestEntityTooLarge, httpErr.HTTPStatus)
		}
	}
}

func TestWrapJSONRPCError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger, nil)

	ctx := context.WithValue(context.Background(), correlationIDKey, "test-correlation")

	// Test with HTTP error
	httpErr := pkgerrors.NewAuthenticationError("invalid token", "test-correlation")
	data := eh.WrapJSONRPCError(ctx, httpErr, "req-123")

	if len(data) == 0 {
		t.Error("expected non-empty JSON response")
	}

	// Test with generic error
	genericErr := fmt.Errorf("generic error")
	data2 := eh.WrapJSONRPCError(ctx, genericErr, "req-456")

	if len(data2) == 0 {
		t.Error("expected non-empty JSON response")
	}
}

func TestGetDegradationStatus(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Test without degradation manager
	eh1 := NewErrorHandler(logger, nil)
	status1 := eh1.GetDegradationStatus()

	if status1["mode"] != "normal" {
		t.Errorf("expected normal mode, got %v", status1["mode"])
	}

	// Test with degradation manager
	degradationManager := pkgerrors.NewDegradationManager(logger, nil, nil)
	eh2 := NewErrorHandler(logger, degradationManager)

	// Record a failure
	degradationManager.RecordServiceFailure("audit", fmt.Errorf("test failure"))

	status2 := eh2.GetDegradationStatus()
	if status2["mode"] != "audit_buffering" {
		t.Errorf("expected audit_buffering mode, got %v", status2["mode"])
	}
}

func TestFlushAuditBuffer(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Test without degradation manager
	eh1 := NewErrorHandler(logger, nil)
	events1 := eh1.FlushAuditBuffer()
	if events1 != nil {
		t.Error("expected nil events without degradation manager")
	}

	// Test with degradation manager
	degradationManager := pkgerrors.NewDegradationManager(logger, nil, nil)
	eh2 := NewErrorHandler(logger, degradationManager)

	// Buffer an event
	event := pkgerrors.AuditEvent{
		ID:            "test-event",
		Timestamp:     time.Now(),
		CorrelationID: "test-correlation",
		Action:        "test_action",
		Subject:       "test_subject",
		Tenant:        "test_tenant",
	}

	err := degradationManager.BufferAuditEvent(event)
	if err != nil {
		return
	}

	events2 := eh2.FlushAuditBuffer()
	if len(events2) != 1 {
		t.Errorf("expected 1 event, got %d", len(events2))
	}
}

func TestIsAuditBuffering(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Test without degradation manager
	eh1 := NewErrorHandler(logger, nil)
	if eh1.IsAuditBuffering() {
		t.Error("expected not buffering without degradation manager")
	}

	// Test with degradation manager
	degradationManager := pkgerrors.NewDegradationManager(logger, nil, nil)
	eh2 := NewErrorHandler(logger, degradationManager)

	if eh2.IsAuditBuffering() {
		t.Error("expected not buffering initially")
	}

	// Record audit failure
	degradationManager.RecordServiceFailure("audit", fmt.Errorf("test failure"))

	if !eh2.IsAuditBuffering() {
		t.Error("expected buffering after audit failure")
	}
}

func TestSetConfigs(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eh := NewErrorHandler(logger, nil)

	// Test setting retry config
	newRetryConfig := &pkgerrors.RetryConfig{
		MaxAttempts:   5,
		InitialDelay:  200 * time.Millisecond,
		MaxDelay:      10 * time.Second,
		Multiplier:    3.0,
		JitterPercent: 0.2,
	}

	eh.SetRetryConfig(newRetryConfig)
	if eh.retryConfig != newRetryConfig {
		t.Error("expected retry config to be updated")
	}

	// Test setting circuit breaker config
	newCircuitConfig := &pkgerrors.CircuitBreakerConfig{
		MaxFailures:   10,
		ResetTimeout:  60 * time.Second,
		HalfOpenMax:   5,
		FailureWindow: 120 * time.Second,
	}

	eh.SetCircuitBreakerConfig(newCircuitConfig)
	if eh.circuitConfig != newCircuitConfig {
		t.Error("expected circuit config to be updated")
	}

	// Test setting nil configs (should not update)
	originalRetryConfig := eh.retryConfig
	originalCircuitConfig := eh.circuitConfig

	eh.SetRetryConfig(nil)
	eh.SetCircuitBreakerConfig(nil)

	if eh.retryConfig != originalRetryConfig {
		t.Error("expected retry config to remain unchanged with nil input")
	}

	if eh.circuitConfig != originalCircuitConfig {
		t.Error("expected circuit config to remain unchanged with nil input")
	}
}

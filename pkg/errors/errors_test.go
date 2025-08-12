package errors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewMCPError(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		message  string
		data     any
		expected *MCPError
	}{
		{
			name:    "basic error",
			code:    ErrorCodeInvalidRequest,
			message: "Invalid request",
			data:    nil,
			expected: &MCPError{
				Code:    ErrorCodeInvalidRequest,
				Message: "Invalid request",
				Data:    nil,
			},
		},
		{
			name:    "error with data",
			code:    ErrorCodeForbidden,
			message: "Access denied",
			data:    map[string]any{"reason": "insufficient permissions"},
			expected: &MCPError{
				Code:    ErrorCodeForbidden,
				Message: "Access denied",
				Data:    map[string]any{"reason": "insufficient permissions"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewMCPError(tt.code, tt.message, tt.data)
			if err.Code != tt.expected.Code {
				t.Errorf("expected code %d, got %d", tt.expected.Code, err.Code)
			}
			if err.Message != tt.expected.Message {
				t.Errorf("expected message %q, got %q", tt.expected.Message, err.Message)
			}
		})
	}
}

func TestHTTPToMCPMapping(t *testing.T) {
	tests := []struct {
		httpStatus int
		expected   int
	}{
		{http.StatusBadRequest, ErrorCodeInvalidRequest},
		{http.StatusUnauthorized, ErrorCodeAuthFailed},
		{http.StatusForbidden, ErrorCodeForbidden},
		{http.StatusNotFound, ErrorCodeResourceNotFound},
		{http.StatusRequestEntityTooLarge, ErrorCodeRequestTooLarge},
		{http.StatusTooManyRequests, ErrorCodeRateLimitHit},
		{http.StatusBadGateway, ErrorCodeUpstreamFailure},
		{http.StatusServiceUnavailable, ErrorCodeCircuitOpen},
		{http.StatusGatewayTimeout, ErrorCodeTimeout},
		{http.StatusInternalServerError, ErrorCodeInternalError},
		{999, ErrorCodeInternalError}, // Unknown status should map to internal error
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.httpStatus), func(t *testing.T) {
			result := MapHTTPStatusToMCP(tt.httpStatus)
			if result != tt.expected {
				t.Errorf("expected MCP code %d for HTTP %d, got %d", tt.expected, tt.httpStatus, result)
			}
		})
	}
}

func TestNewAuthenticationError(t *testing.T) {
	reason := "invalid token"
	correlationID := "test-correlation-123"

	err := NewAuthenticationError(reason, correlationID)

	if err.HTTPStatus != http.StatusUnauthorized {
		t.Errorf("expected HTTP status %d, got %d", http.StatusUnauthorized, err.HTTPStatus)
	}

	if err.MCPError.Code != ErrorCodeAuthFailed {
		t.Errorf("expected MCP code %d, got %d", ErrorCodeAuthFailed, err.MCPError.Code)
	}

	data, ok := err.MCPError.Data.(map[string]any)
	if !ok {
		t.Fatal("expected data to be map[string]any")
	}

	if data["reason"] != reason {
		t.Errorf("expected reason %q, got %q", reason, data["reason"])
	}

	if data["correlation_id"] != correlationID {
		t.Errorf("expected correlation_id %q, got %q", correlationID, data["correlation_id"])
	}

	if data["www_authenticate"] != "Bearer realm=\"mcp-airlock\"" {
		t.Errorf("unexpected www_authenticate header: %v", data["www_authenticate"])
	}
}

func TestNewPolicyDenialError(t *testing.T) {
	reason := "insufficient permissions"
	ruleID := "rule-123"
	tenant := "tenant-456"
	correlationID := "corr-789"

	err := NewPolicyDenialError(reason, ruleID, tenant, correlationID)

	if err.HTTPStatus != http.StatusForbidden {
		t.Errorf("expected HTTP status %d, got %d", http.StatusForbidden, err.HTTPStatus)
	}

	if err.MCPError.Code != ErrorCodeForbidden {
		t.Errorf("expected MCP code %d, got %d", ErrorCodeForbidden, err.MCPError.Code)
	}

	data, ok := err.MCPError.Data.(map[string]any)
	if !ok {
		t.Fatal("expected data to be map[string]any")
	}

	expectedFields := map[string]string{
		"reason":         reason,
		"rule_id":        ruleID,
		"tenant":         tenant,
		"correlation_id": correlationID,
	}

	for field, expected := range expectedFields {
		if data[field] != expected {
			t.Errorf("expected %s %q, got %q", field, expected, data[field])
		}
	}
}

func TestNewMessageTooLargeError(t *testing.T) {
	maxSizeKB := 256
	actualSizeKB := 512
	correlationID := "corr-123"

	err := NewMessageTooLargeError(maxSizeKB, actualSizeKB, correlationID)

	if err.HTTPStatus != http.StatusRequestEntityTooLarge {
		t.Errorf("expected HTTP status %d, got %d", http.StatusRequestEntityTooLarge, err.HTTPStatus)
	}

	if err.MCPError.Code != ErrorCodeRequestTooLarge {
		t.Errorf("expected MCP code %d, got %d", ErrorCodeRequestTooLarge, err.MCPError.Code)
	}

	data, ok := err.MCPError.Data.(map[string]any)
	if !ok {
		t.Fatal("expected data to be map[string]any")
	}

	if data["max_size_kb"] != maxSizeKB {
		t.Errorf("expected max_size_kb %d, got %v", maxSizeKB, data["max_size_kb"])
	}

	if data["actual_size_kb"] != actualSizeKB {
		t.Errorf("expected actual_size_kb %d, got %v", actualSizeKB, data["actual_size_kb"])
	}
}

func TestToJSONRPCResponse(t *testing.T) {
	err := NewInternalError("test-correlation")
	requestID := "req-123"

	response := err.ToJSONRPCResponse(requestID)

	if response.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", response.JSONRPC)
	}

	if response.ID != requestID {
		t.Errorf("expected ID %q, got %v", requestID, response.ID)
	}

	if response.Error != err.MCPError {
		t.Error("expected error to match MCPError")
	}
}

func TestWriteHTTPResponse(t *testing.T) {
	err := NewAuthenticationError("invalid token", "test-correlation")
	requestID := "req-123"

	recorder := httptest.NewRecorder()
	writeErr := err.WriteHTTPResponse(recorder, requestID)

	if writeErr != nil {
		t.Fatalf("unexpected error writing response: %v", writeErr)
	}

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}

	contentType := recorder.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", contentType)
	}

	var response ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", response.JSONRPC)
	}

	if response.ID != requestID {
		t.Errorf("expected ID %q, got %v", requestID, response.ID)
	}
}

func TestGetCorrelationID(t *testing.T) {
	correlationID := "test-correlation-123"
	err := NewInternalError(correlationID)

	result := err.GetCorrelationID()
	if result != correlationID {
		t.Errorf("expected correlation ID %q, got %q", correlationID, result)
	}

	// Test error without correlation ID
	errWithoutCorr := &HTTPError{
		HTTPStatus: http.StatusInternalServerError,
		MCPError:   NewMCPError(ErrorCodeInternalError, "test", nil),
	}

	result = errWithoutCorr.GetCorrelationID()
	if result != "" {
		t.Errorf("expected empty correlation ID, got %q", result)
	}
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "bad gateway - retryable",
			err:      NewUpstreamFailureError(502, "test"),
			expected: true,
		},
		{
			name:     "service unavailable - retryable",
			err:      NewCircuitOpenError(time.Minute, "test"),
			expected: true,
		},
		{
			name:     "gateway timeout - retryable",
			err:      NewTimeoutError(30, "test"),
			expected: true,
		},
		{
			name:     "authentication error - not retryable",
			err:      NewAuthenticationError("invalid", "test"),
			expected: false,
		},
		{
			name:     "policy denial - not retryable",
			err:      NewPolicyDenialError("denied", "rule", "tenant", "test"),
			expected: false,
		},
		{
			name:     "non-HTTP error - not retryable",
			err:      context.DeadlineExceeded,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryableError(tt.err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsClientError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "authentication error - client error",
			err:      NewAuthenticationError("invalid", "test"),
			expected: true,
		},
		{
			name:     "policy denial - client error",
			err:      NewPolicyDenialError("denied", "rule", "tenant", "test"),
			expected: true,
		},
		{
			name:     "message too large - client error",
			err:      NewMessageTooLargeError(256, 512, "test"),
			expected: true,
		},
		{
			name:     "internal error - not client error",
			err:      NewInternalError("test"),
			expected: false,
		},
		{
			name:     "upstream failure - not client error",
			err:      NewUpstreamFailureError(502, "test"),
			expected: false,
		},
		{
			name:     "non-HTTP error - not client error",
			err:      context.DeadlineExceeded,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsClientError(tt.err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsServerError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "internal error - server error",
			err:      NewInternalError("test"),
			expected: true,
		},
		{
			name:     "upstream failure - server error",
			err:      NewUpstreamFailureError(502, "test"),
			expected: true,
		},
		{
			name:     "circuit open - server error",
			err:      NewCircuitOpenError(time.Minute, "test"),
			expected: true,
		},
		{
			name:     "timeout - server error",
			err:      NewTimeoutError(30, "test"),
			expected: true,
		},
		{
			name:     "authentication error - not server error",
			err:      NewAuthenticationError("invalid", "test"),
			expected: false,
		},
		{
			name:     "policy denial - not server error",
			err:      NewPolicyDenialError("denied", "rule", "tenant", "test"),
			expected: false,
		},
		{
			name:     "non-HTTP error - not server error",
			err:      context.DeadlineExceeded,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsServerError(tt.err)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestNewErrorContext(t *testing.T) {
	// Create context with values using exported context keys
	ctx := context.Background()
	ctx = context.WithValue(ctx, CorrelationIDKey, "test-correlation")
	ctx = context.WithValue(ctx, TenantKey, "test-tenant")
	ctx = context.WithValue(ctx, SubjectKey, "test-subject")
	ctx = context.WithValue(ctx, ToolKey, "test-tool")

	errorCtx := NewErrorContext(ctx)

	if errorCtx.CorrelationID != "test-correlation" {
		t.Errorf("expected correlation ID %q, got %q", "test-correlation", errorCtx.CorrelationID)
	}

	if errorCtx.Tenant != "test-tenant" {
		t.Errorf("expected tenant %q, got %q", "test-tenant", errorCtx.Tenant)
	}

	if errorCtx.Subject != "test-subject" {
		t.Errorf("expected subject %q, got %q", "test-subject", errorCtx.Subject)
	}

	if errorCtx.Tool != "test-tool" {
		t.Errorf("expected tool %q, got %q", "test-tool", errorCtx.Tool)
	}

	// Test duration
	time.Sleep(10 * time.Millisecond)
	duration := errorCtx.Duration()
	if duration < 10*time.Millisecond {
		t.Errorf("expected duration >= 10ms, got %v", duration)
	}
}

func TestNewErrorContextWithMissingValues(t *testing.T) {
	ctx := context.Background()
	errorCtx := NewErrorContext(ctx)

	if errorCtx.CorrelationID != "unknown" {
		t.Errorf("expected correlation ID %q, got %q", "unknown", errorCtx.CorrelationID)
	}

	if errorCtx.Tenant != "unknown" {
		t.Errorf("expected tenant %q, got %q", "unknown", errorCtx.Tenant)
	}

	if errorCtx.Subject != "unknown" {
		t.Errorf("expected subject %q, got %q", "unknown", errorCtx.Subject)
	}

	if errorCtx.Tool != "unknown" {
		t.Errorf("expected tool %q, got %q", "unknown", errorCtx.Tool)
	}
}

// Benchmark tests for performance validation
func BenchmarkNewMCPError(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewMCPError(ErrorCodeInternalError, "test error", map[string]any{"key": "value"})
	}
}

func BenchmarkNewAuthenticationError(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewAuthenticationError("invalid token", "correlation-123")
	}
}

func BenchmarkMapHTTPStatusToMCP(b *testing.B) {
	statuses := []int{400, 401, 403, 404, 413, 429, 500, 502, 503, 504}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		status := statuses[i%len(statuses)]
		MapHTTPStatusToMCP(status)
	}
}

func BenchmarkToJSONRPCResponse(b *testing.B) {
	err := NewInternalError("test-correlation")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err.ToJSONRPCResponse("request-123")
	}
}

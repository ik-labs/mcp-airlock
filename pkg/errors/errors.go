// Package errors provides deterministic error handling with HTTP-to-MCP mapping
// for the MCP Airlock gateway, ensuring consistent error responses across all components.
package errors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// MCPError represents a Model Context Protocol error response
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Error implements the error interface
func (e *MCPError) Error() string {
	return fmt.Sprintf("MCP error %d: %s", e.Code, e.Message)
}

// HTTPError represents an HTTP error with MCP mapping
type HTTPError struct {
	HTTPStatus int
	MCPError   *MCPError
}

// Error implements the error interface
func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.HTTPStatus, e.MCPError.Error())
}

// MCP Error Codes (JSON-RPC 2.0 specification)
const (
	// Standard JSON-RPC errors
	ErrorCodeParseError     = -32700
	ErrorCodeInvalidRequest = -32600
	ErrorCodeMethodNotFound = -32601
	ErrorCodeInvalidParams  = -32602
	ErrorCodeInternalError  = -32603

	// MCP-specific errors (application-defined range)
	ErrorCodeForbidden        = -32000
	ErrorCodeRequestTooLarge  = -32001
	ErrorCodeUpstreamFailure  = -32002
	ErrorCodeRateLimitHit     = -32003
	ErrorCodePolicyDenied     = -32004
	ErrorCodeAuthFailed       = -32005
	ErrorCodeResourceNotFound = -32006
	ErrorCodeTimeout          = -32007
	ErrorCodeCircuitOpen      = -32008
)

// HTTP Status to MCP Error mapping table
var httpToMCPMapping = map[int]int{
	http.StatusBadRequest:            ErrorCodeInvalidRequest,
	http.StatusUnauthorized:          ErrorCodeAuthFailed,
	http.StatusForbidden:             ErrorCodeForbidden,
	http.StatusNotFound:              ErrorCodeResourceNotFound,
	http.StatusRequestEntityTooLarge: ErrorCodeRequestTooLarge,
	http.StatusTooManyRequests:       ErrorCodeRateLimitHit,
	http.StatusBadGateway:            ErrorCodeUpstreamFailure,
	http.StatusServiceUnavailable:    ErrorCodeCircuitOpen,
	http.StatusGatewayTimeout:        ErrorCodeTimeout,
	http.StatusInternalServerError:   ErrorCodeInternalError,
}

// ErrorResponse represents a complete JSON-RPC error response
type ErrorResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Error   *MCPError `json:"error"`
}

// NewMCPError creates a new MCP error with the given code and message
func NewMCPError(code int, message string, data any) *MCPError {
	return &MCPError{
		Code:    code,
		Message: message,
		Data:    data,
	}
}

// NewHTTPError creates a new HTTP error with MCP mapping
func NewHTTPError(httpStatus int, message string, data any) *HTTPError {
	mcpCode, exists := httpToMCPMapping[httpStatus]
	if !exists {
		mcpCode = ErrorCodeInternalError
	}

	return &HTTPError{
		HTTPStatus: httpStatus,
		MCPError:   NewMCPError(mcpCode, message, data),
	}
}

// NewAuthenticationError creates a 401 authentication error
func NewAuthenticationError(reason string, correlationID string) *HTTPError {
	data := map[string]any{
		"reason":           reason,
		"www_authenticate": "Bearer realm=\"mcp-airlock\"",
		"correlation_id":   correlationID,
	}

	return NewHTTPError(http.StatusUnauthorized, "Authentication failed", data)
}

// NewPolicyDenialError creates a 403 policy denial error
func NewPolicyDenialError(reason, ruleID, tenant, correlationID string) *HTTPError {
	data := map[string]any{
		"reason":         reason,
		"rule_id":        ruleID,
		"tenant":         tenant,
		"correlation_id": correlationID,
	}

	return NewHTTPError(http.StatusForbidden, "Policy denied request", data)
}

// NewMessageTooLargeError creates a 413 message too large error
func NewMessageTooLargeError(maxSizeKB, actualSizeKB int, correlationID string) *HTTPError {
	data := map[string]any{
		"max_size_kb":    maxSizeKB,
		"actual_size_kb": actualSizeKB,
		"correlation_id": correlationID,
	}

	return NewHTTPError(http.StatusRequestEntityTooLarge, "Request too large", data)
}

// NewUpstreamFailureError creates a 502 upstream failure error
func NewUpstreamFailureError(upstreamStatus int, correlationID string) *HTTPError {
	data := map[string]any{
		"upstream_status": upstreamStatus,
		"correlation_id":  correlationID,
	}

	return NewHTTPError(http.StatusBadGateway, "Upstream server error", data)
}

// NewInternalError creates a 500 internal error (no sensitive details)
func NewInternalError(correlationID string) *HTTPError {
	data := map[string]any{
		"correlation_id": correlationID,
	}

	return NewHTTPError(http.StatusInternalServerError, "Internal server error", data)
}

// NewRateLimitError creates a 429 rate limit error
func NewRateLimitError(retryAfter time.Duration, correlationID string) *HTTPError {
	data := map[string]any{
		"retry_after_seconds": int(retryAfter.Seconds()),
		"correlation_id":      correlationID,
	}

	return NewHTTPError(http.StatusTooManyRequests, "Rate limit exceeded", data)
}

// NewTimeoutError creates a 504 timeout error
func NewTimeoutError(timeoutSeconds int, correlationID string) *HTTPError {
	data := map[string]any{
		"timeout_seconds": timeoutSeconds,
		"correlation_id":  correlationID,
	}

	return NewHTTPError(http.StatusGatewayTimeout, "Request timeout", data)
}

// NewCircuitOpenError creates a 503 circuit breaker open error
func NewCircuitOpenError(retryAfter time.Duration, correlationID string) *HTTPError {
	data := map[string]any{
		"retry_after_seconds": int(retryAfter.Seconds()),
		"correlation_id":      correlationID,
	}

	return NewHTTPError(http.StatusServiceUnavailable, "Circuit breaker open", data)
}

// ToJSONRPCResponse converts an HTTPError to a JSON-RPC error response
func (e *HTTPError) ToJSONRPCResponse(id any) *ErrorResponse {
	return &ErrorResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   e.MCPError,
	}
}

// WriteHTTPResponse writes the error as an HTTP response
func (e *HTTPError) WriteHTTPResponse(w http.ResponseWriter, requestID any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.HTTPStatus)

	response := e.ToJSONRPCResponse(requestID)
	return json.NewEncoder(w).Encode(response)
}

// GetCorrelationID extracts correlation ID from error data
func (e *HTTPError) GetCorrelationID() string {
	if e.MCPError.Data == nil {
		return ""
	}

	if data, ok := e.MCPError.Data.(map[string]any); ok {
		if correlationID, ok := data["correlation_id"].(string); ok {
			return correlationID
		}
	}

	return ""
}

// MapHTTPStatusToMCP maps HTTP status codes to MCP error codes
func MapHTTPStatusToMCP(httpStatus int) int {
	if mcpCode, exists := httpToMCPMapping[httpStatus]; exists {
		return mcpCode
	}
	return ErrorCodeInternalError
}

// IsRetryableError determines if an error should trigger retry logic
func IsRetryableError(err error) bool {
	if httpErr, ok := err.(*HTTPError); ok {
		switch httpErr.HTTPStatus {
		case http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			return true
		}
	}
	return false
}

// IsClientError determines if an error is a client-side error (4xx)
func IsClientError(err error) bool {
	if httpErr, ok := err.(*HTTPError); ok {
		return httpErr.HTTPStatus >= 400 && httpErr.HTTPStatus < 500
	}
	return false
}

// IsServerError determines if an error is a server-side error (5xx)
func IsServerError(err error) bool {
	if httpErr, ok := err.(*HTTPError); ok {
		return httpErr.HTTPStatus >= 500
	}
	return false
}

// ErrorContext provides context for error handling
type ErrorContext struct {
	CorrelationID string
	Tenant        string
	Subject       string
	Tool          string
	Resource      string
	StartTime     time.Time
}

// NewErrorContext creates error context from request context
func NewErrorContext(ctx context.Context) *ErrorContext {
	return &ErrorContext{
		CorrelationID: getCorrelationID(ctx),
		Tenant:        getTenant(ctx),
		Subject:       getSubject(ctx),
		Tool:          getTool(ctx),
		StartTime:     time.Now(),
	}
}

// Helper functions to extract values from context
// These should match the context functions in internal/server/context.go
func getCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value("correlation_id").(string); ok {
		return id
	}
	return "unknown"
}

func getTenant(ctx context.Context) string {
	if tenant, ok := ctx.Value("tenant").(string); ok {
		return tenant
	}
	return "unknown"
}

func getSubject(ctx context.Context) string {
	if subject, ok := ctx.Value("subject").(string); ok {
		return subject
	}
	return "unknown"
}

func getTool(ctx context.Context) string {
	if tool, ok := ctx.Value("tool").(string); ok {
		return tool
	}
	return "unknown"
}

// Duration returns the elapsed time since error context creation
func (ec *ErrorContext) Duration() time.Duration {
	return time.Since(ec.StartTime)
}

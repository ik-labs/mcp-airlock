// Package server provides error handling integration for the MCP Airlock server
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	pkgerrors "github.com/ik-labs/mcp-airlock/pkg/errors"
	"go.uber.org/zap"
)

// ErrorHandler provides centralized error handling for the MCP server
type ErrorHandler struct {
	logger             *zap.Logger
	degradationManager *pkgerrors.DegradationManager
	retryConfig        *pkgerrors.RetryConfig
	circuitConfig      *pkgerrors.CircuitBreakerConfig
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(logger *zap.Logger, degradationManager *pkgerrors.DegradationManager) *ErrorHandler {
	return &ErrorHandler{
		logger:             logger,
		degradationManager: degradationManager,
		retryConfig:        pkgerrors.DefaultRetryConfig(),
		circuitConfig:      pkgerrors.DefaultCircuitBreakerConfig(),
	}
}

// HandleError processes an error and returns appropriate HTTP response
func (eh *ErrorHandler) HandleError(ctx context.Context, err error, w http.ResponseWriter, requestID any) {
	errorCtx := pkgerrors.NewErrorContext(ctx)

	// Log the error with context
	eh.logger.Error("Request error",
		zap.Error(err),
		zap.String("correlation_id", errorCtx.CorrelationID),
		zap.String("tenant", errorCtx.Tenant),
		zap.String("subject", errorCtx.Subject),
		zap.String("tool", errorCtx.Tool),
		zap.Duration("duration", errorCtx.Duration()),
	)

	// Convert to HTTP error if not already
	var httpErr *pkgerrors.HTTPError
	if he, ok := err.(*pkgerrors.HTTPError); ok {
		httpErr = he
	} else {
		// Create internal error for unknown errors
		httpErr = pkgerrors.NewInternalError(errorCtx.CorrelationID)
	}

	// Write HTTP response
	if writeErr := httpErr.WriteHTTPResponse(w, requestID); writeErr != nil {
		eh.logger.Error("Failed to write error response",
			zap.Error(writeErr),
			zap.String("correlation_id", errorCtx.CorrelationID),
		)
	}
}

// HandleUpstreamError handles errors from upstream MCP servers with retry logic
func (eh *ErrorHandler) HandleUpstreamError(ctx context.Context, upstreamName string, err error) error {
	errorCtx := pkgerrors.NewErrorContext(ctx)

	// Check if error is retryable
	if !pkgerrors.IsRetryableError(err) {
		eh.logger.Warn("Non-retryable upstream error",
			zap.String("upstream", upstreamName),
			zap.Error(err),
			zap.String("correlation_id", errorCtx.CorrelationID),
		)
		return err
	}

	// Record upstream failure for degradation tracking
	if eh.degradationManager != nil {
		eh.degradationManager.RecordServiceFailure("upstream:"+upstreamName, err)
	}

	eh.logger.Error("Upstream error",
		zap.String("upstream", upstreamName),
		zap.Error(err),
		zap.String("correlation_id", errorCtx.CorrelationID),
		zap.Bool("retryable", pkgerrors.IsRetryableError(err)),
	)

	return err
}

// HandleAuditError handles audit system failures with graceful degradation
func (eh *ErrorHandler) HandleAuditError(ctx context.Context, event pkgerrors.AuditEvent, err error) error {
	errorCtx := pkgerrors.NewErrorContext(ctx)

	eh.logger.Error("Audit system error",
		zap.Error(err),
		zap.String("correlation_id", errorCtx.CorrelationID),
		zap.String("event_id", event.ID),
		zap.String("action", event.Action),
	)

	// Record audit service failure
	if eh.degradationManager != nil {
		eh.degradationManager.RecordServiceFailure("audit", err)

		// Buffer the event if in degradation mode
		if eh.degradationManager.IsAuditBuffering() {
			if bufferErr := eh.degradationManager.BufferAuditEvent(event); bufferErr != nil {
				eh.logger.Error("Failed to buffer audit event",
					zap.Error(bufferErr),
					zap.String("correlation_id", errorCtx.CorrelationID),
					zap.String("event_id", event.ID),
				)
				return bufferErr
			}

			eh.logger.Info("Audit event buffered due to system failure",
				zap.String("correlation_id", errorCtx.CorrelationID),
				zap.String("event_id", event.ID),
				zap.Int("buffer_size", eh.degradationManager.GetAuditBufferSize()),
			)
		}
	}

	return err
}

// RetryUpstreamCall executes an upstream call with retry logic
func (eh *ErrorHandler) RetryUpstreamCall(ctx context.Context, upstreamName string, fn pkgerrors.RetryableFunc) error {
	result, err := pkgerrors.RetryWithCircuitBreaker(ctx, eh.retryConfig, eh.circuitConfig, fn)

	errorCtx := pkgerrors.NewErrorContext(ctx)

	if err != nil {
		eh.logger.Error("Upstream call failed after retries",
			zap.String("upstream", upstreamName),
			zap.Error(err),
			zap.String("correlation_id", errorCtx.CorrelationID),
			zap.Int("attempts", result.Attempts),
			zap.Duration("total_duration", result.Duration),
		)

		// Record failure for degradation tracking
		if eh.degradationManager != nil {
			eh.degradationManager.RecordServiceFailure("upstream:"+upstreamName, err)
		}
	} else {
		eh.logger.Info("Upstream call succeeded",
			zap.String("upstream", upstreamName),
			zap.String("correlation_id", errorCtx.CorrelationID),
			zap.Int("attempts", result.Attempts),
			zap.Duration("duration", result.Duration),
		)

		// Record recovery if there were previous failures
		if eh.degradationManager != nil {
			eh.degradationManager.RecordServiceRecovery("upstream:" + upstreamName)
		}
	}

	return err
}

// CreateAuthenticationError creates a standardized authentication error
func (eh *ErrorHandler) CreateAuthenticationError(ctx context.Context, reason string) *pkgerrors.HTTPError {
	errorCtx := pkgerrors.NewErrorContext(ctx)
	return pkgerrors.NewAuthenticationError(reason, errorCtx.CorrelationID)
}

// CreatePolicyDenialError creates a standardized policy denial error
func (eh *ErrorHandler) CreatePolicyDenialError(ctx context.Context, reason, ruleID string) *pkgerrors.HTTPError {
	errorCtx := pkgerrors.NewErrorContext(ctx)
	return pkgerrors.NewPolicyDenialError(reason, ruleID, errorCtx.Tenant, errorCtx.CorrelationID)
}

// CreateMessageTooLargeError creates a standardized message size error
func (eh *ErrorHandler) CreateMessageTooLargeError(ctx context.Context, maxSizeKB, actualSizeKB int) *pkgerrors.HTTPError {
	errorCtx := pkgerrors.NewErrorContext(ctx)
	return pkgerrors.NewMessageTooLargeError(maxSizeKB, actualSizeKB, errorCtx.CorrelationID)
}

// CreateRateLimitError creates a standardized rate limit error
func (eh *ErrorHandler) CreateRateLimitError(ctx context.Context, retryAfter time.Duration) *pkgerrors.HTTPError {
	errorCtx := pkgerrors.NewErrorContext(ctx)
	return pkgerrors.NewRateLimitError(retryAfter, errorCtx.CorrelationID)
}

// CreateTimeoutError creates a standardized timeout error
func (eh *ErrorHandler) CreateTimeoutError(ctx context.Context, timeoutSeconds int) *pkgerrors.HTTPError {
	errorCtx := pkgerrors.NewErrorContext(ctx)
	return pkgerrors.NewTimeoutError(timeoutSeconds, errorCtx.CorrelationID)
}

// ValidateMessageSize checks if a message exceeds size limits
func (eh *ErrorHandler) ValidateMessageSize(ctx context.Context, data []byte, maxSizeKB int) error {
	actualSizeKB := len(data) / 1024
	if actualSizeKB > maxSizeKB {
		return eh.CreateMessageTooLargeError(ctx, maxSizeKB, actualSizeKB)
	}
	return nil
}

// WrapJSONRPCError wraps an error in a JSON-RPC error response
func (eh *ErrorHandler) WrapJSONRPCError(ctx context.Context, err error, requestID any) []byte {
	var httpErr *pkgerrors.HTTPError
	if he, ok := err.(*pkgerrors.HTTPError); ok {
		httpErr = he
	} else {
		errorCtx := pkgerrors.NewErrorContext(ctx)
		httpErr = pkgerrors.NewInternalError(errorCtx.CorrelationID)
	}

	response := httpErr.ToJSONRPCResponse(requestID)
	data, marshalErr := json.Marshal(response)
	if marshalErr != nil {
		eh.logger.Error("Failed to marshal JSON-RPC error response",
			zap.Error(marshalErr),
			zap.String("correlation_id", pkgerrors.NewErrorContext(ctx).CorrelationID),
		)
		// Return a basic error response
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}`)
	}

	return data
}

// GetDegradationStatus returns the current system degradation status
func (eh *ErrorHandler) GetDegradationStatus() map[string]interface{} {
	if eh.degradationManager == nil {
		return map[string]interface{}{
			"mode":              "normal",
			"audit_buffer_size": 0,
			"buffer_overflow":   false,
			"services":          map[string]interface{}{},
		}
	}

	return eh.degradationManager.GetDegradationStatus()
}

// FlushAuditBuffer flushes any buffered audit events
func (eh *ErrorHandler) FlushAuditBuffer() []pkgerrors.AuditEvent {
	if eh.degradationManager == nil {
		return nil
	}

	return eh.degradationManager.FlushAuditBuffer()
}

// IsAuditBuffering returns true if audit events are being buffered
func (eh *ErrorHandler) IsAuditBuffering() bool {
	if eh.degradationManager == nil {
		return false
	}

	return eh.degradationManager.IsAuditBuffering()
}

// SetRetryConfig updates the retry configuration
func (eh *ErrorHandler) SetRetryConfig(config *pkgerrors.RetryConfig) {
	if config != nil {
		eh.retryConfig = config
	}
}

// SetCircuitBreakerConfig updates the circuit breaker configuration
func (eh *ErrorHandler) SetCircuitBreakerConfig(config *pkgerrors.CircuitBreakerConfig) {
	if config != nil {
		eh.circuitConfig = config
	}
}

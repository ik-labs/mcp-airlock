// Package server provides request proxying functionality for MCP messages
package server

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// RequestProxy handles proxying MCP requests between clients and upstream servers
type RequestProxy struct {
	logger     *zap.Logger
	clientPool *ClientPool
	
	// Proxy configuration
	defaultTimeout time.Duration
	maxRetries     int
}

// ProxyRequest represents a request to be proxied
type ProxyRequest struct {
	ID         interface{} `json:"id"`
	Method     string      `json:"method"`
	Params     interface{} `json:"params"`
	Upstream   string      `json:"upstream"`
	Timeout    time.Duration
	RetryCount int
}

// ProxyResponse represents a response from an upstream server
type ProxyResponse struct {
	ID     interface{} `json:"id"`
	Result interface{} `json:"result,omitempty"`
	Error  *ProxyError `json:"error,omitempty"`
}

// ProxyError represents an error from proxying
type ProxyError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// NewRequestProxy creates a new request proxy
func NewRequestProxy(logger *zap.Logger, clientPool *ClientPool) *RequestProxy {
	return &RequestProxy{
		logger:         logger,
		clientPool:     clientPool,
		defaultTimeout: 30 * time.Second,
		maxRetries:     3,
	}
}

// ProxyRequest proxies a request to an upstream server
func (rp *RequestProxy) ProxyRequest(ctx context.Context, req *ProxyRequest) (*ProxyResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	
	if req.Method == "" {
		return rp.createErrorResponse(req.ID, -32600, "Invalid Request: method is required", nil), nil
	}
	
	if req.Upstream == "" {
		return rp.createErrorResponse(req.ID, -32600, "Invalid Request: upstream is required", nil), nil
	}
	
	// Apply timeout
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = rp.defaultTimeout
	}
	
	proxyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	// Add correlation ID for tracing
	correlationID := getCorrelationID(ctx)
	if correlationID == "" {
		correlationID = generateCorrelationID()
		proxyCtx = withCorrelationID(proxyCtx, correlationID)
	}
	
	rp.logger.Info("Proxying request to upstream",
		zap.String("correlation_id", correlationID),
		zap.String("method", req.Method),
		zap.String("upstream", req.Upstream),
		zap.Any("id", req.ID),
	)
	
	// Proxy the request with retries
	result, err := rp.proxyWithRetries(proxyCtx, req)
	if err != nil {
		rp.logger.Error("Failed to proxy request",
			zap.String("correlation_id", correlationID),
			zap.String("method", req.Method),
			zap.String("upstream", req.Upstream),
			zap.Error(err),
		)
		
		return rp.createErrorResponseFromError(req.ID, err), nil
	}
	
	rp.logger.Info("Successfully proxied request",
		zap.String("correlation_id", correlationID),
		zap.String("method", req.Method),
		zap.String("upstream", req.Upstream),
		zap.Any("id", req.ID),
	)
	
	return &ProxyResponse{
		ID:     req.ID,
		Result: result,
	}, nil
}

// proxyWithRetries attempts to proxy a request with retry logic
func (rp *RequestProxy) proxyWithRetries(ctx context.Context, req *ProxyRequest) (interface{}, error) {
	var lastErr error
	maxRetries := req.RetryCount
	if maxRetries <= 0 {
		maxRetries = rp.maxRetries
	}
	
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff with jitter
			backoff := time.Duration(attempt*attempt) * 100 * time.Millisecond
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			
			rp.logger.Info("Retrying request",
				zap.String("method", req.Method),
				zap.String("upstream", req.Upstream),
				zap.Int("attempt", attempt+1),
				zap.Int("max_retries", maxRetries),
			)
		}
		
		result, err := rp.clientPool.ProxyRequest(ctx, req.Upstream, req.Method, req.Params)
		if err == nil {
			if attempt > 0 {
				rp.logger.Info("Request succeeded after retry",
					zap.String("method", req.Method),
					zap.String("upstream", req.Upstream),
					zap.Int("attempts", attempt+1),
				)
			}
			return result, nil
		}
		
		lastErr = err
		
		// Check if error is retryable
		if !rp.isRetryableError(err) {
			rp.logger.Debug("Error is not retryable, stopping",
				zap.String("method", req.Method),
				zap.String("upstream", req.Upstream),
				zap.Error(err),
			)
			break
		}
		
		rp.logger.Warn("Request failed, will retry",
			zap.String("method", req.Method),
			zap.String("upstream", req.Upstream),
			zap.Int("attempt", attempt+1),
			zap.Error(err),
		)
	}
	
	return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries+1, lastErr)
}

// isRetryableError determines if an error is retryable
func (rp *RequestProxy) isRetryableError(err error) bool {
	// For now, consider most errors retryable except for obvious client errors
	// This can be refined based on specific error types from the MCP SDK
	
	errStr := err.Error()
	
	// Don't retry client errors
	if contains(errStr, "invalid") || contains(errStr, "malformed") || contains(errStr, "unauthorized") {
		return false
	}
	
	// Don't retry method not found errors
	if contains(errStr, "method not found") || contains(errStr, "not supported") {
		return false
	}
	
	// Retry connection errors, timeouts, and server errors
	return true
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    (len(s) > len(substr) && 
		     (s[:len(substr)] == substr || 
		      s[len(s)-len(substr):] == substr ||
		      containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// createErrorResponse creates a JSON-RPC error response
func (rp *RequestProxy) createErrorResponse(id interface{}, code int, message string, data interface{}) *ProxyResponse {
	return &ProxyResponse{
		ID: id,
		Error: &ProxyError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// createErrorResponseFromError creates an error response from a Go error
func (rp *RequestProxy) createErrorResponseFromError(id interface{}, err error) *ProxyResponse {
	// Map common errors to JSON-RPC error codes
	code := -32000 // Server error (default)
	message := err.Error()
	
	errStr := err.Error()
	switch {
	case contains(errStr, "timeout") || contains(errStr, "deadline exceeded"):
		code = -32001 // Timeout
		message = "Request timeout"
	case contains(errStr, "not found") || contains(errStr, "not configured"):
		code = -32601 // Method not found
	case contains(errStr, "invalid") || contains(errStr, "malformed"):
		code = -32600 // Invalid request
	case contains(errStr, "unauthorized") || contains(errStr, "forbidden"):
		code = -32002 // Unauthorized
	case contains(errStr, "connection") || contains(errStr, "network"):
		code = -32003 // Connection error
	}
	
	return rp.createErrorResponse(id, code, message, map[string]interface{}{
		"original_error": err.Error(),
		"correlation_id": generateCorrelationID(),
	})
}

// BatchProxyRequest handles multiple requests in a batch
func (rp *RequestProxy) BatchProxyRequest(ctx context.Context, requests []*ProxyRequest) ([]*ProxyResponse, error) {
	if len(requests) == 0 {
		return nil, fmt.Errorf("batch cannot be empty")
	}
	
	responses := make([]*ProxyResponse, len(requests))
	
	// Process requests concurrently
	type result struct {
		index    int
		response *ProxyResponse
		err      error
	}
	
	resultChan := make(chan result, len(requests))
	
	for i, req := range requests {
		go func(index int, request *ProxyRequest) {
			resp, err := rp.ProxyRequest(ctx, request)
			resultChan <- result{
				index:    index,
				response: resp,
				err:      err,
			}
		}(i, req)
	}
	
	// Collect results
	for i := 0; i < len(requests); i++ {
		select {
		case res := <-resultChan:
			if res.err != nil {
				responses[res.index] = rp.createErrorResponseFromError(
					requests[res.index].ID, 
					res.err,
				)
			} else {
				responses[res.index] = res.response
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	
	return responses, nil
}

// GetStats returns proxy statistics
func (rp *RequestProxy) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"default_timeout": rp.defaultTimeout,
		"max_retries":     rp.maxRetries,
		"client_pool":     rp.clientPool.GetPoolStats(),
	}
}

// SetDefaultTimeout sets the default timeout for requests
func (rp *RequestProxy) SetDefaultTimeout(timeout time.Duration) {
	rp.defaultTimeout = timeout
	rp.logger.Info("Updated default timeout",
		zap.Duration("timeout", timeout),
	)
}

// SetMaxRetries sets the maximum number of retries
func (rp *RequestProxy) SetMaxRetries(retries int) {
	rp.maxRetries = retries
	rp.logger.Info("Updated max retries",
		zap.Int("max_retries", retries),
	)
}
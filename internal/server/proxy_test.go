package server

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestRequestProxy_NewRequestProxy(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	proxy := NewRequestProxy(logger, pool)
	
	if proxy == nil {
		t.Fatal("NewRequestProxy returned nil")
	}
	
	if proxy.logger != logger {
		t.Error("Logger not set correctly")
	}
	
	if proxy.clientPool != pool {
		t.Error("Client pool not set correctly")
	}
	
	if proxy.defaultTimeout != 30*time.Second {
		t.Errorf("Expected default timeout 30s, got %v", proxy.defaultTimeout)
	}
	
	if proxy.maxRetries != 3 {
		t.Errorf("Expected max retries 3, got %d", proxy.maxRetries)
	}
}

func TestRequestProxy_ProxyRequest_Validation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	proxy := NewRequestProxy(logger, pool)
	ctx := context.Background()
	
	tests := []struct {
		name        string
		request     *ProxyRequest
		expectError bool
		errorCode   int
	}{
		{
			name:        "nil request",
			request:     nil,
			expectError: true,
		},
		{
			name: "missing method",
			request: &ProxyRequest{
				ID:       "test-1",
				Upstream: "test-upstream",
				Params:   nil,
			},
			expectError: false, // Returns error response, not error
			errorCode:   -32600,
		},
		{
			name: "missing upstream",
			request: &ProxyRequest{
				ID:     "test-2",
				Method: "test_method",
				Params: nil,
			},
			expectError: false, // Returns error response, not error
			errorCode:   -32600,
		},
		{
			name: "valid request",
			request: &ProxyRequest{
				ID:       "test-3",
				Method:   "test_method",
				Upstream: "test-upstream",
				Params:   map[string]interface{}{"key": "value"},
			},
			expectError: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := proxy.ProxyRequest(ctx, tt.request)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			
			if response == nil {
				t.Error("Expected response but got nil")
				return
			}
			
			if tt.errorCode != 0 {
				// Expect error response
				if response.Error == nil {
					t.Error("Expected error response but got none")
				} else if response.Error.Code != tt.errorCode {
					t.Errorf("Expected error code %d, got %d", tt.errorCode, response.Error.Code)
				}
			}
		})
	}
}

func TestRequestProxy_CreateErrorResponse(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	proxy := NewRequestProxy(logger, pool)
	
	id := "test-id"
	code := -32000
	message := "Test error"
	data := map[string]interface{}{"key": "value"}
	
	response := proxy.createErrorResponse(id, code, message, data)
	
	if response == nil {
		t.Fatal("Expected response but got nil")
	}
	
	if response.ID != id {
		t.Errorf("Expected ID %v, got %v", id, response.ID)
	}
	
	if response.Error == nil {
		t.Fatal("Expected error but got nil")
	}
	
	if response.Error.Code != code {
		t.Errorf("Expected error code %d, got %d", code, response.Error.Code)
	}
	
	if response.Error.Message != message {
		t.Errorf("Expected error message %s, got %s", message, response.Error.Message)
	}
	
	// Compare error data by converting to string for comparison
	if fmt.Sprintf("%v", response.Error.Data) != fmt.Sprintf("%v", data) {
		t.Errorf("Expected error data %v, got %v", data, response.Error.Data)
	}
	
	if response.Result != nil {
		t.Error("Expected nil result in error response")
	}
}

func TestRequestProxy_CreateErrorResponseFromError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	proxy := NewRequestProxy(logger, pool)
	
	tests := []struct {
		name         string
		err          error
		expectedCode int
	}{
		{
			name:         "timeout error",
			err:          errors.New("request timeout"),
			expectedCode: -32001,
		},
		{
			name:         "deadline exceeded",
			err:          errors.New("context deadline exceeded"),
			expectedCode: -32001,
		},
		{
			name:         "not found error",
			err:          errors.New("method not found"),
			expectedCode: -32601,
		},
		{
			name:         "invalid error",
			err:          errors.New("invalid request format"),
			expectedCode: -32600,
		},
		{
			name:         "unauthorized error",
			err:          errors.New("unauthorized access"),
			expectedCode: -32002,
		},
		{
			name:         "connection error",
			err:          errors.New("connection failed"),
			expectedCode: -32003,
		},
		{
			name:         "generic error",
			err:          errors.New("something went wrong"),
			expectedCode: -32000,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := "test-id"
			response := proxy.createErrorResponseFromError(id, tt.err)
			
			if response == nil {
				t.Fatal("Expected response but got nil")
			}
			
			if response.ID != id {
				t.Errorf("Expected ID %v, got %v", id, response.ID)
			}
			
			if response.Error == nil {
				t.Fatal("Expected error but got nil")
			}
			
			if response.Error.Code != tt.expectedCode {
				t.Errorf("Expected error code %d, got %d", tt.expectedCode, response.Error.Code)
			}
			
			// Verify error data contains original error
			if response.Error.Data == nil {
				t.Error("Expected error data but got nil")
			} else {
				data, ok := response.Error.Data.(map[string]interface{})
				if !ok {
					t.Error("Expected error data to be map")
				} else {
					if data["original_error"] != tt.err.Error() {
						t.Errorf("Expected original_error %s, got %v", tt.err.Error(), data["original_error"])
					}
				}
			}
		})
	}
}

func TestRequestProxy_IsRetryableError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	proxy := NewRequestProxy(logger, pool)
	
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "connection error",
			err:       errors.New("connection failed"),
			retryable: true,
		},
		{
			name:      "timeout error",
			err:       errors.New("request timeout"),
			retryable: true,
		},
		{
			name:      "server error",
			err:       errors.New("internal server error"),
			retryable: true,
		},
		{
			name:      "invalid request",
			err:       errors.New("invalid request format"),
			retryable: false,
		},
		{
			name:      "malformed data",
			err:       errors.New("malformed JSON"),
			retryable: false,
		},
		{
			name:      "unauthorized",
			err:       errors.New("unauthorized access"),
			retryable: false,
		},
		{
			name:      "method not found",
			err:       errors.New("method not found"),
			retryable: false,
		},
		{
			name:      "not supported",
			err:       errors.New("operation not supported"),
			retryable: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retryable := proxy.isRetryableError(tt.err)
			
			if retryable != tt.retryable {
				t.Errorf("Expected retryable %v, got %v for error: %s", tt.retryable, retryable, tt.err.Error())
			}
		})
	}
}

func TestRequestProxy_BatchProxyRequest(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	proxy := NewRequestProxy(logger, pool)
	ctx := context.Background()
	
	// Test empty batch
	responses, err := proxy.BatchProxyRequest(ctx, []*ProxyRequest{})
	if err == nil {
		t.Error("Expected error for empty batch")
	}
	if responses != nil {
		t.Error("Expected nil responses for empty batch")
	}
	
	// Test batch with multiple requests
	requests := []*ProxyRequest{
		{
			ID:       "batch-1",
			Method:   "test_method_1",
			Upstream: "test-upstream-1",
			Params:   map[string]interface{}{"key": "value1"},
		},
		{
			ID:       "batch-2",
			Method:   "test_method_2",
			Upstream: "test-upstream-2",
			Params:   map[string]interface{}{"key": "value2"},
		},
		{
			ID:     "batch-3", // Missing method - should return error response
			Upstream: "test-upstream-3",
			Params: map[string]interface{}{"key": "value3"},
		},
	}
	
	responses, err = proxy.BatchProxyRequest(ctx, requests)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	if len(responses) != len(requests) {
		t.Errorf("Expected %d responses, got %d", len(requests), len(responses))
	}
	
	// Verify response IDs match request IDs
	for i, response := range responses {
		if response == nil {
			t.Errorf("Response %d is nil", i)
			continue
		}
		
		if response.ID != requests[i].ID {
			t.Errorf("Response %d ID mismatch: expected %v, got %v", i, requests[i].ID, response.ID)
		}
	}
	
	// Third request should have error response due to missing method
	if responses[2].Error == nil {
		t.Error("Expected error response for request with missing method")
	}
}

func TestRequestProxy_GetStats(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	proxy := NewRequestProxy(logger, pool)
	
	stats := proxy.GetStats()
	
	expectedFields := []string{"default_timeout", "max_retries", "client_pool"}
	for _, field := range expectedFields {
		if _, exists := stats[field]; !exists {
			t.Errorf("Expected field %s in stats", field)
		}
	}
	
	if stats["default_timeout"] != proxy.defaultTimeout {
		t.Errorf("Expected default_timeout %v, got %v", proxy.defaultTimeout, stats["default_timeout"])
	}
	
	if stats["max_retries"] != proxy.maxRetries {
		t.Errorf("Expected max_retries %d, got %v", proxy.maxRetries, stats["max_retries"])
	}
}

func TestRequestProxy_SetDefaultTimeout(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	proxy := NewRequestProxy(logger, pool)
	
	newTimeout := 60 * time.Second
	proxy.SetDefaultTimeout(newTimeout)
	
	if proxy.defaultTimeout != newTimeout {
		t.Errorf("Expected default timeout %v, got %v", newTimeout, proxy.defaultTimeout)
	}
}

func TestRequestProxy_SetMaxRetries(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	proxy := NewRequestProxy(logger, pool)
	
	newMaxRetries := 5
	proxy.SetMaxRetries(newMaxRetries)
	
	if proxy.maxRetries != newMaxRetries {
		t.Errorf("Expected max retries %d, got %d", newMaxRetries, proxy.maxRetries)
	}
}

func TestRequestProxy_ProxyRequest_WithTimeout(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	proxy := NewRequestProxy(logger, pool)
	
	// Create a context that will timeout quickly
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	
	request := &ProxyRequest{
		ID:       "timeout-test",
		Method:   "test_method",
		Upstream: "test-upstream",
		Params:   nil,
		Timeout:  5 * time.Second, // Longer than context timeout
	}
	
	// This should timeout due to context
	response, err := proxy.ProxyRequest(ctx, request)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	if response == nil {
		t.Fatal("Expected response but got nil")
	}
	
	// Should get an error response due to timeout or upstream not configured
	if response.Error == nil {
		t.Error("Expected error response due to timeout or missing upstream")
	}
}

func TestRequestProxy_Contains(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substr   string
		expected bool
	}{
		{
			name:     "exact match",
			s:        "timeout",
			substr:   "timeout",
			expected: true,
		},
		{
			name:     "substring at start",
			s:        "timeout error",
			substr:   "timeout",
			expected: true,
		},
		{
			name:     "substring at end",
			s:        "request timeout",
			substr:   "timeout",
			expected: true,
		},
		{
			name:     "substring in middle",
			s:        "connection timeout error",
			substr:   "timeout",
			expected: true,
		},
		{
			name:     "no match",
			s:        "connection error",
			substr:   "timeout",
			expected: false,
		},
		{
			name:     "empty substring",
			s:        "test",
			substr:   "",
			expected: true,
		},
		{
			name:     "empty string",
			s:        "",
			substr:   "test",
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.s, tt.substr)
			if result != tt.expected {
				t.Errorf("contains(%q, %q) = %v, expected %v", tt.s, tt.substr, result, tt.expected)
			}
		})
	}
}
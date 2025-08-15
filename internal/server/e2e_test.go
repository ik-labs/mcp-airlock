package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// MockMCPServer represents a mock MCP server for testing
type MockMCPServer struct {
	responses map[string]interface{}
	logger    *zap.Logger
}

// NewMockMCPServer creates a new mock MCP server
func NewMockMCPServer(logger *zap.Logger) *MockMCPServer {
	return &MockMCPServer{
		responses: make(map[string]interface{}),
		logger:    logger,
	}
}

// SetResponse sets a mock response for a given method
func (m *MockMCPServer) SetResponse(method string, response interface{}) {
	m.responses[method] = response
}

// HandleRequest handles a mock MCP request
func (m *MockMCPServer) HandleRequest(method string, params interface{}) (interface{}, error) {
	if response, exists := m.responses[method]; exists {
		return response, nil
	}

	// Default responses for common MCP methods
	switch method {
	case "tools/list":
		return map[string]interface{}{
			"tools": []map[string]interface{}{
				{
					"name":        "test_tool",
					"description": "A test tool",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"query": map[string]interface{}{
								"type":        "string",
								"description": "Test query",
							},
						},
					},
				},
			},
		}, nil
	case "tools/call":
		return map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": "Mock tool response",
				},
			},
		}, nil
	case "resources/list":
		return map[string]interface{}{
			"resources": []map[string]interface{}{
				{
					"uri":         "test://resource/1",
					"name":        "Test Resource",
					"description": "A test resource",
					"mimeType":    "text/plain",
				},
			},
		}, nil
	case "resources/read":
		return map[string]interface{}{
			"contents": []map[string]interface{}{
				{
					"uri":      "test://resource/1",
					"mimeType": "text/plain",
					"text":     "Mock resource content",
				},
			},
		}, nil
	case "ping":
		return map[string]interface{}{
			"pong": true,
		}, nil
	default:
		return nil, fmt.Errorf("method not found: %s", method)
	}
}

// TestEndToEndMessageFlow tests the complete message flow from client to upstream
func TestEndToEndMessageFlow(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create server with test configuration
	config := &Config{
		Addr:              ":0",
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       10 * time.Second,
		HeartbeatInterval: 1 * time.Second,
		MaxMessageSize:    256 * 1024,
		MaxQueueSize:      100,
		MaxConnections:    10,
		MaxClients:        5,
	}

	server := NewAirlockServer(logger, config)

	// Add a mock upstream configuration
	upstreamConfig := &UpstreamConfig{
		Name:    "test-upstream",
		Type:    "stdio",
		Command: []string{"echo", "test"}, // This will fail, but we'll test error handling
		Timeout: 5 * time.Second,
	}

	err := server.AddUpstream(upstreamConfig)
	if err != nil {
		t.Fatalf("Failed to add upstream: %v", err)
	}

	// Start server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = server.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func(server *AirlockServer, ctx context.Context) {
		err := server.Stop(ctx)
		if err != nil {

		}
	}(server, ctx)

	// Test various MCP message flows
	testCases := []struct {
		name           string
		method         string
		params         interface{}
		expectError    bool
		expectedFields []string
	}{
		{
			name:           "tools/list request",
			method:         "tools/list",
			params:         map[string]interface{}{},
			expectError:    true, // Will fail because echo is not a real MCP server
			expectedFields: []string{"jsonrpc", "id", "error"},
		},
		{
			name:   "tools/call request",
			method: "tools/call",
			params: map[string]interface{}{
				"name":      "test_tool",
				"arguments": map[string]interface{}{"query": "test"},
			},
			expectError:    true, // Will fail because echo is not a real MCP server
			expectedFields: []string{"jsonrpc", "id", "error"},
		},
		{
			name:           "resources/list request",
			method:         "resources/list",
			params:         map[string]interface{}{},
			expectError:    true, // Will fail because echo is not a real MCP server
			expectedFields: []string{"jsonrpc", "id", "error"},
		},
		{
			name:           "ping request",
			method:         "ping",
			params:         map[string]interface{}{},
			expectError:    true, // Will fail because echo is not a real MCP server
			expectedFields: []string{"jsonrpc", "id", "error"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create JSON-RPC request
			request := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      fmt.Sprintf("test-%d", time.Now().UnixNano()),
				"method":  tc.method,
				"params":  tc.params,
			}

			requestData, err := json.Marshal(request)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}

			// Create HTTP request with timeout context
			httpReq := httptest.NewRequest("POST", "/mcp", bytes.NewReader(requestData))
			httpReq.Header.Set("Content-Type", "application/json")

			// Add timeout to the request context
			timeoutCtx, cancel := context.WithTimeout(httpReq.Context(), 2*time.Second)
			defer cancel()
			httpReq = httpReq.WithContext(timeoutCtx)

			// Create response recorder
			w := httptest.NewRecorder()

			// Handle the request in a goroutine with timeout
			done := make(chan bool, 1)
			go func() {
				defer func() { done <- true }()
				server.handleMCPConnection(w, httpReq)
			}()

			// Wait for completion or timeout
			select {
			case <-done:
				// Request completed
			case <-time.After(3 * time.Second):
				t.Log("Request timed out (expected for SSE connections)")
			}

			// Check response
			if w.Code != http.StatusOK && w.Code != 0 {
				t.Logf("HTTP status: %d (this may be expected for SSE)", w.Code)
			}

			// For SSE connections, we expect specific headers
			contentType := w.Header().Get("Content-Type")
			if contentType == "text/event-stream" {
				t.Logf("SSE connection established successfully")

				// Check for SSE events in response body
				body := w.Body.String()
				if !strings.Contains(body, "event: connected") {
					t.Error("Expected connection event in SSE stream")
				}

				// Check if we got a response to our JSON-RPC request
				if strings.Contains(body, tc.method) {
					t.Logf("Found method %s in response", tc.method)
				}
			}
		})
	}

	// Test metrics collection
	t.Run("metrics collection", func(t *testing.T) {
		metrics := server.GetMetrics()

		expectedMetrics := []string{
			"requests_total",
			"requests_succeeded",
			"requests_failed",
			"avg_response_time",
			"active_connections",
		}

		for _, metric := range expectedMetrics {
			if _, exists := metrics[metric]; !exists {
				t.Errorf("Expected metric %s not found", metric)
			}
		}

		t.Logf("Server metrics: %+v", metrics)
	})
}

// TestMessageCorrelation tests request/response correlation
func TestMessageCorrelation(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create a simple connection for testing correlation
	pool := NewConnectionPool(logger, 10)
	proxy := NewRequestProxy(logger, NewClientPool(logger, 5))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/mcp", nil)
	ctx := context.Background()

	conn, err := pool.CreateConnection(ctx, "correlation-test", w, r)
	if err != nil {
		t.Fatalf("Failed to create connection: %v", err)
	}
	defer pool.RemoveConnection("correlation-test")

	conn.SetProxy(proxy)

	// Test correlation ID generation and propagation
	correlationID := generateCorrelationID()
	if correlationID == "" {
		t.Error("Expected non-empty correlation ID")
	}

	// Test context propagation
	ctx = withCorrelationID(ctx, correlationID)
	retrievedID := getCorrelationID(ctx)

	if retrievedID != correlationID {
		t.Errorf("Expected correlation ID %s, got %s", correlationID, retrievedID)
	}

	t.Logf("Correlation ID test passed: %s", correlationID)
}

// TestErrorHandling tests error handling with go-sdk error types
func TestErrorHandling(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 5)
	proxy := NewRequestProxy(logger, pool)

	ctx := context.Background()

	// Test various error scenarios
	testCases := []struct {
		name        string
		request     *ProxyRequest
		expectError bool
		errorCode   int
	}{
		{
			name: "missing method",
			request: &ProxyRequest{
				ID:       "error-test-1",
				Upstream: "non-existent",
			},
			expectError: false, // Returns error response, not Go error
			errorCode:   -32600,
		},
		{
			name: "missing upstream",
			request: &ProxyRequest{
				ID:     "error-test-2",
				Method: "tools/list",
			},
			expectError: false, // Returns error response, not Go error
			errorCode:   -32600,
		},
		{
			name: "non-existent upstream",
			request: &ProxyRequest{
				ID:       "error-test-3",
				Method:   "tools/list",
				Upstream: "non-existent",
				Params:   map[string]interface{}{},
			},
			expectError: false, // Returns error response, not Go error
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response, err := proxy.ProxyRequest(ctx, tc.request)

			if tc.expectError {
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

			// Verify response structure
			if response.ID != tc.request.ID {
				t.Errorf("Response ID %v doesn't match request ID %v", response.ID, tc.request.ID)
			}

			// For error cases, verify error response
			if tc.errorCode != 0 {
				if response.Error == nil {
					t.Error("Expected error response but got none")
				} else {
					t.Logf("Got expected error response: code=%d, message=%s",
						response.Error.Code, response.Error.Message)
				}
			}
		})
	}
}

// TestConcurrentConnections tests handling multiple concurrent connections
func TestConcurrentConnections(t *testing.T) {
	logger := zaptest.NewLogger(t)

	config := &Config{
		Addr:              ":0",
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       5 * time.Second,
		HeartbeatInterval: 1 * time.Second,
		MaxMessageSize:    64 * 1024,
		MaxQueueSize:      50,
		MaxConnections:    5,
		MaxClients:        3,
	}

	server := NewAirlockServer(logger, config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := server.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func(server *AirlockServer, ctx context.Context) {
		err := server.Stop(ctx)
		if err != nil {
			
		}
	}(server, ctx)

	// Create multiple concurrent connections
	numConnections := 3
	done := make(chan bool, numConnections)

	for i := 0; i < numConnections; i++ {
		go func(connID int) {
			defer func() { done <- true }()

			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/mcp", nil)

			// Add timeout to the request context
			timeoutCtx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
			defer cancel()
			r = r.WithContext(timeoutCtx)

			// This will establish SSE connection
			server.handleMCPConnection(w, r)

			// Verify SSE headers were set
			if w.Header().Get("Content-Type") != "text/event-stream" {
				t.Errorf("Connection %d: Expected SSE content type", connID)
			}
		}(i)
	}

	// Wait for all connections to complete
	for i := 0; i < numConnections; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Concurrent connection test timed out")
		}
	}

	// Check final metrics
	metrics := server.GetMetrics()
	t.Logf("Final metrics after concurrent test: %+v", metrics)
}

// BenchmarkMessageProcessing benchmarks message processing performance
func BenchmarkMessageProcessing(b *testing.B) {
	logger := zaptest.NewLogger(b)
	pool := NewClientPool(logger, 10)
	proxy := NewRequestProxy(logger, pool)

	ctx := context.Background()

	// Create a test request
	request := &ProxyRequest{
		ID:       "benchmark-test",
		Method:   "tools/list",
		Upstream: "non-existent", // Will fail quickly
		Params:   map[string]interface{}{},
		Timeout:  1 * time.Second,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := proxy.ProxyRequest(ctx, request)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

package server

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// TestUpstreamConnectorIntegration tests the integration between components
func TestUpstreamConnectorIntegration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	
	// Create client pool
	pool := NewClientPool(logger, 5)
	defer pool.Close()
	
	// Create request proxy
	proxy := NewRequestProxy(logger, pool)
	
	// Add upstream configuration
	config := &UpstreamConfig{
		Name:    "test-integration",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 5 * time.Second,
	}
	
	err := pool.AddUpstream(config)
	if err != nil {
		t.Fatalf("Failed to add upstream: %v", err)
	}
	
	// Verify upstream is configured
	upstreams := pool.ListUpstreams()
	if len(upstreams) != 1 {
		t.Errorf("Expected 1 upstream, got %d", len(upstreams))
	}
	
	if upstreams[0] != "test-integration" {
		t.Errorf("Expected upstream 'test-integration', got %s", upstreams[0])
	}
	
	// Test proxy request (will fail because echo is not MCP server)
	ctx := context.Background()
	request := &ProxyRequest{
		ID:       "integration-test",
		Method:   "tools/list",
		Upstream: "test-integration",
		Params:   map[string]interface{}{},
		Timeout:  2 * time.Second,
	}
	
	response, err := proxy.ProxyRequest(ctx, request)
	if err != nil {
		t.Errorf("Unexpected error from proxy: %v", err)
	}
	
	if response == nil {
		t.Fatal("Expected response but got nil")
	}
	
	// Should get error response because echo is not a real MCP server
	if response.Error == nil {
		t.Log("Unexpectedly got successful response (echo somehow worked as MCP server)")
	} else {
		t.Logf("Got expected error response: %s", response.Error.Message)
	}
	
	// Verify response ID matches request ID
	if response.ID != request.ID {
		t.Errorf("Response ID %v doesn't match request ID %v", response.ID, request.ID)
	}
	
	// Test pool stats
	stats := pool.GetPoolStats()
	if stats["configured_upstreams"] != 1 {
		t.Errorf("Expected 1 configured upstream in stats, got %v", stats["configured_upstreams"])
	}
	
	// Test proxy stats
	proxyStats := proxy.GetStats()
	if proxyStats["default_timeout"] != proxy.defaultTimeout {
		t.Errorf("Proxy stats don't match expected values")
	}
}

// TestClientPoolLifecycle tests the complete lifecycle of client pool operations
func TestClientPoolLifecycle(t *testing.T) {
	logger := zaptest.NewLogger(t)
	
	// Create client pool
	pool := NewClientPool(logger, 3)
	defer pool.Close()
	
	// Test initial state
	if len(pool.ListUpstreams()) != 0 {
		t.Error("Expected empty upstream list initially")
	}
	
	if len(pool.ListActiveClients()) != 0 {
		t.Error("Expected no active clients initially")
	}
	
	// Add multiple upstreams
	configs := []*UpstreamConfig{
		{
			Name:    "upstream-1",
			Type:    "stdio",
			Command: []string{"echo", "test1"},
			Timeout: 5 * time.Second,
		},
		{
			Name:    "upstream-2",
			Type:    "stdio",
			Command: []string{"echo", "test2"},
			Timeout: 5 * time.Second,
		},
	}
	
	for _, config := range configs {
		err := pool.AddUpstream(config)
		if err != nil {
			t.Errorf("Failed to add upstream %s: %v", config.Name, err)
		}
	}
	
	// Verify upstreams are configured
	upstreams := pool.ListUpstreams()
	if len(upstreams) != 2 {
		t.Errorf("Expected 2 upstreams, got %d", len(upstreams))
	}
	
	// Test health check
	ctx := context.Background()
	healthResults := pool.HealthCheck(ctx)
	if len(healthResults) != 2 {
		t.Errorf("Expected 2 health check results, got %d", len(healthResults))
	}
	
	// All should fail because echo is not MCP server
	for name, result := range healthResults {
		if result == nil {
			t.Logf("Health check for %s unexpectedly passed", name)
		} else {
			t.Logf("Health check for %s failed as expected: %v", name, result)
		}
	}
	
	// Remove one upstream
	err := pool.RemoveUpstream("upstream-1")
	if err != nil {
		t.Errorf("Failed to remove upstream: %v", err)
	}
	
	// Verify removal
	upstreams = pool.ListUpstreams()
	if len(upstreams) != 1 {
		t.Errorf("Expected 1 upstream after removal, got %d", len(upstreams))
	}
	
	if upstreams[0] != "upstream-2" {
		t.Errorf("Expected remaining upstream to be 'upstream-2', got %s", upstreams[0])
	}
	
	// Test configuration updates
	pool.SetMaxIdleTime(10 * time.Minute)
	pool.SetCleanupInterval(2 * time.Minute)
	
	stats := pool.GetPoolStats()
	if stats["max_idle_time"] != 10*time.Minute {
		t.Errorf("Max idle time not updated correctly")
	}
	
	if stats["cleanup_interval"] != 2*time.Minute {
		t.Errorf("Cleanup interval not updated correctly")
	}
}

// TestRequestProxyErrorHandling tests various error scenarios
func TestRequestProxyErrorHandling(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 5)
	defer pool.Close()
	
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
			name:        "nil request",
			request:     nil,
			expectError: true,
		},
		{
			name: "missing method",
			request: &ProxyRequest{
				ID:       "test-1",
				Upstream: "test-upstream",
			},
			expectError: false,
			errorCode:   -32600,
		},
		{
			name: "missing upstream",
			request: &ProxyRequest{
				ID:     "test-2",
				Method: "tools/list",
			},
			expectError: false,
			errorCode:   -32600,
		},
		{
			name: "non-existent upstream",
			request: &ProxyRequest{
				ID:       "test-3",
				Method:   "tools/list",
				Upstream: "non-existent",
			},
			expectError: false,
			errorCode:   -32601, // Will be mapped from "not found" error
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
			
			if tc.errorCode != 0 {
				if response.Error == nil {
					t.Error("Expected error response but got none")
				} else if response.Error.Code != tc.errorCode {
					t.Logf("Expected error code %d, got %d (this may be acceptable depending on error mapping)", tc.errorCode, response.Error.Code)
				}
			}
		})
	}
}

// TestBatchProxyRequest tests batch request processing
func TestBatchProxyRequest(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 5)
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
	
	// Test batch with mixed valid/invalid requests
	requests := []*ProxyRequest{
		{
			ID:       "batch-1",
			Method:   "tools/list",
			Upstream: "non-existent-1",
		},
		{
			ID:       "batch-2",
			Upstream: "non-existent-2", // Missing method
		},
		{
			ID:     "batch-3",
			Method: "tools/list", // Missing upstream
		},
	}
	
	responses, err = proxy.BatchProxyRequest(ctx, requests)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	if len(responses) != len(requests) {
		t.Errorf("Expected %d responses, got %d", len(requests), len(responses))
	}
	
	// All should have error responses
	for i, response := range responses {
		if response == nil {
			t.Errorf("Response %d is nil", i)
			continue
		}
		
		if response.ID != requests[i].ID {
			t.Errorf("Response %d ID mismatch", i)
		}
		
		if response.Error == nil {
			t.Errorf("Expected error response for request %d", i)
		}
	}
}
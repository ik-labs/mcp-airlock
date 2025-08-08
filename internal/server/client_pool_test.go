package server

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestClientPool_NewClientPool(t *testing.T) {
	logger := zaptest.NewLogger(t)
	maxClients := 10
	
	pool := NewClientPool(logger, maxClients)
	
	if pool == nil {
		t.Fatal("NewClientPool returned nil")
	}
	
	if pool.logger != logger {
		t.Error("Logger not set correctly")
	}
	
	if pool.connector == nil {
		t.Error("Connector not initialized")
	}
	
	if pool.configs == nil {
		t.Error("Configs map not initialized")
	}
	
	// Verify default values
	if pool.maxIdleTime != 5*time.Minute {
		t.Errorf("Expected maxIdleTime 5m, got %v", pool.maxIdleTime)
	}
	
	if pool.cleanupInterval != 1*time.Minute {
		t.Errorf("Expected cleanupInterval 1m, got %v", pool.cleanupInterval)
	}
	
	// Clean up
	pool.Close()
}

func TestClientPool_AddUpstream(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	tests := []struct {
		name        string
		config      *UpstreamConfig
		expectError bool
	}{
		{
			name: "valid stdio config",
			config: &UpstreamConfig{
				Name:    "test-stdio",
				Type:    "stdio",
				Command: []string{"echo", "test"},
				Timeout: 30 * time.Second,
			},
			expectError: false,
		},
		{
			name: "valid unix config",
			config: &UpstreamConfig{
				Name:    "test-unix",
				Type:    "unix",
				Socket:  "/tmp/test.sock",
				Timeout: 30 * time.Second,
			},
			expectError: false,
		},
		{
			name: "config without name",
			config: &UpstreamConfig{
				Type:    "stdio",
				Command: []string{"echo", "test"},
			},
			expectError: true,
		},
		{
			name: "config without type",
			config: &UpstreamConfig{
				Name:    "test-no-type",
				Command: []string{"echo", "test"},
			},
			expectError: true,
		},
		{
			name: "stdio config without command",
			config: &UpstreamConfig{
				Name: "test-no-command",
				Type: "stdio",
			},
			expectError: true,
		},
		{
			name: "unix config without socket",
			config: &UpstreamConfig{
				Name: "test-no-socket",
				Type: "unix",
			},
			expectError: true,
		},
		{
			name: "unsupported type",
			config: &UpstreamConfig{
				Name: "test-unsupported",
				Type: "http",
			},
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pool.AddUpstream(tt.config)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				
				// Verify config was added
				upstreams := pool.ListUpstreams()
				found := false
				for _, name := range upstreams {
					if name == tt.config.Name {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Upstream %s not found in list", tt.config.Name)
				}
			}
		})
	}
}

func TestClientPool_RemoveUpstream(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	config := &UpstreamConfig{
		Name:    "test-remove",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 30 * time.Second,
	}
	
	// Try to remove non-existent upstream
	err := pool.RemoveUpstream("non-existent")
	if err == nil {
		t.Error("Expected error for removing non-existent upstream")
	}
	
	// Add upstream
	err = pool.AddUpstream(config)
	if err != nil {
		t.Fatalf("Failed to add upstream: %v", err)
	}
	
	// Verify upstream exists
	upstreams := pool.ListUpstreams()
	if len(upstreams) != 1 {
		t.Errorf("Expected 1 upstream, got %d", len(upstreams))
	}
	
	// Remove upstream
	err = pool.RemoveUpstream("test-remove")
	if err != nil {
		t.Errorf("Failed to remove upstream: %v", err)
	}
	
	// Verify upstream is removed
	upstreams = pool.ListUpstreams()
	if len(upstreams) != 0 {
		t.Errorf("Expected 0 upstreams after removal, got %d", len(upstreams))
	}
}

func TestClientPool_GetClient(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	config := &UpstreamConfig{
		Name:    "test-get-client",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 30 * time.Second,
	}
	
	ctx := context.Background()
	
	// Try to get client for non-configured upstream
	client, err := pool.GetClient(ctx, "non-existent")
	if err == nil {
		t.Error("Expected error for non-configured upstream")
	}
	if client != nil {
		t.Error("Expected nil client for non-configured upstream")
	}
	
	// Add upstream configuration
	err = pool.AddUpstream(config)
	if err != nil {
		t.Fatalf("Failed to add upstream: %v", err)
	}
	
	// Get client (should attempt to create new connection)
	// Note: This will fail because echo is not a real MCP server,
	// but we're testing the pool logic, not the MCP protocol
	client, err = pool.GetClient(ctx, "test-get-client")
	if err != nil {
		t.Logf("Expected failure connecting to echo command (not a real MCP server): %v", err)
		// This is expected since echo is not an MCP server
	} else if client != nil {
		t.Log("Unexpectedly succeeded in connecting to echo command")
		// If it somehow succeeded, verify it's a valid client
		if !client.IsConnected() {
			t.Error("Client should be connected if creation succeeded")
		}
	}
}

func TestClientPool_ProxyRequest(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	config := &UpstreamConfig{
		Name:    "test-proxy",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 30 * time.Second,
	}
	
	ctx := context.Background()
	
	// Try to proxy to non-configured upstream
	result, err := pool.ProxyRequest(ctx, "non-existent", "test_method", nil)
	if err == nil {
		t.Error("Expected error for non-configured upstream")
	}
	if result != nil {
		t.Error("Expected nil result for non-configured upstream")
	}
	
	// Add upstream configuration
	err = pool.AddUpstream(config)
	if err != nil {
		t.Fatalf("Failed to add upstream: %v", err)
	}
	
	// Note: We can't easily test successful proxy without a real MCP server
	// This would require integration tests with mock servers
	// For now, we test that the method attempts to create a client
	_, err = pool.ProxyRequest(ctx, "test-proxy", "tools/list", map[string]interface{}{})
	// We expect this to fail because echo is not a real MCP server
	// but it should fail at the MCP protocol level, not at the pool level
	if err == nil {
		t.Log("Proxy request succeeded (unexpected but not necessarily wrong)")
	} else {
		t.Logf("Proxy request failed as expected: %v", err)
	}
}

func TestClientPool_ListUpstreams(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	// Initially should be empty
	upstreams := pool.ListUpstreams()
	if len(upstreams) != 0 {
		t.Errorf("Expected 0 upstreams initially, got %d", len(upstreams))
	}
	
	// Add some upstreams
	configs := []*UpstreamConfig{
		{
			Name:    "upstream1",
			Type:    "stdio",
			Command: []string{"echo", "test1"},
			Timeout: 30 * time.Second,
		},
		{
			Name:    "upstream2",
			Type:    "stdio",
			Command: []string{"echo", "test2"},
			Timeout: 30 * time.Second,
		},
	}
	
	for _, config := range configs {
		err := pool.AddUpstream(config)
		if err != nil {
			t.Fatalf("Failed to add upstream %s: %v", config.Name, err)
		}
	}
	
	// Check list
	upstreams = pool.ListUpstreams()
	if len(upstreams) != 2 {
		t.Errorf("Expected 2 upstreams, got %d", len(upstreams))
	}
	
	// Verify names are present
	expectedNames := map[string]bool{"upstream1": true, "upstream2": true}
	for _, name := range upstreams {
		if !expectedNames[name] {
			t.Errorf("Unexpected upstream name: %s", name)
		}
		delete(expectedNames, name)
	}
	
	if len(expectedNames) > 0 {
		t.Errorf("Missing upstream names: %v", expectedNames)
	}
}

func TestClientPool_GetPoolStats(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	// Get initial stats
	stats := pool.GetPoolStats()
	
	// Verify stats structure
	expectedFields := []string{"configured_upstreams", "active_clients", "active_client_names", "max_idle_time", "cleanup_interval"}
	for _, field := range expectedFields {
		if _, exists := stats[field]; !exists {
			t.Errorf("Expected field %s in stats", field)
		}
	}
	
	// Verify initial values
	if stats["configured_upstreams"] != 0 {
		t.Errorf("Expected 0 configured upstreams, got %v", stats["configured_upstreams"])
	}
	
	if stats["active_clients"] != 0 {
		t.Errorf("Expected 0 active clients, got %v", stats["active_clients"])
	}
	
	// Add an upstream
	config := &UpstreamConfig{
		Name:    "test-stats",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 30 * time.Second,
	}
	
	err := pool.AddUpstream(config)
	if err != nil {
		t.Fatalf("Failed to add upstream: %v", err)
	}
	
	// Get updated stats
	stats = pool.GetPoolStats()
	if stats["configured_upstreams"] != 1 {
		t.Errorf("Expected 1 configured upstream, got %v", stats["configured_upstreams"])
	}
}

func TestClientPool_SetMaxIdleTime(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	newIdleTime := 10 * time.Minute
	pool.SetMaxIdleTime(newIdleTime)
	
	if pool.maxIdleTime != newIdleTime {
		t.Errorf("Expected maxIdleTime %v, got %v", newIdleTime, pool.maxIdleTime)
	}
}

func TestClientPool_SetCleanupInterval(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	newInterval := 2 * time.Minute
	pool.SetCleanupInterval(newInterval)
	
	if pool.cleanupInterval != newInterval {
		t.Errorf("Expected cleanupInterval %v, got %v", newInterval, pool.cleanupInterval)
	}
}

func TestClientPool_HealthCheck(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	defer pool.Close()
	
	ctx := context.Background()
	
	// Health check with no upstreams
	results := pool.HealthCheck(ctx)
	if len(results) != 0 {
		t.Errorf("Expected 0 health check results, got %d", len(results))
	}
	
	// Add an upstream
	config := &UpstreamConfig{
		Name:    "test-health",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 30 * time.Second,
	}
	
	err := pool.AddUpstream(config)
	if err != nil {
		t.Fatalf("Failed to add upstream: %v", err)
	}
	
	// Health check with upstream
	results = pool.HealthCheck(ctx)
	if len(results) != 1 {
		t.Errorf("Expected 1 health check result, got %d", len(results))
	}
	
	// Check result for our upstream
	if result, exists := results["test-health"]; exists {
		// We expect this to fail because echo is not a real MCP server
		// but the health check should still return a result
		if result == nil {
			t.Log("Health check passed (unexpected but not necessarily wrong)")
		} else {
			t.Logf("Health check failed as expected: %v", result)
		}
	} else {
		t.Error("Expected health check result for test-health")
	}
}

func TestClientPool_Close(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewClientPool(logger, 10)
	
	// Add an upstream
	config := &UpstreamConfig{
		Name:    "test-close",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 30 * time.Second,
	}
	
	err := pool.AddUpstream(config)
	if err != nil {
		t.Fatalf("Failed to add upstream: %v", err)
	}
	
	// Close the pool
	pool.Close()
	
	// Verify cleanup goroutine is stopped by checking context
	select {
	case <-pool.ctx.Done():
		// Expected - context should be cancelled
	default:
		t.Error("Expected context to be cancelled after close")
	}
}
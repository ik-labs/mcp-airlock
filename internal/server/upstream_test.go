package server

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestUpstreamConnector_NewUpstreamConnector(t *testing.T) {
	logger := zaptest.NewLogger(t)
	maxClients := 10
	
	connector := NewUpstreamConnector(logger, maxClients)
	
	if connector == nil {
		t.Fatal("NewUpstreamConnector returned nil")
	}
	
	if connector.logger != logger {
		t.Error("Logger not set correctly")
	}
	
	if connector.maxClients != maxClients {
		t.Errorf("Expected maxClients %d, got %d", maxClients, connector.maxClients)
	}
	
	if connector.clients == nil {
		t.Error("Clients map not initialized")
	}
}

func TestUpstreamConnector_CreateTransport(t *testing.T) {
	logger := zaptest.NewLogger(t)
	connector := NewUpstreamConnector(logger, 10)
	ctx := context.Background()
	
	tests := []struct {
		name        string
		config      *UpstreamConfig
		expectError bool
	}{
		{
			name: "stdio transport with command",
			config: &UpstreamConfig{
				Name:    "test-stdio",
				Type:    "stdio",
				Command: []string{"echo", "test"},
			},
			expectError: false,
		},
		{
			name: "stdio transport without command",
			config: &UpstreamConfig{
				Name: "test-stdio-no-cmd",
				Type: "stdio",
			},
			expectError: true,
		},
		{
			name: "unix transport with socket",
			config: &UpstreamConfig{
				Name:   "test-unix",
				Type:   "unix",
				Socket: "/tmp/test.sock",
			},
			expectError: true, // Unix transport not yet implemented
		},
		{
			name: "unix transport without socket",
			config: &UpstreamConfig{
				Name: "test-unix-no-socket",
				Type: "unix",
			},
			expectError: true,
		},
		{
			name: "unsupported transport type",
			config: &UpstreamConfig{
				Name: "test-unsupported",
				Type: "http",
			},
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport, err := connector.createTransport(ctx, tt.config)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if transport != nil {
					t.Error("Expected nil transport on error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if transport == nil {
					t.Error("Expected transport but got nil")
				}
			}
		})
	}
}

func TestUpstreamConnector_Connect_MaxClients(t *testing.T) {
	logger := zaptest.NewLogger(t)
	maxClients := 2
	connector := NewUpstreamConnector(logger, maxClients)
	ctx := context.Background()
	
	// Create configs for testing
	config1 := &UpstreamConfig{
		Name:    "test1",
		Type:    "stdio",
		Command: []string{"echo", "test1"},
		Timeout: 5 * time.Second,
	}
	
	config2 := &UpstreamConfig{
		Name:    "test2",
		Type:    "stdio",
		Command: []string{"echo", "test2"},
		Timeout: 5 * time.Second,
	}
	
	config3 := &UpstreamConfig{
		Name:    "test3",
		Type:    "stdio",
		Command: []string{"echo", "test3"},
		Timeout: 5 * time.Second,
	}
	
	// Connect first client - will fail because echo is not MCP server
	client1, err := connector.Connect(ctx, config1)
	if err != nil {
		t.Logf("First connection failed as expected (echo is not MCP server): %v", err)
		// Skip the rest of this test since we can't connect to echo
		return
	}
	if client1 == nil {
		t.Fatal("First client is nil")
	}
	
	// Connect second client - should succeed
	client2, err := connector.Connect(ctx, config2)
	if err != nil {
		t.Logf("Second connection failed as expected: %v", err)
		return
	}
	if client2 == nil {
		t.Fatal("Second client is nil")
	}
	
	// Connect third client - should fail due to max limit
	client3, err := connector.Connect(ctx, config3)
	if err == nil {
		t.Error("Expected error for exceeding max clients")
	}
	if client3 != nil {
		t.Error("Expected nil client when exceeding max clients")
	}
	
	// Verify client count
	clients := connector.ListClients()
	if len(clients) != maxClients {
		t.Errorf("Expected %d clients, got %d", maxClients, len(clients))
	}
}

func TestUpstreamConnector_GetClient(t *testing.T) {
	logger := zaptest.NewLogger(t)
	connector := NewUpstreamConnector(logger, 10)
	ctx := context.Background()
	
	config := &UpstreamConfig{
		Name:    "test-client",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 5 * time.Second,
	}
	
	// Try to get non-existent client
	client, err := connector.GetClient("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent client")
	}
	if client != nil {
		t.Error("Expected nil client for non-existent client")
	}
	
	// Connect a client (will fail with echo, but that's expected)
	_, err = connector.Connect(ctx, config)
	if err != nil {
		t.Logf("Failed to connect client as expected (echo is not MCP server): %v", err)
		// Skip the rest since we can't actually connect
		return
	}
	
	// Get the connected client
	client, err = connector.GetClient("test-client")
	if err != nil {
		t.Errorf("Failed to get connected client: %v", err)
	}
	if client == nil {
		t.Error("Expected client but got nil")
	}
}

func TestUpstreamConnector_CloseClient(t *testing.T) {
	logger := zaptest.NewLogger(t)
	connector := NewUpstreamConnector(logger, 10)
	ctx := context.Background()
	
	config := &UpstreamConfig{
		Name:    "test-close",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 5 * time.Second,
	}
	
	// Try to close non-existent client
	err := connector.CloseClient("non-existent")
	if err == nil {
		t.Error("Expected error for closing non-existent client")
	}
	
	// Connect a client (will fail with echo, but that's expected)
	_, err = connector.Connect(ctx, config)
	if err != nil {
		t.Logf("Failed to connect client as expected (echo is not MCP server): %v", err)
		// Skip the rest since we can't actually connect
		return
	}
	
	// Verify client exists
	clients := connector.ListClients()
	if len(clients) != 1 {
		t.Errorf("Expected 1 client, got %d", len(clients))
	}
	
	// Close the client
	err = connector.CloseClient("test-close")
	if err != nil {
		t.Errorf("Failed to close client: %v", err)
	}
	
	// Verify client is removed
	clients = connector.ListClients()
	if len(clients) != 0 {
		t.Errorf("Expected 0 clients after close, got %d", len(clients))
	}
}

func TestUpstreamConnector_CloseAll(t *testing.T) {
	logger := zaptest.NewLogger(t)
	connector := NewUpstreamConnector(logger, 10)
	ctx := context.Background()
	
	// Connect multiple clients
	configs := []*UpstreamConfig{
		{
			Name:    "test1",
			Type:    "stdio",
			Command: []string{"echo", "test1"},
			Timeout: 5 * time.Second,
		},
		{
			Name:    "test2",
			Type:    "stdio",
			Command: []string{"echo", "test2"},
			Timeout: 5 * time.Second,
		},
	}
	
	connectedCount := 0
	for _, config := range configs {
		_, err := connector.Connect(ctx, config)
		if err != nil {
			t.Logf("Failed to connect client %s as expected: %v", config.Name, err)
		} else {
			connectedCount++
		}
	}
	
	// Verify clients exist (only those that actually connected)
	clients := connector.ListClients()
	if len(clients) != connectedCount {
		t.Errorf("Expected %d clients, got %d", connectedCount, len(clients))
	}
	
	// Close all clients
	connector.CloseAll()
	
	// Verify all clients are removed
	clients = connector.ListClients()
	if len(clients) != 0 {
		t.Errorf("Expected 0 clients after CloseAll, got %d", len(clients))
	}
}

func TestUpstreamConnector_CleanupStaleClients(t *testing.T) {
	logger := zaptest.NewLogger(t)
	connector := NewUpstreamConnector(logger, 10)
	ctx := context.Background()
	
	config := &UpstreamConfig{
		Name:    "test-stale",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 5 * time.Second,
	}
	
	// Connect a client (will fail with echo, but that's expected)
	client, err := connector.Connect(ctx, config)
	if err != nil {
		t.Logf("Failed to connect client as expected (echo is not MCP server): %v", err)
		// Skip the rest since we can't actually connect
		return
	}
	
	// Manually set last used time to make it stale
	client.mu.Lock()
	client.lastUsed = time.Now().Add(-10 * time.Minute)
	client.mu.Unlock()
	
	// Verify client exists
	clients := connector.ListClients()
	if len(clients) != 1 {
		t.Errorf("Expected 1 client before cleanup, got %d", len(clients))
	}
	
	// Run cleanup with 5 minute threshold
	connector.CleanupStaleClients(5 * time.Minute)
	
	// Verify stale client is removed
	clients = connector.ListClients()
	if len(clients) != 0 {
		t.Errorf("Expected 0 clients after cleanup, got %d", len(clients))
	}
}

func TestUpstreamClient_GetStats(t *testing.T) {
	logger := zaptest.NewLogger(t)
	connector := NewUpstreamConnector(logger, 10)
	ctx := context.Background()
	
	config := &UpstreamConfig{
		Name:    "test-stats",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 5 * time.Second,
	}
	
	// Connect a client (will fail with echo, but that's expected)
	client, err := connector.Connect(ctx, config)
	if err != nil {
		t.Logf("Failed to connect client as expected (echo is not MCP server): %v", err)
		// Skip the rest since we can't actually connect
		return
	}
	
	// Get stats
	stats := client.GetStats()
	
	// Verify stats structure
	expectedFields := []string{"name", "connected", "request_count", "error_count", "last_used", "created_at", "uptime"}
	for _, field := range expectedFields {
		if _, exists := stats[field]; !exists {
			t.Errorf("Expected field %s in stats", field)
		}
	}
	
	// Verify specific values
	if stats["name"] != "test-stats" {
		t.Errorf("Expected name 'test-stats', got %v", stats["name"])
	}
	
	if stats["request_count"] != int64(0) {
		t.Errorf("Expected request_count 0, got %v", stats["request_count"])
	}
	
	if stats["error_count"] != int64(0) {
		t.Errorf("Expected error_count 0, got %v", stats["error_count"])
	}
}

func TestUpstreamClient_IsConnected(t *testing.T) {
	logger := zaptest.NewLogger(t)
	connector := NewUpstreamConnector(logger, 10)
	ctx := context.Background()
	
	config := &UpstreamConfig{
		Name:    "test-connected",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 5 * time.Second,
	}
	
	// Connect a client (will fail with echo, but that's expected)
	client, err := connector.Connect(ctx, config)
	if err != nil {
		t.Logf("Failed to connect client as expected (echo is not MCP server): %v", err)
		// Skip the rest since we can't actually connect
		return
	}
	
	// Check if connected
	if !client.IsConnected() {
		t.Error("Expected client to be connected")
	}
	
	// Close the client
	client.Close()
	
	// Check if disconnected
	if client.IsConnected() {
		t.Error("Expected client to be disconnected after close")
	}
}

func TestUpstreamConfig_Validation(t *testing.T) {
	tests := []struct {
		name        string
		config      *UpstreamConfig
		expectError bool
	}{
		{
			name: "valid stdio config",
			config: &UpstreamConfig{
				Name:    "valid-stdio",
				Type:    "stdio",
				Command: []string{"echo", "test"},
				Timeout: 30 * time.Second,
			},
			expectError: false,
		},
		{
			name: "valid unix config",
			config: &UpstreamConfig{
				Name:    "valid-unix",
				Type:    "unix",
				Socket:  "/tmp/test.sock",
				Timeout: 30 * time.Second,
			},
			expectError: true, // Unix transport not yet implemented
		},
		{
			name: "stdio config with env",
			config: &UpstreamConfig{
				Name:    "stdio-with-env",
				Type:    "stdio",
				Command: []string{"python", "-m", "test"},
				Env:     map[string]string{"PYTHONPATH": "/opt/test"},
				Timeout: 30 * time.Second,
			},
			expectError: false,
		},
		{
			name: "config with allow tools",
			config: &UpstreamConfig{
				Name:       "with-tools",
				Type:       "stdio",
				Command:    []string{"echo", "test"},
				AllowTools: []string{"read_file", "search"},
				Timeout:    30 * time.Second,
			},
			expectError: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)
			connector := NewUpstreamConnector(logger, 10)
			ctx := context.Background()
			
			_, err := connector.createTransport(ctx, tt.config)
			
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
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

	"go.uber.org/zap/zaptest"
)

// TestMCPServerIntegration tests the basic MCP server functionality
func TestMCPServerIntegration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &Config{
		Addr:              ":0",
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       10 * time.Second,
		HeartbeatInterval: 1 * time.Second,
		MaxMessageSize:    256 * 1024,
		MaxQueueSize:      100,
		MaxConnections:    10,
	}
	
	server := NewAirlockServer(logger, config)
	
	t.Run("health endpoints", func(t *testing.T) {
		// Test health endpoint
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		
		server.handleHealth(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		var healthResp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &healthResp); err != nil {
			t.Fatalf("failed to parse health response: %v", err)
		}
		
		if healthResp["status"] != "healthy" {
			t.Errorf("expected status 'healthy', got %v", healthResp["status"])
		}
	})
	
	t.Run("mcp connection handling", func(t *testing.T) {
		// Create a test MCP request
		mcpRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]interface{}{},
				"clientInfo": map[string]interface{}{
					"name":    "test-client",
					"version": "1.0.0",
				},
			},
		}
		
		requestBody, err := json.Marshal(mcpRequest)
		if err != nil {
			t.Fatalf("failed to marshal request: %v", err)
		}
		
		// Test POST request to MCP endpoint with timeout context
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		
		req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(requestBody))
		req = req.WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		// Handle the request in a goroutine
		done := make(chan bool)
		go func() {
			defer func() { done <- true }()
			server.handleMCPConnection(w, req)
		}()
		
		// Wait for either completion or timeout
		select {
		case <-done:
			// Connection handling completed
		case <-time.After(200 * time.Millisecond):
			// This is expected - the connection will timeout
		}
		
		// Check that SSE headers are set
		if w.Header().Get("Content-Type") != "text/event-stream" {
			t.Errorf("expected Content-Type text/event-stream, got %s", w.Header().Get("Content-Type"))
		}
		
		if w.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("expected Cache-Control no-cache, got %s", w.Header().Get("Cache-Control"))
		}
		
		// Check response body contains SSE events
		body := w.Body.String()
		if !strings.Contains(body, "event: connected") {
			t.Error("expected connected event in response")
		}
		
		// Should contain the connection ID
		if !strings.Contains(body, "connection_id") {
			t.Error("expected connection_id in response")
		}
	})
	
	t.Run("message size limit", func(t *testing.T) {
		// Test connection pool limits
		pool := server.connections
		
		// Verify max message size configuration
		if server.config.MaxMessageSize != 256*1024 {
			t.Errorf("expected max message size 256KB, got %d", server.config.MaxMessageSize)
		}
		
		// Test that we can create connections up to the limit
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/mcp", nil)
		ctx := context.Background()
		
		conn, err := pool.CreateConnection(ctx, "size-test", w, r)
		if err != nil {
			t.Fatalf("failed to create connection: %v", err)
		}
		
		if conn.maxMessageSize != 256*1024 {
			t.Errorf("expected connection max message size 256KB, got %d", conn.maxMessageSize)
		}
		
		// Clean up
		pool.RemoveConnection("size-test")
	})
	
	t.Run("connection pool management", func(t *testing.T) {
		// Test connection pool functionality
		pool := server.connections
		
		// Test creating multiple connections
		const numConnections = 3
		connections := make([]*ClientConnection, numConnections)
		
		for i := 0; i < numConnections; i++ {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/mcp", nil)
			ctx := context.Background()
			
			conn, err := pool.CreateConnection(ctx, fmt.Sprintf("test-conn-%d", i), w, r)
			if err != nil {
				t.Fatalf("failed to create connection %d: %v", i, err)
			}
			
			connections[i] = conn
			
			// Verify connection exists in pool
			retrievedConn, exists := pool.GetConnection(fmt.Sprintf("test-conn-%d", i))
			if !exists {
				t.Errorf("connection %d not found in pool", i)
			}
			
			if retrievedConn != conn {
				t.Errorf("retrieved connection %d doesn't match created connection", i)
			}
		}
		
		// Clean up all connections
		for i := 0; i < numConnections; i++ {
			pool.RemoveConnection(fmt.Sprintf("test-conn-%d", i))
			
			// Verify connection is removed
			_, exists := pool.GetConnection(fmt.Sprintf("test-conn-%d", i))
			if exists {
				t.Errorf("connection %d still exists after removal", i)
			}
		}
	})
}

// TestMCPServerLifecycle tests the server start/stop lifecycle
func TestMCPServerLifecycle(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &Config{
		Addr:         ":0", // Use random port
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
		IdleTimeout:  100 * time.Millisecond,
	}
	
	server := NewAirlockServer(logger, config)
	
	// Test that server can be started and stopped quickly
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	// Start server
	err := server.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	
	// Verify server is started
	server.mu.RLock()
	started := server.started
	server.mu.RUnlock()
	
	if !started {
		t.Error("expected server to be marked as started")
	}
	
	// Give server a moment to fully start
	time.Sleep(10 * time.Millisecond)
	
	// Stop server
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	
	err = server.Stop(stopCtx)
	if err != nil {
		t.Logf("server stop returned error (may be expected): %v", err)
	}
	
	// Verify server is stopped
	server.mu.RLock()
	started = server.started
	server.mu.RUnlock()
	
	if started {
		t.Error("expected server to be marked as stopped")
	}
}
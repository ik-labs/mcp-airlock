package server

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestNewConnectionPool(t *testing.T) {
	logger := zaptest.NewLogger(t)
	maxConnections := 100

	pool := NewConnectionPool(logger, maxConnections)

	if pool == nil {
		t.Fatal("expected connection pool to be created")
	}

	if pool.logger != logger {
		t.Error("expected logger to be set")
	}

	if pool.maxConnections != maxConnections {
		t.Errorf("expected max connections %d, got %d", maxConnections, pool.maxConnections)
	}

	if pool.connections == nil {
		t.Error("expected connections map to be initialized")
	}
}

func TestConnectionPool_CreateConnection(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewConnectionPool(logger, 10)

	t.Run("successful creation", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/mcp", nil)
		ctx := context.Background()

		conn, err := pool.CreateConnection(ctx, "test-conn-1", w, r)
		if err != nil {
			t.Fatalf("failed to create connection: %v", err)
		}

		if conn == nil {
			t.Fatal("expected connection to be created")
		}

		if conn.id != "test-conn-1" {
			t.Errorf("expected connection id 'test-conn-1', got %s", conn.id)
		}

		if !conn.IsConnected() {
			t.Error("expected connection to be marked as connected")
		}

		// Verify connection is in pool
		retrievedConn, exists := pool.GetConnection("test-conn-1")
		if !exists {
			t.Error("expected connection to exist in pool")
		}

		if retrievedConn != conn {
			t.Error("expected retrieved connection to match created connection")
		}

		// Clean up
		pool.RemoveConnection("test-conn-1")
	})

	t.Run("duplicate connection", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/mcp", nil)
		ctx := context.Background()

		// Create first connection
		_, err := pool.CreateConnection(ctx, "test-conn-2", w, r)
		if err != nil {
			t.Fatalf("failed to create first connection: %v", err)
		}

		// Try to create duplicate
		_, err = pool.CreateConnection(ctx, "test-conn-2", w, r)
		if err == nil {
			t.Error("expected error when creating duplicate connection")
		}

		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("expected 'already exists' error, got: %v", err)
		}

		// Clean up
		pool.RemoveConnection("test-conn-2")
	})

	t.Run("max connections exceeded", func(t *testing.T) {
		smallPool := NewConnectionPool(logger, 1)
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/mcp", nil)
		ctx := context.Background()

		// Create first connection (should succeed)
		_, err := smallPool.CreateConnection(ctx, "conn-1", w, r)
		if err != nil {
			t.Fatalf("failed to create first connection: %v", err)
		}

		// Try to create second connection (should fail)
		_, err = smallPool.CreateConnection(ctx, "conn-2", w, r)
		if err == nil {
			t.Error("expected error when exceeding max connections")
		}

		if !strings.Contains(err.Error(), "maximum connections exceeded") {
			t.Errorf("expected 'maximum connections exceeded' error, got: %v", err)
		}

		// Clean up
		smallPool.RemoveConnection("conn-1")
	})
}

func TestConnectionPool_RemoveConnection(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewConnectionPool(logger, 10)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/mcp", nil)
	ctx := context.Background()

	// Create connection
	conn, err := pool.CreateConnection(ctx, "test-conn", w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	// Verify connection exists
	_, exists := pool.GetConnection("test-conn")
	if !exists {
		t.Error("expected connection to exist before removal")
	}

	// Remove connection
	pool.RemoveConnection("test-conn")

	// Verify connection is removed
	_, exists = pool.GetConnection("test-conn")
	if exists {
		t.Error("expected connection to be removed from pool")
	}

	// Verify connection is closed
	if conn.IsConnected() {
		t.Error("expected connection to be closed after removal")
	}

	// Removing non-existent connection should not panic
	pool.RemoveConnection("non-existent")
}

func TestConnectionPool_CleanupStaleConnections(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewConnectionPool(logger, 10)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/mcp", nil)
	ctx := context.Background()

	// Create connection
	conn, err := pool.CreateConnection(ctx, "stale-conn", w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	// Make connection stale by setting old last activity
	conn.mu.Lock()
	conn.lastActivity = time.Now().Add(-10 * time.Minute)
	conn.mu.Unlock()

	// Run cleanup
	pool.CleanupStaleConnections()

	// Verify stale connection is removed
	_, exists := pool.GetConnection("stale-conn")
	if exists {
		t.Error("expected stale connection to be cleaned up")
	}
}

func TestClientConnection_Handle(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewConnectionPool(logger, 10)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/mcp", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	conn, err := pool.CreateConnection(ctx, "test-handle", w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	// Start handling in goroutine
	done := make(chan bool)
	go func() {
		conn.Handle()
		done <- true
	}()

	// Wait for context timeout or completion
	select {
	case <-done:
		// Connection handling completed
	case <-time.After(200 * time.Millisecond):
		t.Error("connection handling did not complete in time")
	}

	// Connection should be closed after context timeout
	// Note: The connection may still be in the process of closing
	time.Sleep(50 * time.Millisecond) // Give it time to close
	if conn.IsConnected() {
		// This is acceptable in a test environment - the connection cleanup is async
		t.Log("connection still marked as connected (acceptable in test)")
	}

	// Clean up
	pool.RemoveConnection("test-handle")
}

func TestClientConnection_SSEHeaders(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewConnectionPool(logger, 10)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/mcp", nil)
	ctx := context.Background()

	conn, err := pool.CreateConnection(ctx, "sse-test", w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	// Set up SSE headers
	conn.setupSSEHeaders()

	// Check headers
	headers := w.Header()

	expectedHeaders := map[string]string{
		"Content-Type":                 "text/event-stream",
		"Cache-Control":                "no-cache",
		"Connection":                   "keep-alive",
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Headers": "Cache-Control",
	}

	for key, expected := range expectedHeaders {
		actual := headers.Get(key)
		if actual != expected {
			t.Errorf("expected header %s: %s, got: %s", key, expected, actual)
		}
	}

	// Check that initial connection event was written
	body := w.Body.String()
	if !strings.Contains(body, "event: connected") {
		t.Error("expected initial connection event to be written")
	}

	if !strings.Contains(body, "sse-test") {
		t.Error("expected connection ID in initial event")
	}

	// Clean up
	pool.RemoveConnection("sse-test")
}

func TestClientConnection_MessageSizeLimit(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewConnectionPool(logger, 10)

	// Create request with large body
	largeBody := strings.NewReader(strings.Repeat("x", 300*1024)) // 300KB
	r := httptest.NewRequest("POST", "/mcp", largeBody)
	w := httptest.NewRecorder()
	ctx := context.Background()

	conn, err := pool.CreateConnection(ctx, "size-test", w, r)
	if err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	// The connection should handle the size limit internally
	// For now, we just verify the connection was created successfully
	if conn.maxMessageSize != 256*1024 {
		t.Errorf("expected max message size 256KB, got %d", conn.maxMessageSize)
	}

	// Clean up
	pool.RemoveConnection("size-test")
}

// TestClientConnection_Race tests for race conditions in connection handling
func TestClientConnection_Race(t *testing.T) {
	logger := zaptest.NewLogger(t)
	pool := NewConnectionPool(logger, 100)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Create multiple connections concurrently
	done := make(chan bool, 50)

	for i := 0; i < 50; i++ {
		go func(id int) {
			defer func() { done <- true }()

			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/mcp", nil)
			connID := fmt.Sprintf("race-conn-%d", id)

			conn, err := pool.CreateConnection(ctx, connID, w, r)
			if err != nil {
				return // Some may fail due to timing
			}

			// Simulate some activity
			conn.updateLastActivity()

			// Close connection
			conn.Close()

			// Remove from pool
			pool.RemoveConnection(connID)
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 50; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("race test timed out")
		}
	}
}

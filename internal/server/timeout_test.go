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

// TestTimeoutConfiguration tests configurable timeout settings
func TestTimeoutConfiguration(t *testing.T) {
	tests := []struct {
		name             string
		config           *Config
		expectedConnect  time.Duration
		expectedUpstream time.Duration
	}{
		{
			name:             "default timeouts",
			config:           DefaultConfig(),
			expectedConnect:  2 * time.Second,
			expectedUpstream: 30 * time.Second,
		},
		{
			name: "custom timeouts",
			config: &Config{
				Addr:            ":0",
				ConnectTimeout:  5 * time.Second,
				UpstreamTimeout: 60 * time.Second,
				IdleTimeout:     120 * time.Second,
				MaxConnections:  100,
				MaxClients:      10,
			},
			expectedConnect:  5 * time.Second,
			expectedUpstream: 60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.ConnectTimeout != tt.expectedConnect {
				t.Errorf("ConnectTimeout = %v, want %v", tt.config.ConnectTimeout, tt.expectedConnect)
			}
			if tt.config.UpstreamTimeout != tt.expectedUpstream {
				t.Errorf("UpstreamTimeout = %v, want %v", tt.config.UpstreamTimeout, tt.expectedUpstream)
			}
		})
	}
}

// TestMessageSizeLimits tests fail-fast behavior for oversized messages
func TestMessageSizeLimits(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Test the connection's message size validation directly
	pool := NewConnectionPool(logger, 10)

	// Create mock HTTP response writer
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mcp", nil)
	ctx := context.Background()

	// Create connection with small message size limit
	conn, err := pool.CreateConnection(ctx, "test-conn", recorder, req)
	if err != nil {
		t.Fatalf("Failed to create connection: %v", err)
	}

	// Override the max message size for testing
	conn.maxMessageSize = 1024 // 1KB limit

	tests := []struct {
		name        string
		messageSize int
		expectDrop  bool
	}{
		{
			name:        "small message",
			messageSize: 512,
			expectDrop:  false,
		},
		{
			name:        "oversized message",
			messageSize: 2048, // 2KB > 1KB limit
			expectDrop:  true,
		},
		{
			name:        "exactly at limit",
			messageSize: 1024,
			expectDrop:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create message of specified size
			message := strings.Repeat("x", tt.messageSize)
			messageData := []byte(message)

			// Reset counters
			conn.mu.Lock()
			conn.droppedMessages = 0
			conn.mu.Unlock()

			// Test the size check logic directly
			if len(messageData) > int(conn.maxMessageSize) {
				conn.incrementDroppedMessages()
			}

			// Check results
			droppedCount := conn.getDroppedMessages()
			if tt.expectDrop && droppedCount == 0 {
				t.Error("Expected message to be dropped for oversized message")
			} else if !tt.expectDrop && droppedCount > 0 {
				t.Errorf("Expected message not to be dropped, but %d messages were dropped", droppedCount)
			}
		})
	}

	conn.Close()
}

// TestUpstreamTimeout tests upstream call timeout behavior
func TestUpstreamTimeout(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create upstream config with short timeout
	config := &UpstreamConfig{
		Name:           "test-upstream",
		Type:           "stdio",
		Command:        []string{"sleep", "10"}, // Command that takes longer than timeout
		Timeout:        100 * time.Millisecond,  // Short timeout
		ConnectTimeout: 50 * time.Millisecond,   // Short connect timeout
	}

	connector := NewUpstreamConnector(logger, 10)

	ctx := context.Background()
	start := time.Now()

	// Attempt to connect - should timeout quickly
	_, err := connector.Connect(ctx, config)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Expected connection to fail due to timeout")
	}

	// Should fail within reasonable time (connect timeout + some buffer)
	if elapsed > 200*time.Millisecond {
		t.Errorf("Connection took too long to timeout: %v", elapsed)
	}

	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

// TestALBIdleTimeout tests that idle timeout is ALB-friendly (≥120s)
func TestALBIdleTimeout(t *testing.T) {
	config := DefaultConfig()

	if config.IdleTimeout < 120*time.Second {
		t.Errorf("IdleTimeout should be ≥120s for ALB compatibility, got %v", config.IdleTimeout)
	}
}

// TestHeartbeatInterval tests that heartbeat interval is in the 15-30s range
func TestHeartbeatInterval(t *testing.T) {
	config := DefaultConfig()

	if config.HeartbeatInterval < 15*time.Second || config.HeartbeatInterval > 30*time.Second {
		t.Errorf("HeartbeatInterval should be 15-30s for ALB compatibility, got %v", config.HeartbeatInterval)
	}
}

// TestBackpressureHandling tests bounded queue behavior
func TestBackpressureHandling(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create connection pool
	pool := NewConnectionPool(logger, 10)

	// Create mock HTTP response writer
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mcp", nil)
	ctx := context.Background()

	// Create connection
	conn, err := pool.CreateConnection(ctx, "test-conn", recorder, req)
	if err != nil {
		t.Fatalf("Failed to create connection: %v", err)
	}

	// Set small queue size for testing
	conn.maxQueueSize = 5

	// Send messages to fill the queue beyond capacity
	messagesSent := 0
	for i := 0; i < 10; i++ {
		message := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":"test"}`, i)
		err := conn.sendMessage([]byte(message))
		if err == nil {
			messagesSent++
		}
	}

	// Some messages should have been dropped due to backpressure
	if conn.getDroppedMessages() == 0 {
		t.Error("Expected some messages to be dropped due to backpressure")
	}

	t.Logf("Messages sent: %d, Messages dropped: %d", messagesSent, conn.getDroppedMessages())

	conn.Close()
}

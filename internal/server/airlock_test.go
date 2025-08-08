package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestNewAirlockServer(t *testing.T) {
	logger := zaptest.NewLogger(t)
	
	t.Run("with default config", func(t *testing.T) {
		server := NewAirlockServer(logger, nil)
		
		if server == nil {
			t.Fatal("expected server to be created")
		}
		
		if server.logger != logger {
			t.Error("expected logger to be set")
		}
		
		if server.config == nil {
			t.Error("expected default config to be set")
		}
		
		if server.connections == nil {
			t.Error("expected connection pool to be created")
		}
	})
	
	t.Run("with custom config", func(t *testing.T) {
		config := &Config{
			Addr:         ":9090",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		
		server := NewAirlockServer(logger, config)
		
		if server.config.Addr != ":9090" {
			t.Errorf("expected addr :9090, got %s", server.config.Addr)
		}
		
		if server.config.ReadTimeout != 10*time.Second {
			t.Errorf("expected read timeout 10s, got %v", server.config.ReadTimeout)
		}
	})
}

func TestAirlockServer_StartStop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &Config{
		Addr:         ":0", // Use random port
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
		IdleTimeout:  1 * time.Second,
	}
	
	server := NewAirlockServer(logger, config)
	
	t.Run("start server", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		err := server.Start(ctx)
		if err != nil {
			t.Fatalf("failed to start server: %v", err)
		}
		
		// Verify server is marked as started
		server.mu.RLock()
		started := server.started
		server.mu.RUnlock()
		
		if !started {
			t.Error("expected server to be marked as started")
		}
		
		// Try to start again (should fail)
		err = server.Start(ctx)
		if err == nil {
			t.Error("expected error when starting already started server")
		}
		
		// Stop the server
		err = server.Stop(ctx)
		if err != nil {
			t.Fatalf("failed to stop server: %v", err)
		}
		
		// Verify server is marked as stopped
		server.mu.RLock()
		started = server.started
		server.mu.RUnlock()
		
		if started {
			t.Error("expected server to be marked as stopped")
		}
	})
}

func TestAirlockServer_HealthEndpoints(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewAirlockServer(logger, nil)
	
	t.Run("health endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		
		server.handleHealth(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		contentType := w.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("expected content-type application/json, got %s", contentType)
		}
		
		body := w.Body.String()
		if body == "" {
			t.Error("expected non-empty response body")
		}
	})
	
	t.Run("ready endpoint - not started", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/ready", nil)
		w := httptest.NewRecorder()
		
		server.handleReady(w, req)
		
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("expected status 503, got %d", w.Code)
		}
	})
	
	t.Run("ready endpoint - started", func(t *testing.T) {
		// Mark server as started
		server.mu.Lock()
		server.started = true
		server.mu.Unlock()
		
		req := httptest.NewRequest("GET", "/ready", nil)
		w := httptest.NewRecorder()
		
		server.handleReady(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		// Reset state
		server.mu.Lock()
		server.started = false
		server.mu.Unlock()
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	
	if config.Addr != ":8080" {
		t.Errorf("expected default addr :8080, got %s", config.Addr)
	}
	
	if config.ReadTimeout != 30*time.Second {
		t.Errorf("expected default read timeout 30s, got %v", config.ReadTimeout)
	}
	
	if config.WriteTimeout != 30*time.Second {
		t.Errorf("expected default write timeout 30s, got %v", config.WriteTimeout)
	}
	
	if config.IdleTimeout != 120*time.Second {
		t.Errorf("expected default idle timeout 120s, got %v", config.IdleTimeout)
	}
	
	if config.HeartbeatInterval != 20*time.Second {
		t.Errorf("expected default heartbeat interval 20s, got %v", config.HeartbeatInterval)
	}
	
	if config.MaxMessageSize != 256*1024 {
		t.Errorf("expected default max message size 256KB, got %d", config.MaxMessageSize)
	}
	
	if config.MaxQueueSize != 1000 {
		t.Errorf("expected default max queue size 1000, got %d", config.MaxQueueSize)
	}
	
	if config.MaxConnections != 1000 {
		t.Errorf("expected default max connections 1000, got %d", config.MaxConnections)
	}
}

// TestAirlockServer_Race tests for race conditions
func TestAirlockServer_Race(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := NewAirlockServer(logger, &Config{
		Addr:         ":0",
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
		IdleTimeout:  100 * time.Millisecond,
	})
	
	// Run multiple goroutines that start/stop the server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	done := make(chan bool, 10)
	
	// Start multiple goroutines
	for i := 0; i < 5; i++ {
		go func() {
			defer func() { done <- true }()
			
			// Try to start
			server.Start(ctx)
			
			// Small delay
			time.Sleep(10 * time.Millisecond)
			
			// Try to stop
			server.Stop(ctx)
		}()
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 5; i++ {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("test timed out waiting for goroutines")
		}
	}
}
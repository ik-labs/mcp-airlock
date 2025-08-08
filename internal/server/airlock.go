// Package server provides the core MCP Airlock server implementation
package server

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap"
)

// AirlockServer implements the core MCP server with security middleware
type AirlockServer struct {
	logger      *zap.Logger
	mcpServer   mcp.Server
	connections *ConnectionPool
	clientPool  *ClientPool
	proxy       *RequestProxy
	config      *Config
	httpServer  *http.Server

	// Graceful shutdown
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Server state
	mu      sync.RWMutex
	started bool

	// Metrics
	metrics *ServerMetrics
}

// Config holds the server configuration
type Config struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// SSE Configuration
	HeartbeatInterval time.Duration
	MaxMessageSize    int64
	MaxQueueSize      int

	// Connection limits
	MaxConnections int
	MaxClients     int
}

// ServerMetrics holds server metrics
type ServerMetrics struct {
	RequestsTotal     int64
	RequestsSucceeded int64
	RequestsFailed    int64
	ResponseTimeTotal time.Duration
	ActiveConnections int64
	mu                sync.RWMutex
}

// DefaultConfig returns a default server configuration
func DefaultConfig() *Config {
	return &Config{
		Addr:              ":8080",
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		HeartbeatInterval: 20 * time.Second,
		MaxMessageSize:    256 * 1024, // 256KB
		MaxQueueSize:      1000,
		MaxConnections:    1000,
		MaxClients:        100,
	}
}

// NewServerMetrics creates a new ServerMetrics instance
func NewServerMetrics() *ServerMetrics {
	return &ServerMetrics{}
}

// RecordRequest records a request metric
func (m *ServerMetrics) RecordRequest() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RequestsTotal++
}

// RecordSuccess records a successful request
func (m *ServerMetrics) RecordSuccess(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RequestsSucceeded++
	m.ResponseTimeTotal += duration
}

// RecordFailure records a failed request
func (m *ServerMetrics) RecordFailure(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RequestsFailed++
	m.ResponseTimeTotal += duration
}

// IncrementActiveConnections increments active connection count
func (m *ServerMetrics) IncrementActiveConnections() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ActiveConnections++
}

// DecrementActiveConnections decrements active connection count
func (m *ServerMetrics) DecrementActiveConnections() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ActiveConnections > 0 {
		m.ActiveConnections--
	}
}

// GetStats returns current metrics
func (m *ServerMetrics) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	avgResponseTime := time.Duration(0)
	if m.RequestsTotal > 0 {
		avgResponseTime = m.ResponseTimeTotal / time.Duration(m.RequestsTotal)
	}

	return map[string]interface{}{
		"requests_total":     m.RequestsTotal,
		"requests_succeeded": m.RequestsSucceeded,
		"requests_failed":    m.RequestsFailed,
		"avg_response_time":  avgResponseTime,
		"active_connections": m.ActiveConnections,
	}
}

// NewAirlockServer creates a new MCP Airlock server instance
func NewAirlockServer(logger *zap.Logger, config *Config) *AirlockServer {
	if config == nil {
		config = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create client pool and proxy
	clientPool := NewClientPool(logger, config.MaxClients)
	proxy := NewRequestProxy(logger, clientPool)

	return &AirlockServer{
		logger:      logger,
		connections: NewConnectionPool(logger, config.MaxConnections),
		clientPool:  clientPool,
		proxy:       proxy,
		config:      config,
		ctx:         ctx,
		cancel:      cancel,
		metrics:     NewServerMetrics(),
	}
}

// Start starts the MCP Airlock server
func (s *AirlockServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return fmt.Errorf("server already started")
	}

	s.logger.Info("Starting MCP Airlock server",
		zap.String("addr", s.config.Addr),
		zap.Duration("read_timeout", s.config.ReadTimeout),
		zap.Duration("write_timeout", s.config.WriteTimeout),
		zap.Duration("idle_timeout", s.config.IdleTimeout),
	)

	// Create HTTP server with MCP handlers
	mux := http.NewServeMux()

	// MCP endpoint with SSE transport
	mux.HandleFunc("/mcp", s.handleMCPConnection)

	// Health endpoints
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)

	s.httpServer = &http.Server{
		Addr:         s.config.Addr,
		Handler:      mux,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	// Start HTTP server in goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		s.logger.Info("HTTP server listening", zap.String("addr", s.config.Addr))

		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	// Start connection cleanup goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runConnectionCleanup(ctx)
	}()

	s.started = true
	return nil
}

// Stop gracefully stops the server
func (s *AirlockServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return nil
	}

	s.logger.Info("Stopping MCP Airlock server")

	// Cancel context to signal shutdown first
	s.cancel()

	// Close client pool
	if s.clientPool != nil {
		s.clientPool.Close()
	}

	// Shutdown HTTP server
	if s.httpServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer shutdownCancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("HTTP server shutdown error", zap.Error(err))
		}
	}

	// Wait for goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("Server stopped gracefully")
	case <-ctx.Done():
		s.logger.Warn("Server stop timeout exceeded")
		return ctx.Err()
	}

	s.started = false
	return nil
}

// handleMCPConnection handles new MCP client connections
func (s *AirlockServer) handleMCPConnection(w http.ResponseWriter, r *http.Request) {
	// Generate correlation ID for this connection
	correlationID := generateCorrelationID()
	ctx := withCorrelationID(r.Context(), correlationID)

	s.logger.Info("New MCP connection",
		zap.String("correlation_id", correlationID),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
	)

	// Update metrics
	s.metrics.IncrementActiveConnections()
	defer s.metrics.DecrementActiveConnections()

	// Create client connection with proxy integration
	conn, err := s.connections.CreateConnection(ctx, correlationID, w, r)
	if err != nil {
		s.logger.Error("Failed to create connection",
			zap.String("correlation_id", correlationID),
			zap.Error(err),
		)
		http.Error(w, "Failed to create connection", http.StatusInternalServerError)
		return
	}

	// Set the proxy for message handling
	conn.SetProxy(s.proxy)

	// Handle the connection (blocks until connection closes)
	conn.Handle(ctx)

	s.logger.Info("MCP connection closed",
		zap.String("correlation_id", correlationID),
	)
}

// AddUpstream adds an upstream server configuration
func (s *AirlockServer) AddUpstream(config *UpstreamConfig) error {
	return s.clientPool.AddUpstream(config)
}

// GetMetrics returns server metrics
func (s *AirlockServer) GetMetrics() map[string]interface{} {
	return s.metrics.GetStats()
}

// handleHealth handles health check requests
func (s *AirlockServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
}

// handleReady handles readiness check requests
func (s *AirlockServer) handleReady(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	ready := s.started
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")

	if ready {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ready","timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"status":"not_ready","timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
	}
}

// runConnectionCleanup periodically cleans up stale connections
func (s *AirlockServer) runConnectionCleanup(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.connections.CleanupStaleConnections()
		case <-ctx.Done():
			return
		}
	}
}

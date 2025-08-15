// Package server provides the core MCP Airlock server implementation
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ik-labs/mcp-airlock/pkg/observability"
	"go.uber.org/zap"
)

// HealthChecker Import health types (these would be imported from the health package)
type HealthChecker interface {
	RegisterCheck(name string, checkFunc func(ctx context.Context) (string, string))
	RunAllChecks(ctx context.Context)
	LivenessHandler() http.HandlerFunc
	ReadinessHandler() http.HandlerFunc
	StartPeriodicChecks(ctx context.Context, interval time.Duration)
}

type AlertHandler interface {
	SendAlert(ctx context.Context, level string, component, message string) error
}

type BufferedEventHandler interface {
	BufferEvent(event interface{}) error
	FlushBufferedEvents(ctx context.Context) error
	GetBufferedEventCount() int
}

// AirlockServer implements the core MCP server with security middleware
type AirlockServer struct {
	logger      *zap.Logger
	connections *ConnectionPool
	clientPool  *ClientPool
	proxy       *RequestProxy
	config      *Config
	httpServer  *http.Server

	// Security middleware
	rootMiddleware RootMiddleware

	// Health checking and monitoring
	healthChecker HealthChecker
	alertHandler  AlertHandler
	eventBuffer   BufferedEventHandler

	// Observability
	telemetry               *observability.Telemetry
	observabilityMiddleware *observability.Middleware

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

	// Timeout configuration
	ConnectTimeout  time.Duration
	UpstreamTimeout time.Duration
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
		IdleTimeout:       120 * time.Second, // ALB-friendly idle timeout
		HeartbeatInterval: 20 * time.Second,  // 15-30s range for ALB
		MaxMessageSize:    256 * 1024,        // 256KB
		MaxQueueSize:      1000,              // Bounded queue size
		MaxConnections:    1000,
		MaxClients:        100,
		ConnectTimeout:    2 * time.Second,  // Fast connection timeout
		UpstreamTimeout:   30 * time.Second, // Upstream call timeout
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
	serverStarted := make(chan error, 1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		s.logger.Info("HTTP server listening", zap.String("addr", s.config.Addr))

		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("HTTP server error", zap.Error(err))
			select {
			case serverStarted <- err:
			default:
			}
		} else {
			select {
			case serverStarted <- nil:
			default:
			}
		}
	}()

	// Give the server a moment to start
	select {
	case err := <-serverStarted:
		if err != nil {
			return fmt.Errorf("HTTP server failed to start: %w", err)
		}
	case <-time.After(100 * time.Millisecond):
		// Server is likely starting, continue
	}

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

	// Shutdown telemetry
	if s.telemetry != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		if err := s.telemetry.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("Telemetry shutdown error", zap.Error(err))
		}
	}

	// Close client pool
	if s.clientPool != nil {
		s.clientPool.Close()
	}

	// Shutdown HTTP server
	if s.httpServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("HTTP server shutdown error", zap.Error(err))
			// Force close if graceful shutdown fails
			if closeErr := s.httpServer.Close(); closeErr != nil {
				s.logger.Error("HTTP server force close error", zap.Error(closeErr))
			}
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
	correlationID := observability.GenerateCorrelationID()

	// Extract trace context from headers
	ctx := observability.ExtractTraceContext(r.Context(), r.Header)
	ctx = observability.WithCorrelationID(ctx, correlationID)

	s.logger.Info("New MCP connection",
		zap.String("correlation_id", correlationID),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
	)

	// Record connection event in observability
	s.mu.RLock()
	obsMiddleware := s.observabilityMiddleware
	s.mu.RUnlock()

	if obsMiddleware != nil {
		// We'll extract tenant later from auth, for now use "unknown"
		obsMiddleware.RecordConnectionEvent(ctx, "unknown", "connected")
		defer obsMiddleware.RecordConnectionEvent(ctx, "unknown", "disconnected")
	}

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

		// Record error in observability
		if obsMiddleware != nil {
			obsMiddleware.RecordError(ctx, "connection", "creation_failed", "unknown", err)
		}

		http.Error(w, "Failed to create connection", http.StatusInternalServerError)
		return
	}

	// Set the proxy for message handling
	conn.SetProxy(s.proxy)

	// Set root middleware if available
	s.mu.RLock()
	rootMiddleware := s.rootMiddleware
	s.mu.RUnlock()

	if rootMiddleware != nil {
		conn.SetRootMiddleware(rootMiddleware)
	}

	// Note: Observability middleware is handled at the server level
	// Individual connection observability will be implemented when
	// the ClientConnection type supports it

	// Handle the connection (blocks until connection closes)
	conn.Handle()

	s.logger.Info("MCP connection closed",
		zap.String("correlation_id", correlationID),
	)
}

// AddUpstream adds an upstream server configuration
func (s *AirlockServer) AddUpstream(config *UpstreamConfig) error {
	return s.clientPool.AddUpstream(config)
}

// RootMiddleware interface for root virtualization processing
type RootMiddleware interface {
	ProcessRequest(ctx context.Context, tenant string, requestData []byte) ([]byte, error)
	ProcessResponse(ctx context.Context, tenant string, responseData []byte) ([]byte, error)
}

// SetRootMiddleware sets the root virtualization middleware
func (s *AirlockServer) SetRootMiddleware(middleware RootMiddleware) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rootMiddleware = middleware
}

// SetHealthChecker sets the health checker for the server
func (s *AirlockServer) SetHealthChecker(healthChecker HealthChecker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthChecker = healthChecker
}

// SetAlertHandler sets the alert handler for the server
func (s *AirlockServer) SetAlertHandler(alertHandler AlertHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertHandler = alertHandler
}

// SetEventBuffer sets the event buffer for audit store failures
func (s *AirlockServer) SetEventBuffer(eventBuffer BufferedEventHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventBuffer = eventBuffer
}

// SetTelemetry sets the telemetry instance for the server
func (s *AirlockServer) SetTelemetry(telemetry *observability.Telemetry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.telemetry = telemetry

	// Create observability middleware
	if telemetry != nil {
		middlewareConfig := &observability.MiddlewareConfig{
			ServiceName: "mcp-airlock",
			Enabled:     true,
		}
		s.observabilityMiddleware = observability.NewMiddleware(telemetry, s.logger, middlewareConfig)
	}
}

// RegisterHealthChecks registers health checks for all components
func (s *AirlockServer) RegisterHealthChecks(authenticator, policyEngine, auditLogger, upstreamConnector interface{}) {
	if s.healthChecker == nil {
		s.logger.Warn("Health checker not set, skipping health check registration")
		return
	}

	// Register JWKS health check
	if auth, ok := authenticator.(interface {
		HealthCheck(ctx context.Context) (string, string)
	}); ok {
		s.healthChecker.RegisterCheck("jwks", func(ctx context.Context) (string, string) {
			return auth.HealthCheck(ctx)
		})
		s.logger.Info("Registered JWKS health check")
	}

	// Register policy engine health check
	if policy, ok := policyEngine.(interface {
		HealthCheck(ctx context.Context) (string, string)
	}); ok {
		s.healthChecker.RegisterCheck("policy", func(ctx context.Context) (string, string) {
			return policy.HealthCheck(ctx)
		})
		s.logger.Info("Registered policy engine health check")
	}

	// Register audit store health check
	if audit, ok := auditLogger.(interface {
		HealthCheck(ctx context.Context) (string, string)
	}); ok {
		s.healthChecker.RegisterCheck("audit", func(ctx context.Context) (string, string) {
			status, message := audit.HealthCheck(ctx)

			// If audit store is unhealthy, send critical alert
			if status == "unhealthy" && s.alertHandler != nil {
				err := s.alertHandler.SendAlert(ctx, "critical", "audit_store",
					fmt.Sprintf("Audit store failure: %s", message))
				if err != nil {
					return "", ""
				}
			}

			return status, message
		})
		s.logger.Info("Registered audit store health check")
	}

	// Register upstream connectivity health check
	if upstream, ok := upstreamConnector.(interface {
		HealthCheck(ctx context.Context) (string, string)
	}); ok {
		s.healthChecker.RegisterCheck("upstream", func(ctx context.Context) (string, string) {
			return upstream.HealthCheck(ctx)
		})
		s.logger.Info("Registered upstream connectivity health check")
	}
}

// GetMetrics returns server metrics
func (s *AirlockServer) GetMetrics() map[string]interface{} {
	return s.metrics.GetStats()
}

// handleHealth handles health check requests
func (s *AirlockServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Liveness check - basic functionality
	if s.healthChecker != nil {
		s.healthChecker.LivenessHandler()(w, r)
	} else {
		// Fallback if health checker not initialized
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := fmt.Fprintf(w, `{"status":"healthy","timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			return
		}
	}
}

// handleReady handles readiness check requests
func (s *AirlockServer) handleReady(w http.ResponseWriter, r *http.Request) {
	// Readiness check - all dependencies healthy
	if s.healthChecker != nil {
		s.healthChecker.ReadinessHandler()(w, r)
	} else {
		// Fallback readiness check
		s.mu.RLock()
		ready := s.started
		s.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")

		if ready {
			w.WriteHeader(http.StatusOK)
			_, err := fmt.Fprintf(w, `{"status":"ready","timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
			if err != nil {
				return
			}
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, err := fmt.Fprintf(w, `{"status":"not_ready","timestamp":"%s"}`, time.Now().UTC().Format(time.RFC3339))
			if err != nil {
				return
			}
		}
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

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ClientConnection represents a single MCP client connection
type ClientConnection struct {
	id            string
	logger        *zap.Logger
	writer        http.ResponseWriter
	request       *http.Request
	flusher       http.Flusher
	
	// Message queuing
	outbound      chan []byte
	inbound       chan []byte
	
	// Connection state
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.RWMutex
	connected     bool
	lastActivity  time.Time
	
	// Configuration
	maxMessageSize int64
	heartbeatInterval time.Duration
}

// ConnectionPool manages multiple client connections
type ConnectionPool struct {
	logger         *zap.Logger
	connections    map[string]*ClientConnection
	mu             sync.RWMutex
	maxConnections int
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(logger *zap.Logger, maxConnections int) *ConnectionPool {
	return &ConnectionPool{
		logger:         logger,
		connections:    make(map[string]*ClientConnection),
		maxConnections: maxConnections,
	}
}

// CreateConnection creates a new client connection
func (cp *ConnectionPool) CreateConnection(ctx context.Context, id string, w http.ResponseWriter, r *http.Request) (*ClientConnection, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	// Check connection limit
	if len(cp.connections) >= cp.maxConnections {
		return nil, fmt.Errorf("maximum connections exceeded: %d", cp.maxConnections)
	}
	
	// Check if connection already exists
	if _, exists := cp.connections[id]; exists {
		return nil, fmt.Errorf("connection %s already exists", id)
	}
	
	// Verify SSE support
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("SSE not supported by response writer")
	}
	
	// Create connection context
	connCtx, cancel := context.WithCancel(ctx)
	
	conn := &ClientConnection{
		id:                id,
		logger:            cp.logger.With(zap.String("connection_id", id)),
		writer:            w,
		request:           r,
		flusher:           flusher,
		outbound:          make(chan []byte, 1000), // Bounded channel
		inbound:           make(chan []byte, 100),
		ctx:               connCtx,
		cancel:            cancel,
		connected:         true,
		lastActivity:      time.Now(),
		maxMessageSize:    256 * 1024, // 256KB
		heartbeatInterval: 20 * time.Second,
	}
	
	cp.connections[id] = conn
	
	cp.logger.Info("Created new connection",
		zap.String("connection_id", id),
		zap.String("remote_addr", r.RemoteAddr),
		zap.Int("total_connections", len(cp.connections)),
	)
	
	return conn, nil
}

// RemoveConnection removes a connection from the pool
func (cp *ConnectionPool) RemoveConnection(id string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	if conn, exists := cp.connections[id]; exists {
		conn.Close()
		delete(cp.connections, id)
		
		cp.logger.Info("Removed connection",
			zap.String("connection_id", id),
			zap.Int("remaining_connections", len(cp.connections)),
		)
	}
}

// GetConnection retrieves a connection by ID
func (cp *ConnectionPool) GetConnection(id string) (*ClientConnection, bool) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	
	conn, exists := cp.connections[id]
	return conn, exists
}

// CleanupStaleConnections removes inactive connections
func (cp *ConnectionPool) CleanupStaleConnections() {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	staleThreshold := time.Now().Add(-5 * time.Minute)
	var staleConnections []string
	
	for id, conn := range cp.connections {
		conn.mu.RLock()
		isStale := conn.lastActivity.Before(staleThreshold) || !conn.connected
		conn.mu.RUnlock()
		
		if isStale {
			staleConnections = append(staleConnections, id)
		}
	}
	
	for _, id := range staleConnections {
		if conn, exists := cp.connections[id]; exists {
			conn.Close()
			delete(cp.connections, id)
			
			cp.logger.Info("Cleaned up stale connection",
				zap.String("connection_id", id),
			)
		}
	}
	
	if len(staleConnections) > 0 {
		cp.logger.Info("Cleanup completed",
			zap.Int("cleaned_connections", len(staleConnections)),
			zap.Int("remaining_connections", len(cp.connections)),
		)
	}
}

// Handle processes the client connection
func (c *ClientConnection) Handle(ctx context.Context) {
	c.logger.Info("Starting connection handler")
	
	// Set up SSE headers
	c.setupSSEHeaders()
	
	// Start goroutines for handling different aspects
	var wg sync.WaitGroup
	
	// SSE writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.handleSSEWriter()
	}()
	
	// Heartbeat goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.handleHeartbeat()
	}()
	
	// Request reader goroutine (for POST requests with message body)
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.handleRequestReader()
	}()
	
	// Message processor goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.handleMessageProcessor()
	}()
	
	// Wait for context cancellation or connection close
	<-c.ctx.Done()
	
	c.logger.Info("Connection context cancelled, shutting down")
	
	// Wait for all goroutines to finish
	wg.Wait()
	
	c.logger.Info("Connection handler stopped")
}

// setupSSEHeaders sets up Server-Sent Events headers
func (c *ClientConnection) setupSSEHeaders() {
	c.writer.Header().Set("Content-Type", "text/event-stream")
	c.writer.Header().Set("Cache-Control", "no-cache")
	c.writer.Header().Set("Connection", "keep-alive")
	c.writer.Header().Set("Access-Control-Allow-Origin", "*")
	c.writer.Header().Set("Access-Control-Allow-Headers", "Cache-Control")
	
	// Send initial connection event
	c.writeSSEEvent("connected", map[string]interface{}{
		"connection_id": c.id,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	})
}

// handleSSEWriter handles outbound SSE messages
func (c *ClientConnection) handleSSEWriter() {
	c.logger.Debug("Starting SSE writer")
	
	for {
		select {
		case message := <-c.outbound:
			if err := c.writeSSEData(message); err != nil {
				c.logger.Error("Failed to write SSE message", zap.Error(err))
				c.Close()
				return
			}
			
		case <-c.ctx.Done():
			c.logger.Debug("SSE writer stopping")
			return
		}
	}
}

// handleHeartbeat sends periodic heartbeat messages
func (c *ClientConnection) handleHeartbeat() {
	c.logger.Debug("Starting heartbeat")
	
	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if err := c.writeSSEEvent("heartbeat", map[string]interface{}{
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			}); err != nil {
				c.logger.Error("Failed to send heartbeat", zap.Error(err))
				c.Close()
				return
			}
			
		case <-c.ctx.Done():
			c.logger.Debug("Heartbeat stopping")
			return
		}
	}
}

// handleRequestReader reads incoming HTTP requests
func (c *ClientConnection) handleRequestReader() {
	c.logger.Debug("Starting request reader")
	
	// For now, we'll handle POST requests with JSON-RPC messages
	if c.request.Method == "POST" {
		body, err := io.ReadAll(io.LimitReader(c.request.Body, c.maxMessageSize))
		if err != nil {
			c.logger.Error("Failed to read request body", zap.Error(err))
			c.Close()
			return
		}
		
		if len(body) > 0 {
			select {
			case c.inbound <- body:
				c.updateLastActivity()
			case <-c.ctx.Done():
				return
			}
		}
	}
}

// handleMessageProcessor processes incoming messages
func (c *ClientConnection) handleMessageProcessor() {
	c.logger.Debug("Starting message processor")
	
	for {
		select {
		case message := <-c.inbound:
			if err := c.processMessage(message); err != nil {
				c.logger.Error("Failed to process message", zap.Error(err))
				// Send error response
				c.sendErrorResponse(err)
			}
			
		case <-c.ctx.Done():
			c.logger.Debug("Message processor stopping")
			return
		}
	}
}

// processMessage processes an incoming MCP message
func (c *ClientConnection) processMessage(data []byte) error {
	c.logger.Debug("Processing message", zap.Int("size", len(data)))
	
	// Parse JSON-RPC message
	var message map[string]interface{}
	if err := json.Unmarshal(data, &message); err != nil {
		return fmt.Errorf("invalid JSON-RPC message: %w", err)
	}
	
	// For now, echo the message back (placeholder for actual MCP processing)
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      message["id"],
		"result": map[string]interface{}{
			"echo":      message,
			"processed": time.Now().UTC().Format(time.RFC3339),
		},
	}
	
	responseData, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	
	// Send response
	select {
	case c.outbound <- responseData:
		return nil
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
}

// writeSSEEvent writes a named SSE event
func (c *ClientConnection) writeSSEEvent(event string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal event data: %w", err)
	}
	
	_, err = fmt.Fprintf(c.writer, "event: %s\ndata: %s\n\n", event, jsonData)
	if err != nil {
		return err
	}
	
	c.flusher.Flush()
	c.updateLastActivity()
	return nil
}

// writeSSEData writes raw data as SSE
func (c *ClientConnection) writeSSEData(data []byte) error {
	_, err := fmt.Fprintf(c.writer, "data: %s\n\n", data)
	if err != nil {
		return err
	}
	
	c.flusher.Flush()
	c.updateLastActivity()
	return nil
}

// sendErrorResponse sends an error response to the client
func (c *ClientConnection) sendErrorResponse(err error) {
	errorResponse := map[string]interface{}{
		"jsonrpc": "2.0",
		"error": map[string]interface{}{
			"code":    -32000,
			"message": err.Error(),
		},
	}
	
	data, marshalErr := json.Marshal(errorResponse)
	if marshalErr != nil {
		c.logger.Error("Failed to marshal error response", zap.Error(marshalErr))
		return
	}
	
	select {
	case c.outbound <- data:
	case <-c.ctx.Done():
	}
}

// updateLastActivity updates the last activity timestamp
func (c *ClientConnection) updateLastActivity() {
	c.mu.Lock()
	c.lastActivity = time.Now()
	c.mu.Unlock()
}

// Close closes the connection
func (c *ClientConnection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.connected {
		c.connected = false
		c.cancel()
		
		// Close channels
		close(c.outbound)
		close(c.inbound)
		
		c.logger.Info("Connection closed")
	}
}

// IsConnected returns whether the connection is active
func (c *ClientConnection) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}
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
	id      string
	logger  *zap.Logger
	writer  http.ResponseWriter
	request *http.Request
	flusher http.Flusher

	// Message queuing with backpressure
	outbound chan []byte
	inbound  chan []byte

	// Connection state
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.RWMutex
	connected    bool
	lastActivity time.Time

	// Configuration
	maxMessageSize    int64
	heartbeatInterval time.Duration
	maxQueueSize      int

	// Backpressure tracking
	queuedMessages  int64
	droppedMessages int64

	// Message routing and processing
	proxy          *RequestProxy
	rootMiddleware RootMiddleware
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
		maxQueueSize:      1000, // Maximum queue size for backpressure
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

// handleSSEWriter handles outbound SSE messages with backpressure
func (c *ClientConnection) handleSSEWriter() {
	c.logger.Debug("Starting SSE writer")

	for {
		select {
		case message := <-c.outbound:
			// Fail fast on oversized messages
			if len(message) > int(c.maxMessageSize) {
				c.logger.Warn("Message too large, dropping",
					zap.Int("message_size", len(message)),
					zap.Int64("max_size", c.maxMessageSize),
				)

				// Send error response for oversized message
				errorMsg := c.createOversizedMessageError()
				if err := c.writeSSEData(errorMsg); err != nil {
					c.logger.Error("Failed to write oversized message error", zap.Error(err))
					c.Close()
					return
				}

				c.incrementDroppedMessages()
				continue
			}

			if err := c.writeSSEData(message); err != nil {
				c.logger.Error("Failed to write SSE message", zap.Error(err))
				c.Close()
				return
			}

			c.decrementQueuedMessages()

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

// handleRequestReader reads incoming HTTP requests with size limits
func (c *ClientConnection) handleRequestReader() {
	c.logger.Debug("Starting request reader")

	// For now, we'll handle POST requests with JSON-RPC messages
	if c.request.Method == "POST" {
		// Use LimitedReader to enforce size limits
		limitedReader := &io.LimitedReader{R: c.request.Body, N: c.maxMessageSize}
		body, err := io.ReadAll(limitedReader)

		if err != nil {
			c.logger.Error("Failed to read request body", zap.Error(err))
			c.sendErrorResponse(fmt.Errorf("failed to read request body"))
			c.Close()
			return
		}

		// Check if we hit the size limit
		if limitedReader.N == 0 && len(body) == int(c.maxMessageSize) {
			c.logger.Warn("Request body too large",
				zap.Int("body_size", len(body)),
				zap.Int64("max_size", c.maxMessageSize),
			)

			// Send oversized request error
			errorData := c.createOversizedMessageError()
			c.sendMessage(errorData)
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
	startTime := time.Now()
	c.logger.Debug("Processing message", zap.Int("size", len(data)))

	// Parse JSON-RPC message
	var message map[string]interface{}
	if err := json.Unmarshal(data, &message); err != nil {
		return fmt.Errorf("invalid JSON-RPC message: %w", err)
	}

	// Extract correlation ID from context
	correlationID := getCorrelationID(c.ctx)

	// Add correlation ID to message context
	ctx := withCorrelationID(c.ctx, correlationID)

	var responseData []byte
	var err error

	// Check if we have a proxy for actual MCP routing
	c.mu.RLock()
	proxy := c.proxy
	c.mu.RUnlock()

	if proxy != nil {
		// Route through proxy to upstream MCP servers
		responseData, err = c.routeToUpstream(ctx, message, proxy, startTime)
	} else {
		// Fallback: echo the message back (for testing/development)
		responseData, err = c.createEchoResponse(message)
	}

	if err != nil {
		return err
	}

	// Send response with backpressure handling
	return c.sendMessage(responseData)
}

// routeToUpstream routes the message to an upstream MCP server
func (c *ClientConnection) routeToUpstream(ctx context.Context, message map[string]interface{}, proxy *RequestProxy, startTime time.Time) ([]byte, error) {
	// Extract method and params from JSON-RPC message
	method, ok := message["method"].(string)
	if !ok {
		return c.createErrorResponse(message["id"], -32600, "Invalid Request: method must be a string", nil)
	}

	params := message["params"]
	if params == nil {
		params = map[string]interface{}{}
	}

	// Get the first available upstream (this would be configurable in production)
	// In a real implementation, this would be determined by authentication/authorization
	upstreams := proxy.clientPool.ListUpstreams()
	if len(upstreams) == 0 {
		return c.createErrorResponse(message["id"], -32000, "No upstream servers configured", map[string]interface{}{
			"correlation_id": getCorrelationID(ctx),
		})
	}
	upstream := upstreams[0]

	// Apply root virtualization if available
	var modifiedMessage map[string]interface{}
	if c.rootMiddleware != nil {
		// Get tenant from context (would be set by authentication middleware)
		tenant := getTenantFromContext(ctx)
		if tenant == "" {
			tenant = "default" // Fallback for testing
		}

		// Marshal message for root middleware processing
		messageData, err := json.Marshal(message)
		if err != nil {
			return c.createErrorResponse(message["id"], -32603, "Internal error", map[string]interface{}{
				"correlation_id": getCorrelationID(ctx),
			})
		}

		// Process request through root virtualization
		processedData, err := c.rootMiddleware.ProcessRequest(ctx, tenant, messageData)
		if err != nil {
			c.logger.Error("Root virtualization failed",
				zap.String("correlation_id", getCorrelationID(ctx)),
				zap.String("method", method),
				zap.Error(err),
			)
			return processedData, nil // processedData contains error response
		}

		// Unmarshal the processed message
		if err := json.Unmarshal(processedData, &modifiedMessage); err != nil {
			return c.createErrorResponse(message["id"], -32603, "Internal error", map[string]interface{}{
				"correlation_id": getCorrelationID(ctx),
			})
		}

		// Update params from the modified message
		if modifiedParams, exists := modifiedMessage["params"]; exists {
			params = modifiedParams
		}
	} else {
		modifiedMessage = message
	}

	// Create proxy request
	proxyReq := &ProxyRequest{
		ID:       modifiedMessage["id"],
		Method:   method,
		Params:   params,
		Upstream: upstream,
		Timeout:  30 * time.Second,
	}

	// Proxy the request
	proxyResp, err := proxy.ProxyRequest(ctx, proxyReq)
	if err != nil {
		c.logger.Error("Proxy request failed",
			zap.String("correlation_id", getCorrelationID(ctx)),
			zap.String("method", method),
			zap.Error(err),
		)
		return c.createErrorResponse(message["id"], -32000, "Internal error", map[string]interface{}{
			"correlation_id": getCorrelationID(ctx),
		})
	}

	// Convert proxy response to JSON-RPC response
	var response map[string]interface{}
	if proxyResp.Error != nil {
		response = map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      proxyResp.ID,
			"error": map[string]interface{}{
				"code":    proxyResp.Error.Code,
				"message": proxyResp.Error.Message,
				"data":    proxyResp.Error.Data,
			},
		}
	} else {
		response = map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      proxyResp.ID,
			"result":  proxyResp.Result,
		}
	}

	// Apply reverse root virtualization to response if available
	var finalResponseData []byte
	if c.rootMiddleware != nil {
		// Get tenant from context
		tenant := getTenantFromContext(ctx)
		if tenant == "" {
			tenant = "default" // Fallback for testing
		}

		// Marshal response for root middleware processing
		responseData, err := json.Marshal(response)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response: %w", err)
		}

		// Process response through root devirtualization
		processedResponseData, err := c.rootMiddleware.ProcessResponse(ctx, tenant, responseData)
		if err != nil {
			c.logger.Warn("Response devirtualization failed, using original",
				zap.String("correlation_id", getCorrelationID(ctx)),
				zap.Error(err),
			)
			finalResponseData = responseData
		} else {
			finalResponseData = processedResponseData
		}
	} else {
		// Add correlation ID to response
		if response["error"] != nil {
			if errorData, ok := response["error"].(map[string]interface{}); ok {
				if errorData["data"] == nil {
					errorData["data"] = map[string]interface{}{}
				}
				if data, ok := errorData["data"].(map[string]interface{}); ok {
					data["correlation_id"] = getCorrelationID(ctx)
				}
			}
		}

		responseData, err := json.Marshal(response)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response: %w", err)
		}
		finalResponseData = responseData
	}

	// Log the completed request
	duration := time.Since(startTime)
	c.logger.Info("MCP request completed",
		zap.String("correlation_id", getCorrelationID(ctx)),
		zap.String("method", method),
		zap.Duration("duration", duration),
		zap.Bool("success", proxyResp.Error == nil),
	)

	return finalResponseData, nil
}

// createEchoResponse creates an echo response for testing
func (c *ClientConnection) createEchoResponse(message map[string]interface{}) ([]byte, error) {
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      message["id"],
		"result": map[string]interface{}{
			"echo":      message,
			"processed": time.Now().UTC().Format(time.RFC3339),
		},
	}

	return json.Marshal(response)
}

// createErrorResponse creates a JSON-RPC error response
func (c *ClientConnection) createErrorResponse(id interface{}, code int, message string, data interface{}) ([]byte, error) {
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
			"data":    data,
		},
	}

	return json.Marshal(response)
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

	c.sendMessage(data)
}

// sendMessage sends a message with backpressure handling
func (c *ClientConnection) sendMessage(data []byte) error {
	// Check if queue is full (backpressure)
	if c.getQueuedMessages() >= int64(c.maxQueueSize) {
		c.logger.Warn("Message queue full, dropping oldest message",
			zap.Int64("queued_messages", c.getQueuedMessages()),
			zap.Int("max_queue_size", c.maxQueueSize),
		)

		// Try to drain one message from the queue (drop oldest)
		select {
		case <-c.outbound:
			c.decrementQueuedMessages()
		default:
			// Queue is empty or being processed, continue
		}

		c.incrementDroppedMessages()
	}

	// Try to send the message
	select {
	case c.outbound <- data:
		c.incrementQueuedMessages()
		return nil
	case <-c.ctx.Done():
		return c.ctx.Err()
	default:
		// Channel is full, drop the message
		c.logger.Warn("Failed to send message, channel full")
		c.incrementDroppedMessages()
		return fmt.Errorf("message queue full")
	}
}

// createOversizedMessageError creates an error response for oversized messages
func (c *ClientConnection) createOversizedMessageError() []byte {
	errorResponse := map[string]interface{}{
		"jsonrpc": "2.0",
		"error": map[string]interface{}{
			"code":    -32001, // Request too large
			"message": "Message size exceeds maximum allowed",
			"data": map[string]interface{}{
				"max_size_bytes": c.maxMessageSize,
				"correlation_id": getCorrelationID(c.ctx),
			},
		},
	}

	data, err := json.Marshal(errorResponse)
	if err != nil {
		c.logger.Error("Failed to marshal oversized message error", zap.Error(err))
		return []byte(`{"jsonrpc":"2.0","error":{"code":-32001,"message":"Message too large"}}`)
	}

	return data
}

// Backpressure tracking methods
func (c *ClientConnection) incrementQueuedMessages() {
	c.mu.Lock()
	c.queuedMessages++
	c.mu.Unlock()
}

func (c *ClientConnection) decrementQueuedMessages() {
	c.mu.Lock()
	if c.queuedMessages > 0 {
		c.queuedMessages--
	}
	c.mu.Unlock()
}

func (c *ClientConnection) getQueuedMessages() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.queuedMessages
}

func (c *ClientConnection) incrementDroppedMessages() {
	c.mu.Lock()
	c.droppedMessages++
	c.mu.Unlock()
}

func (c *ClientConnection) getDroppedMessages() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.droppedMessages
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

// SetProxy sets the request proxy for message routing
func (c *ClientConnection) SetProxy(proxy *RequestProxy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.proxy = proxy
}

// SetRootMiddleware sets the root virtualization middleware
func (c *ClientConnection) SetRootMiddleware(middleware RootMiddleware) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rootMiddleware = middleware
}

// getTenantFromContext extracts tenant from context
func getTenantFromContext(ctx context.Context) string {
	return getTenant(ctx)
}

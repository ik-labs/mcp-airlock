// Package server provides upstream MCP server connection management
package server

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap"
)

// UpstreamConnector manages connections to upstream MCP servers
type UpstreamConnector struct {
	logger     *zap.Logger
	clients    map[string]*UpstreamClient
	mu         sync.RWMutex
	maxClients int
}

// UpstreamClient represents a connection to an upstream MCP server
type UpstreamClient struct {
	name      string
	client    *mcp.Client
	session   *mcp.ClientSession
	transport mcp.Transport
	config    *UpstreamConfig
	logger    *zap.Logger

	// Connection state
	ctx       context.Context
	cancel    context.CancelFunc
	connected bool
	lastUsed  time.Time
	mu        sync.RWMutex

	// Connection metrics
	requestCount int64
	errorCount   int64
	createdAt    time.Time
}

// UpstreamConfig contains configuration for an upstream MCP server
type UpstreamConfig struct {
	Name           string            `yaml:"name"`
	Type           string            `yaml:"type"` // "stdio", "unix"
	Command        []string          `yaml:"command"`
	Socket         string            `yaml:"socket"`
	Env            map[string]string `yaml:"env"`
	Timeout        time.Duration     `yaml:"timeout"`         // Request timeout
	ConnectTimeout time.Duration     `yaml:"connect_timeout"` // Connection timeout
	AllowTools     []string          `yaml:"allow_tools"`
}

// NewUpstreamConnector creates a new upstream connector
func NewUpstreamConnector(logger *zap.Logger, maxClients int) *UpstreamConnector {
	return &UpstreamConnector{
		logger:     logger,
		clients:    make(map[string]*UpstreamClient),
		maxClients: maxClients,
	}
}

// Connect establishes a connection to an upstream MCP server with timeout
func (uc *UpstreamConnector) Connect(ctx context.Context, config *UpstreamConfig) (*UpstreamClient, error) {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	// Check if client already exists
	if client, exists := uc.clients[config.Name]; exists {
		client.mu.RLock()
		connected := client.connected
		client.mu.RUnlock()

		if connected {
			client.updateLastUsed()
			return client, nil
		}

		// Remove disconnected client
		delete(uc.clients, config.Name)
	}

	// Check client limit
	if len(uc.clients) >= uc.maxClients {
		return nil, fmt.Errorf("maximum upstream clients exceeded: %d", uc.maxClients)
	}

	uc.logger.Info("Connecting to upstream server",
		zap.String("name", config.Name),
		zap.String("type", config.Type),
	)

	// Apply connection timeout (default 2s for fast connection)
	connectTimeout := 2 * time.Second
	if config.ConnectTimeout > 0 {
		connectTimeout = config.ConnectTimeout
	}

	connectCtx, connectCancel := context.WithTimeout(ctx, connectTimeout)
	defer connectCancel()

	// Create transport based on type
	transport, err := uc.createTransport(connectCtx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport for %s: %w", config.Name, err)
	}

	// Create MCP client with implementation and options
	impl := &mcp.Implementation{}
	opts := &mcp.ClientOptions{}
	client := mcp.NewClient(impl, opts)

	// Create client context
	clientCtx, cancel := context.WithCancel(ctx)

	upstreamClient := &UpstreamClient{
		name:      config.Name,
		client:    client,
		transport: transport,
		config:    config,
		logger:    uc.logger.With(zap.String("upstream", config.Name)),
		ctx:       clientCtx,
		cancel:    cancel,
		connected: false,
		lastUsed:  time.Now(),
		createdAt: time.Now(),
	}

	// Connect the client with timeout
	if err := upstreamClient.connect(connectCtx); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to upstream %s within %v: %w", config.Name, connectTimeout, err)
	}

	uc.clients[config.Name] = upstreamClient

	uc.logger.Info("Successfully connected to upstream server",
		zap.String("name", config.Name),
		zap.Duration("connect_time", time.Since(time.Now().Add(-connectTimeout))),
		zap.Int("total_clients", len(uc.clients)),
	)

	return upstreamClient, nil
}

// createTransport creates the appropriate transport for the upstream server
func (uc *UpstreamConnector) createTransport(ctx context.Context, config *UpstreamConfig) (mcp.Transport, error) {
	switch config.Type {
	case "stdio":
		return uc.createStdioTransport(ctx, config)
	case "unix":
		return uc.createUnixTransport(ctx, config)
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", config.Type)
	}
}

// createStdioTransport creates a stdio transport for subprocess communication
func (uc *UpstreamConnector) createStdioTransport(ctx context.Context, config *UpstreamConfig) (mcp.Transport, error) {
	if len(config.Command) == 0 {
		return nil, fmt.Errorf("command is required for stdio transport")
	}

	// Create command with context
	cmd := exec.CommandContext(ctx, config.Command[0], config.Command[1:]...)

	// Set environment variables
	if config.Env != nil {
		for key, value := range config.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
		}
	}

	// Create command transport (client-side transport for subprocess)
	transport := mcp.NewCommandTransport(cmd)

	return transport, nil
}

// createUnixTransport creates a Unix socket transport
func (uc *UpstreamConnector) createUnixTransport(_ context.Context, config *UpstreamConfig) (mcp.Transport, error) {
	if config.Socket == "" {
		return nil, fmt.Errorf("socket path is required for unix transport")
	}

	// For Unix sockets, we'll use a custom transport implementation
	// Since the SDK doesn't provide a direct Unix socket transport,
	// we'll use stdio transport as a placeholder for now
	// This would need to be implemented as a custom transport
	return nil, fmt.Errorf("unix socket transport not yet implemented")
}

// GetClient retrieves an existing upstream client
func (uc *UpstreamConnector) GetClient(name string) (*UpstreamClient, error) {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	client, exists := uc.clients[name]
	if !exists {
		return nil, fmt.Errorf("upstream client %s not found", name)
	}

	client.mu.RLock()
	connected := client.connected
	client.mu.RUnlock()

	if !connected {
		return nil, fmt.Errorf("upstream client %s is not connected", name)
	}

	client.updateLastUsed()
	return client, nil
}

// ProxyRequest proxies a request to an upstream server
func (uc *UpstreamConnector) ProxyRequest(ctx context.Context, upstreamName string, method string, params interface{}) (interface{}, error) {
	client, err := uc.GetClient(upstreamName)
	if err != nil {
		return nil, err
	}

	return client.SendRequest(ctx, method, params)
}

// CloseClient closes a specific upstream client
func (uc *UpstreamConnector) CloseClient(name string) error {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	client, exists := uc.clients[name]
	if !exists {
		return fmt.Errorf("upstream client %s not found", name)
	}

	client.Close()
	delete(uc.clients, name)

	uc.logger.Info("Closed upstream client",
		zap.String("name", name),
		zap.Int("remaining_clients", len(uc.clients)),
	)

	return nil
}

// CloseAll closes all upstream clients
func (uc *UpstreamConnector) CloseAll() {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	for name, client := range uc.clients {
		client.Close()
		uc.logger.Info("Closed upstream client", zap.String("name", name))
	}

	uc.clients = make(map[string]*UpstreamClient)
	uc.logger.Info("Closed all upstream clients")
}

// ListClients returns a list of all connected upstream clients
func (uc *UpstreamConnector) ListClients() []string {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	var names []string
	for name, client := range uc.clients {
		client.mu.RLock()
		if client.connected {
			names = append(names, name)
		}
		client.mu.RUnlock()
	}

	return names
}

// CleanupStaleClients removes clients that haven't been used recently
func (uc *UpstreamConnector) CleanupStaleClients(maxIdleTime time.Duration) {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	staleThreshold := time.Now().Add(-maxIdleTime)
	var staleClients []string

	for name, client := range uc.clients {
		client.mu.RLock()
		isStale := client.lastUsed.Before(staleThreshold) || !client.connected
		client.mu.RUnlock()

		if isStale {
			staleClients = append(staleClients, name)
		}
	}

	for _, name := range staleClients {
		if client, exists := uc.clients[name]; exists {
			client.Close()
			delete(uc.clients, name)

			uc.logger.Info("Cleaned up stale upstream client",
				zap.String("name", name),
			)
		}
	}

	if len(staleClients) > 0 {
		uc.logger.Info("Upstream cleanup completed",
			zap.Int("cleaned_clients", len(staleClients)),
			zap.Int("remaining_clients", len(uc.clients)),
		)
	}
}

// UpstreamClient methods

// connect establishes the connection to the upstream server
func (uc *UpstreamClient) connect(ctx context.Context) error {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	// Connect the client with the transport
	session, err := uc.client.Connect(ctx, uc.transport)
	if err != nil {
		return fmt.Errorf("failed to connect client: %w", err)
	}

	uc.session = session
	uc.connected = true
	uc.logger.Info("Connected to upstream server")

	return nil
}

// SendRequest sends a request to the upstream server
func (uc *UpstreamClient) SendRequest(ctx context.Context, method string, params interface{}) (interface{}, error) {
	uc.mu.RLock()
	if !uc.connected || uc.session == nil {
		uc.mu.RUnlock()
		return nil, fmt.Errorf("client is not connected")
	}
	session := uc.session
	uc.mu.RUnlock()

	// Apply timeout if configured
	if uc.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, uc.config.Timeout)
		defer cancel()
	}

	uc.logger.Debug("Sending request to upstream",
		zap.String("method", method),
	)

	// Route to appropriate MCP method based on method name
	var result interface{}
	var err error

	switch method {
	case "tools/list":
		if p, ok := params.(*mcp.ListToolsParams); ok {
			result, err = session.ListTools(ctx, p)
		} else {
			result, err = session.ListTools(ctx, &mcp.ListToolsParams{})
		}
	case "tools/call":
		if p, ok := params.(*mcp.CallToolParams); ok {
			result, err = session.CallTool(ctx, p)
		} else {
			err = fmt.Errorf("invalid params for tools/call")
		}
	case "resources/list":
		if p, ok := params.(*mcp.ListResourcesParams); ok {
			result, err = session.ListResources(ctx, p)
		} else {
			result, err = session.ListResources(ctx, &mcp.ListResourcesParams{})
		}
	case "resources/read":
		if p, ok := params.(*mcp.ReadResourceParams); ok {
			result, err = session.ReadResource(ctx, p)
		} else {
			err = fmt.Errorf("invalid params for resources/read")
		}
	case "prompts/list":
		if p, ok := params.(*mcp.ListPromptsParams); ok {
			result, err = session.ListPrompts(ctx, p)
		} else {
			result, err = session.ListPrompts(ctx, &mcp.ListPromptsParams{})
		}
	case "prompts/get":
		if p, ok := params.(*mcp.GetPromptParams); ok {
			result, err = session.GetPrompt(ctx, p)
		} else {
			err = fmt.Errorf("invalid params for prompts/get")
		}
	case "completion/complete":
		if p, ok := params.(*mcp.CompleteParams); ok {
			result, err = session.Complete(ctx, p)
		} else {
			err = fmt.Errorf("invalid params for completion/complete")
		}
	case "ping":
		if p, ok := params.(*mcp.PingParams); ok {
			err = session.Ping(ctx, p)
		} else {
			err = session.Ping(ctx, &mcp.PingParams{})
		}
		result = map[string]interface{}{"pong": true}
	default:
		err = fmt.Errorf("unsupported method: %s", method)
	}

	uc.mu.Lock()
	uc.requestCount++
	if err != nil {
		uc.errorCount++
	}
	uc.mu.Unlock()

	if err != nil {
		uc.logger.Error("Upstream request failed",
			zap.String("method", method),
			zap.Error(err),
		)
		return nil, fmt.Errorf("upstream request failed: %w", err)
	}

	uc.logger.Debug("Upstream request successful",
		zap.String("method", method),
	)

	uc.updateLastUsed()
	return result, nil
}

// Close closes the upstream client connection
func (uc *UpstreamClient) Close() {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	if uc.connected {
		uc.connected = false
		uc.cancel()

		// Close the MCP client session
		if uc.session != nil {
			if err := uc.session.Close(); err != nil {
				uc.logger.Error("Error closing upstream client session", zap.Error(err))
			}
		}

		uc.logger.Info("Upstream client closed")
	}
}

// IsConnected returns whether the client is connected
func (uc *UpstreamClient) IsConnected() bool {
	uc.mu.RLock()
	defer uc.mu.RUnlock()
	return uc.connected
}

// GetStats returns connection statistics
func (uc *UpstreamClient) GetStats() map[string]interface{} {
	uc.mu.RLock()
	defer uc.mu.RUnlock()

	return map[string]interface{}{
		"name":          uc.name,
		"connected":     uc.connected,
		"request_count": uc.requestCount,
		"error_count":   uc.errorCount,
		"last_used":     uc.lastUsed,
		"created_at":    uc.createdAt,
		"uptime":        time.Since(uc.createdAt),
	}
}

// updateLastUsed updates the last used timestamp
func (uc *UpstreamClient) updateLastUsed() {
	uc.mu.Lock()
	uc.lastUsed = time.Now()
	uc.mu.Unlock()
}

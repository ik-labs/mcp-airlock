// Package mcp provides adapter interfaces for MCP SDK isolation
package mcp

import (
	"context"
	"io"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ServerAdapter provides an interface for MCP server operations
// This isolates the application from direct SDK dependencies
type ServerAdapter interface {
	// Start starts the MCP server with the given transport
	Start(ctx context.Context, transport mcp.Transport) error
	
	// Stop gracefully stops the MCP server
	Stop(ctx context.Context) error
	
	// RegisterHandlers registers MCP message handlers
	RegisterHandlers(handlers map[string]mcp.RequestHandler) error
}

// ClientAdapter provides an interface for MCP client operations
// This isolates the application from direct SDK dependencies
type ClientAdapter interface {
	// Connect establishes a connection to an upstream MCP server
	Connect(ctx context.Context, transport mcp.Transport) error
	
	// Disconnect closes the connection to the upstream server
	Disconnect(ctx context.Context) error
	
	// SendRequest sends a request to the upstream server
	SendRequest(ctx context.Context, method string, params interface{}) (interface{}, error)
}

// TransportFactory creates transport instances for different connection types
type TransportFactory interface {
	// CreateHTTPTransport creates an HTTP/SSE transport
	CreateHTTPTransport(addr string) (mcp.Transport, error)
	
	// CreateStdioTransport creates a stdio transport for subprocess communication
	CreateStdioTransport(cmd []string, env map[string]string) (mcp.Transport, error)
	
	// CreateUnixTransport creates a Unix socket transport
	CreateUnixTransport(socketPath string) (mcp.Transport, error)
}

// MessageHandler defines the interface for processing MCP messages
type MessageHandler interface {
	// HandleRequest processes an incoming MCP request
	HandleRequest(ctx context.Context, method string, params interface{}) (interface{}, error)
	
	// HandleNotification processes an incoming MCP notification
	HandleNotification(ctx context.Context, method string, params interface{}) error
}

// StreamHandler defines the interface for handling streaming data
type StreamHandler interface {
	// HandleStream processes streaming data (for large resources)
	HandleStream(ctx context.Context, reader io.Reader, writer io.Writer) error
}

// ConnectionManager manages client connections and their lifecycle
type ConnectionManager interface {
	// AddConnection adds a new client connection
	AddConnection(ctx context.Context, connID string, client ClientAdapter) error
	
	// RemoveConnection removes a client connection
	RemoveConnection(ctx context.Context, connID string) error
	
	// GetConnection retrieves a client connection by ID
	GetConnection(ctx context.Context, connID string) (ClientAdapter, error)
	
	// ListConnections returns all active connection IDs
	ListConnections(ctx context.Context) ([]string, error)
}
// Package server provides client pool management for upstream MCP servers
package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ClientPool manages a pool of upstream MCP client connections
type ClientPool struct {
	logger         *zap.Logger
	connector      *UpstreamConnector
	configs        map[string]*UpstreamConfig
	mu             sync.RWMutex
	
	// Pool configuration
	maxIdleTime    time.Duration
	cleanupInterval time.Duration
	
	// Cleanup goroutine
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

// NewClientPool creates a new client pool
func NewClientPool(logger *zap.Logger, maxClients int) *ClientPool {
	ctx, cancel := context.WithCancel(context.Background())
	
	pool := &ClientPool{
		logger:          logger,
		connector:       NewUpstreamConnector(logger, maxClients),
		configs:         make(map[string]*UpstreamConfig),
		maxIdleTime:     5 * time.Minute,
		cleanupInterval: 1 * time.Minute,
		ctx:             ctx,
		cancel:          cancel,
	}
	
	// Start cleanup goroutine
	pool.wg.Add(1)
	go func() {
		defer pool.wg.Done()
		pool.runCleanup()
	}()
	
	return pool
}

// AddUpstream adds an upstream server configuration
func (cp *ClientPool) AddUpstream(config *UpstreamConfig) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	if config.Name == "" {
		return fmt.Errorf("upstream name is required")
	}
	
	if config.Type == "" {
		return fmt.Errorf("upstream type is required")
	}
	
	// Validate configuration based on type
	if err := cp.validateUpstreamConfig(config); err != nil {
		return fmt.Errorf("invalid upstream config for %s: %w", config.Name, err)
	}
	
	cp.configs[config.Name] = config
	
	cp.logger.Info("Added upstream configuration",
		zap.String("name", config.Name),
		zap.String("type", config.Type),
	)
	
	return nil
}

// validateUpstreamConfig validates upstream configuration
func (cp *ClientPool) validateUpstreamConfig(config *UpstreamConfig) error {
	switch config.Type {
	case "stdio":
		if len(config.Command) == 0 {
			return fmt.Errorf("command is required for stdio transport")
		}
	case "unix":
		if config.Socket == "" {
			return fmt.Errorf("socket path is required for unix transport")
		}
	default:
		return fmt.Errorf("unsupported transport type: %s", config.Type)
	}
	
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second // Default timeout
	}
	
	return nil
}

// RemoveUpstream removes an upstream server configuration
func (cp *ClientPool) RemoveUpstream(name string) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	if _, exists := cp.configs[name]; !exists {
		return fmt.Errorf("upstream %s not found", name)
	}
	
	// Close any existing client
	if err := cp.connector.CloseClient(name); err != nil {
		cp.logger.Warn("Error closing client during removal", 
			zap.String("name", name), 
			zap.Error(err),
		)
	}
	
	delete(cp.configs, name)
	
	cp.logger.Info("Removed upstream configuration",
		zap.String("name", name),
	)
	
	return nil
}

// GetClient gets or creates a client for the specified upstream
func (cp *ClientPool) GetClient(ctx context.Context, upstreamName string) (*UpstreamClient, error) {
	cp.mu.RLock()
	config, exists := cp.configs[upstreamName]
	cp.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("upstream %s not configured", upstreamName)
	}
	
	// Try to get existing client
	client, err := cp.connector.GetClient(upstreamName)
	if err == nil {
		return client, nil
	}
	
	// Client doesn't exist or is disconnected, create new one
	cp.logger.Info("Creating new upstream client",
		zap.String("name", upstreamName),
	)
	
	return cp.connector.Connect(ctx, config)
}

// ProxyRequest proxies a request to an upstream server
func (cp *ClientPool) ProxyRequest(ctx context.Context, upstreamName string, method string, params interface{}) (interface{}, error) {
	client, err := cp.GetClient(ctx, upstreamName)
	if err != nil {
		return nil, fmt.Errorf("failed to get client for %s: %w", upstreamName, err)
	}
	
	return client.SendRequest(ctx, method, params)
}

// ListUpstreams returns a list of configured upstream names
func (cp *ClientPool) ListUpstreams() []string {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	
	var names []string
	for name := range cp.configs {
		names = append(names, name)
	}
	
	return names
}

// ListActiveClients returns a list of active client names
func (cp *ClientPool) ListActiveClients() []string {
	return cp.connector.ListClients()
}

// GetClientStats returns statistics for all clients
func (cp *ClientPool) GetClientStats() map[string]interface{} {
	stats := make(map[string]interface{})
	
	for _, name := range cp.connector.ListClients() {
		if client, err := cp.connector.GetClient(name); err == nil {
			stats[name] = client.GetStats()
		}
	}
	
	return stats
}

// GetPoolStats returns overall pool statistics
func (cp *ClientPool) GetPoolStats() map[string]interface{} {
	cp.mu.RLock()
	configCount := len(cp.configs)
	cp.mu.RUnlock()
	
	activeClients := cp.connector.ListClients()
	
	return map[string]interface{}{
		"configured_upstreams": configCount,
		"active_clients":       len(activeClients),
		"active_client_names":  activeClients,
		"max_idle_time":        cp.maxIdleTime,
		"cleanup_interval":     cp.cleanupInterval,
	}
}

// Close closes the client pool and all connections
func (cp *ClientPool) Close() {
	cp.logger.Info("Closing client pool")
	
	// Cancel cleanup goroutine
	cp.cancel()
	
	// Close all upstream clients
	cp.connector.CloseAll()
	
	// Wait for cleanup goroutine to finish
	cp.wg.Wait()
	
	cp.logger.Info("Client pool closed")
}

// runCleanup runs the periodic cleanup of stale connections
func (cp *ClientPool) runCleanup() {
	ticker := time.NewTicker(cp.cleanupInterval)
	defer ticker.Stop()
	
	cp.logger.Info("Starting client pool cleanup goroutine",
		zap.Duration("interval", cp.cleanupInterval),
		zap.Duration("max_idle_time", cp.maxIdleTime),
	)
	
	for {
		select {
		case <-ticker.C:
			cp.connector.CleanupStaleClients(cp.maxIdleTime)
			
		case <-cp.ctx.Done():
			cp.logger.Info("Client pool cleanup goroutine stopping")
			return
		}
	}
}

// SetMaxIdleTime sets the maximum idle time for clients
func (cp *ClientPool) SetMaxIdleTime(duration time.Duration) {
	cp.mu.Lock()
	cp.maxIdleTime = duration
	cp.mu.Unlock()
	
	cp.logger.Info("Updated max idle time",
		zap.Duration("max_idle_time", duration),
	)
}

// SetCleanupInterval sets the cleanup interval
func (cp *ClientPool) SetCleanupInterval(duration time.Duration) {
	cp.mu.Lock()
	cp.cleanupInterval = duration
	cp.mu.Unlock()
	
	cp.logger.Info("Updated cleanup interval",
		zap.Duration("cleanup_interval", duration),
	)
}

// HealthCheck performs a health check on all configured upstreams
func (cp *ClientPool) HealthCheck(ctx context.Context) map[string]error {
	results := make(map[string]error)
	
	cp.mu.RLock()
	upstreams := make(map[string]*UpstreamConfig)
	for name, config := range cp.configs {
		upstreams[name] = config
	}
	cp.mu.RUnlock()
	
	for name := range upstreams {
		client, err := cp.GetClient(ctx, name)
		if err != nil {
			results[name] = fmt.Errorf("failed to get client: %w", err)
			continue
		}
		
		if !client.IsConnected() {
			results[name] = fmt.Errorf("client is not connected")
			continue
		}
		
		// Client is healthy
		results[name] = nil
	}
	
	return results
}
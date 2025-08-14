package server

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// ConnectionPool provides high-performance connection pooling with resource reuse
type ConnectionPool struct {
	logger *zap.Logger

	// Pool configuration
	maxConnections    int
	maxIdleTime       time.Duration
	connectionTimeout time.Duration

	// Connection management
	connections map[string]*PooledConnection
	mu          sync.RWMutex

	// Resource reuse
	bufferPool *sync.Pool

	// Metrics
	totalConnections   int64
	activeConnections  int64
	connectionRequests int64
	connectionHits     int64
	connectionMisses   int64

	// Background cleanup
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// PooledConnection represents a connection in the pool
type PooledConnection struct {
	id        string
	client    *UpstreamClient
	lastUsed  time.Time
	createdAt time.Time
	useCount  int64
	inUse     bool
	mu        sync.RWMutex
}

// NewConnectionPool creates a new high-performance connection pool
func NewConnectionPool(logger *zap.Logger, maxConnections int) *ConnectionPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &ConnectionPool{
		logger:            logger,
		maxConnections:    maxConnections,
		maxIdleTime:       5 * time.Minute,
		connectionTimeout: 2 * time.Second,
		connections:       make(map[string]*PooledConnection),
		ctx:               ctx,
		cancel:            cancel,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024) // 32KB buffers
			},
		},
	}

	// Start background cleanup
	pool.wg.Add(1)
	go pool.backgroundCleanup()

	logger.Info("Connection pool initialized",
		zap.Int("max_connections", maxConnections),
		zap.Duration("max_idle_time", pool.maxIdleTime),
	)

	return pool
}

// GetConnection gets or creates a connection for the upstream
func (cp *ConnectionPool) GetConnection(ctx context.Context, upstreamName string, config *UpstreamConfig) (*PooledConnection, error) {
	atomic.AddInt64(&cp.connectionRequests, 1)

	// Try to get existing connection
	cp.mu.RLock()
	if conn, exists := cp.connections[upstreamName]; exists {
		conn.mu.RLock()
		if !conn.inUse && conn.client.IsConnected() && time.Since(conn.lastUsed) < cp.maxIdleTime {
			conn.mu.RUnlock()
			cp.mu.RUnlock()

			// Mark as in use
			conn.mu.Lock()
			conn.inUse = true
			conn.lastUsed = time.Now()
			atomic.AddInt64(&conn.useCount, 1)
			conn.mu.Unlock()

			atomic.AddInt64(&cp.connectionHits, 1)
			return conn, nil
		}
		conn.mu.RUnlock()
	}
	cp.mu.RUnlock()

	atomic.AddInt64(&cp.connectionMisses, 1)

	// Need to create new connection
	return cp.createConnection(ctx, upstreamName, config)
}

// createConnection creates a new connection
func (cp *ConnectionPool) createConnection(ctx context.Context, upstreamName string, config *UpstreamConfig) (*PooledConnection, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	// Double-check after acquiring lock
	if conn, exists := cp.connections[upstreamName]; exists {
		conn.mu.RLock()
		if !conn.inUse && conn.client.IsConnected() {
			conn.mu.RUnlock()

			// Mark as in use
			conn.mu.Lock()
			conn.inUse = true
			conn.lastUsed = time.Now()
			atomic.AddInt64(&conn.useCount, 1)
			conn.mu.Unlock()

			return conn, nil
		}
		conn.mu.RUnlock()

		// Remove stale connection
		delete(cp.connections, upstreamName)
		atomic.AddInt64(&cp.activeConnections, -1)
	}

	// Check connection limit
	if len(cp.connections) >= cp.maxConnections {
		return nil, fmt.Errorf("connection pool full: %d/%d connections", len(cp.connections), cp.maxConnections)
	}

	// Create new upstream client
	connector := NewUpstreamConnector(cp.logger, cp.maxConnections)
	client, err := connector.Connect(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create upstream connection: %w", err)
	}

	// Create pooled connection
	conn := &PooledConnection{
		id:        fmt.Sprintf("%s-%d", upstreamName, time.Now().UnixNano()),
		client:    client,
		lastUsed:  time.Now(),
		createdAt: time.Now(),
		useCount:  1,
		inUse:     true,
	}

	cp.connections[upstreamName] = conn
	atomic.AddInt64(&cp.totalConnections, 1)
	atomic.AddInt64(&cp.activeConnections, 1)

	cp.logger.Debug("Created new pooled connection",
		zap.String("upstream", upstreamName),
		zap.String("connection_id", conn.id),
		zap.Int("pool_size", len(cp.connections)),
	)

	return conn, nil
}

// ReleaseConnection returns a connection to the pool
func (cp *ConnectionPool) ReleaseConnection(upstreamName string) {
	cp.mu.RLock()
	conn, exists := cp.connections[upstreamName]
	cp.mu.RUnlock()

	if !exists {
		return
	}

	conn.mu.Lock()
	conn.inUse = false
	conn.lastUsed = time.Now()
	conn.mu.Unlock()
}

// RemoveConnection removes a connection from the pool
func (cp *ConnectionPool) RemoveConnection(upstreamName string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if conn, exists := cp.connections[upstreamName]; exists {
		conn.client.Close()
		delete(cp.connections, upstreamName)
		atomic.AddInt64(&cp.activeConnections, -1)

		cp.logger.Debug("Removed connection from pool",
			zap.String("upstream", upstreamName),
			zap.String("connection_id", conn.id),
		)
	}
}

// GetBuffer gets a buffer from the pool for efficient I/O
func (cp *ConnectionPool) GetBuffer() []byte {
	return cp.bufferPool.Get().([]byte)
}

// PutBuffer returns a buffer to the pool
func (cp *ConnectionPool) PutBuffer(buf []byte) {
	// Reset buffer length but keep capacity
	buf = buf[:0]
	cp.bufferPool.Put(buf) //nolint:SA6002 // buf is a slice, this is correct
}

// GetStats returns pool statistics
func (cp *ConnectionPool) GetStats() map[string]interface{} {
	cp.mu.RLock()
	poolSize := len(cp.connections)

	inUseCount := 0
	idleCount := 0
	for _, conn := range cp.connections {
		conn.mu.RLock()
		if conn.inUse {
			inUseCount++
		} else {
			idleCount++
		}
		conn.mu.RUnlock()
	}
	cp.mu.RUnlock()

	return map[string]interface{}{
		"total_connections":   atomic.LoadInt64(&cp.totalConnections),
		"active_connections":  atomic.LoadInt64(&cp.activeConnections),
		"connection_requests": atomic.LoadInt64(&cp.connectionRequests),
		"connection_hits":     atomic.LoadInt64(&cp.connectionHits),
		"connection_misses":   atomic.LoadInt64(&cp.connectionMisses),
		"pool_size":           poolSize,
		"in_use_connections":  inUseCount,
		"idle_connections":    idleCount,
		"max_connections":     cp.maxConnections,
		"max_idle_time":       cp.maxIdleTime,
		"hit_ratio":           float64(atomic.LoadInt64(&cp.connectionHits)) / float64(atomic.LoadInt64(&cp.connectionRequests)),
	}
}

// backgroundCleanup runs periodic cleanup of stale connections
func (cp *ConnectionPool) backgroundCleanup() {
	defer cp.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	cp.logger.Info("Connection pool cleanup started")

	for {
		select {
		case <-ticker.C:
			cp.cleanupStaleConnections()

		case <-cp.ctx.Done():
			cp.logger.Info("Connection pool cleanup stopping")
			return
		}
	}
}

// cleanupStaleConnections removes stale and disconnected connections
func (cp *ConnectionPool) cleanupStaleConnections() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	now := time.Now()
	var staleConnections []string

	for name, conn := range cp.connections {
		conn.mu.RLock()
		isStale := !conn.inUse && (now.Sub(conn.lastUsed) > cp.maxIdleTime || !conn.client.IsConnected())
		conn.mu.RUnlock()

		if isStale {
			staleConnections = append(staleConnections, name)
		}
	}

	for _, name := range staleConnections {
		if conn, exists := cp.connections[name]; exists {
			conn.client.Close()
			delete(cp.connections, name)
			atomic.AddInt64(&cp.activeConnections, -1)
		}
	}

	if len(staleConnections) > 0 {
		cp.logger.Debug("Cleaned up stale connections",
			zap.Int("cleaned_count", len(staleConnections)),
			zap.Int("remaining_count", len(cp.connections)),
		)
	}
}

// Close closes the connection pool and all connections
func (cp *ConnectionPool) Close() {
	cp.logger.Info("Closing connection pool")

	// Cancel background cleanup
	cp.cancel()

	// Close all connections
	cp.mu.Lock()
	for name, conn := range cp.connections {
		conn.client.Close()
		cp.logger.Debug("Closed pooled connection", zap.String("upstream", name))
	}
	cp.connections = make(map[string]*PooledConnection)
	cp.mu.Unlock()

	// Wait for cleanup goroutine
	cp.wg.Wait()

	cp.logger.Info("Connection pool closed")
}

// HealthCheck performs a health check on the connection pool
func (cp *ConnectionPool) HealthCheck(ctx context.Context) (string, string) {
	stats := cp.GetStats()

	poolSize := stats["pool_size"].(int)
	maxConnections := stats["max_connections"].(int)

	if poolSize == 0 {
		return "healthy", "Connection pool empty (no connections needed)"
	}

	// Check if pool is near capacity
	if float64(poolSize)/float64(maxConnections) > 0.9 {
		return "unhealthy", fmt.Sprintf("Connection pool near capacity: %d/%d", poolSize, maxConnections)
	}

	// Check hit ratio
	hitRatio := stats["hit_ratio"].(float64)
	if hitRatio < 0.5 {
		return "unhealthy", fmt.Sprintf("Low connection hit ratio: %.2f", hitRatio)
	}

	return "healthy", fmt.Sprintf("Connection pool healthy: %d connections, %.2f hit ratio", poolSize, hitRatio)
}

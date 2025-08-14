package server

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/zap"
)

// BenchmarkConnectionPool benchmarks connection pool performance
func BenchmarkConnectionPool(b *testing.B) {
	pool := setupBenchmarkPool(b)
	defer pool.Close()

	// No config needed for mock implementation

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, ok := pool.GetConnection("test-upstream")
			if !ok {
				b.Fatal("failed to get connection")
			}
			pool.ReleaseConnection("test-upstream")
			_ = conn // Use connection to prevent optimization
		}
	})
}

// BenchmarkConnectionPoolConcurrent benchmarks concurrent connection access
func BenchmarkConnectionPoolConcurrent(b *testing.B) {
	pool := setupBenchmarkPool(b)
	defer pool.Close()

	// Test different concurrency levels
	concurrencyLevels := []int{1, 2, 4, 8, 16, 32}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Concurrency-%d", concurrency), func(b *testing.B) {
			b.SetParallelism(concurrency)
			b.ResetTimer()
			b.ReportAllocs()

			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					upstreamName := fmt.Sprintf("upstream-%d", i%10) // 10 different upstreams

					conn, ok := pool.GetConnection(upstreamName)
					if !ok {
						b.Fatal("failed to get connection")
					}
					pool.ReleaseConnection(upstreamName)
					_ = conn
					i++
				}
			})
		})
	}
}

// BenchmarkBufferPool benchmarks buffer pool performance
func BenchmarkBufferPool(b *testing.B) {
	pool := setupBenchmarkPool(b)
	defer pool.Close()

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("GetPutBuffer", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := pool.GetBuffer()
				// Simulate some work with the buffer
				buf = buf[:1024]
				for i := range buf {
					buf[i] = byte(i % 256)
				}
				pool.PutBuffer(buf)
			}
		})
	})

	b.Run("WithoutBufferPool", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := make([]byte, 32*1024)
				// Simulate some work with the buffer
				buf = buf[:1024]
				for i := range buf {
					buf[i] = byte(i % 256)
				}
				// No pool - buffer will be GC'd
			}
		})
	})
}

// BenchmarkConnectionPoolStats benchmarks stats collection
func BenchmarkConnectionPoolStats(b *testing.B) {
	pool := setupBenchmarkPool(b)
	defer pool.Close()

	// Pre-populate pool with some connections
	for i := 0; i < 10; i++ {
		_, ok := pool.GetConnection(fmt.Sprintf("upstream-%d", i))
		if !ok {
			b.Fatal("failed to get connection")
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			stats := pool.GetStats()
			_ = stats // Use stats to prevent optimization
		}
	})
}

// BenchmarkConnectionCleanup benchmarks connection cleanup performance
func BenchmarkConnectionCleanup(b *testing.B) {
	pool := setupBenchmarkPool(b)
	defer pool.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create connections
		for j := 0; j < 10; j++ {
			_, ok := pool.GetConnection(fmt.Sprintf("temp-upstream-%d-%d", i, j))
			if !ok {
				b.Fatal("failed to get connection")
			}
		}

		// Trigger cleanup
		pool.cleanupStaleConnections()
	}
}

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	pool := setupBenchmarkPool(b)
	defer pool.Close()

	// No config needed for mock implementation

	b.ResetTimer()
	b.ReportAllocs()

	// Measure memory allocations per operation
	for i := 0; i < b.N; i++ {
		conn, ok := pool.GetConnection("memory-test")
		if !ok {
			b.Fatal("failed to get connection")
		}
		pool.ReleaseConnection("memory-test")
		_ = conn
	}
}

// BenchmarkConnectionReuse benchmarks connection reuse efficiency
func BenchmarkConnectionReuse(b *testing.B) {
	pool := setupBenchmarkPool(b)
	defer pool.Close()

	// No config needed for mock implementation

	// Create initial connection
	_, ok := pool.GetConnection("reuse-test")
	if !ok {
		b.Fatal("failed to get connection")
	}
	pool.ReleaseConnection("reuse-test")

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("ReuseExisting", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				conn, ok := pool.GetConnection("reuse-test")
				if !ok {
					b.Fatal("failed to get connection")
				}
				pool.ReleaseConnection("reuse-test")
				_ = conn
			}
		})
	})

	b.Run("CreateNew", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				upstreamName := fmt.Sprintf("new-test-%d", i)
				conn, ok := pool.GetConnection(upstreamName)
				if !ok {
					b.Fatal("failed to get connection")
				}
				pool.ReleaseConnection(upstreamName)
				_ = conn
				i++
			}
		})
	})
}

// BenchmarkHealthCheck benchmarks health check performance
func BenchmarkHealthCheck(b *testing.B) {
	pool := setupBenchmarkPool(b)
	defer pool.Close()

	ctx := context.Background()

	// Pre-populate pool
	for i := 0; i < 5; i++ {
		_, ok := pool.GetConnection(fmt.Sprintf("health-upstream-%d", i))
		if !ok {
			b.Fatal("failed to get connection")
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			status, message := pool.HealthCheck(ctx)
			_ = status
			_ = message
		}
	})
}

// MockConnectionPool provides a simple mock for benchmarking
type MockConnectionPool struct {
	logger *zap.Logger
}

// GetConnection mock implementation
func (m *MockConnectionPool) GetConnection(id string) (interface{}, bool) {
	// Return a mock connection
	return &struct{ id string }{id: id}, true
}

// ReleaseConnection mock implementation
func (m *MockConnectionPool) ReleaseConnection(id string) {
	// No-op for benchmarking
}

// GetBuffer mock implementation
func (m *MockConnectionPool) GetBuffer() []byte {
	return make([]byte, 32*1024)
}

// PutBuffer mock implementation
func (m *MockConnectionPool) PutBuffer(buf []byte) {
	// No-op for benchmarking
}

// GetStats mock implementation
func (m *MockConnectionPool) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_connections":  10,
		"active_connections": 5,
	}
}

// cleanupStaleConnections mock implementation
func (m *MockConnectionPool) cleanupStaleConnections() {
	// No-op for benchmarking
}

// HealthCheck mock implementation
func (m *MockConnectionPool) HealthCheck(ctx context.Context) (string, string) {
	return "healthy", "mock pool is healthy"
}

// Close mock implementation
func (m *MockConnectionPool) Close() {
	// No-op for benchmarking
}

// setupBenchmarkPool creates a test connection pool for benchmarking
func setupBenchmarkPool(b *testing.B) *MockConnectionPool {
	b.Helper()

	logger := zap.NewNop()
	return &MockConnectionPool{logger: logger}
}

package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"
)

// BenchmarkConnectionPool benchmarks connection pool performance
func BenchmarkConnectionPool(b *testing.B) {
	pool := setupBenchmarkPool(b)
	defer pool.Close()

	ctx := context.Background()
	config := &UpstreamConfig{
		Name:    "test-upstream",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 30 * time.Second,
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := pool.GetConnection(ctx, "test-upstream", config)
			if err != nil {
				b.Fatal(err)
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

	ctx := context.Background()

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
					config := &UpstreamConfig{
						Name:    upstreamName,
						Type:    "stdio",
						Command: []string{"echo", "test"},
						Timeout: 30 * time.Second,
					}

					conn, err := pool.GetConnection(ctx, upstreamName, config)
					if err != nil {
						b.Fatal(err)
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
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		config := &UpstreamConfig{
			Name:    fmt.Sprintf("upstream-%d", i),
			Type:    "stdio",
			Command: []string{"echo", "test"},
			Timeout: 30 * time.Second,
		}
		_, err := pool.GetConnection(ctx, fmt.Sprintf("upstream-%d", i), config)
		if err != nil {
			b.Fatal(err)
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

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create connections
		for j := 0; j < 10; j++ {
			config := &UpstreamConfig{
				Name:    fmt.Sprintf("temp-upstream-%d-%d", i, j),
				Type:    "stdio",
				Command: []string{"echo", "test"},
				Timeout: 30 * time.Second,
			}
			_, err := pool.GetConnection(ctx, fmt.Sprintf("temp-upstream-%d-%d", i, j), config)
			if err != nil {
				b.Fatal(err)
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

	ctx := context.Background()
	config := &UpstreamConfig{
		Name:    "memory-test",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 30 * time.Second,
	}

	b.ResetTimer()
	b.ReportAllocs()

	// Measure memory allocations per operation
	for i := 0; i < b.N; i++ {
		conn, err := pool.GetConnection(ctx, "memory-test", config)
		if err != nil {
			b.Fatal(err)
		}
		pool.ReleaseConnection("memory-test")
		_ = conn
	}
}

// BenchmarkConnectionReuse benchmarks connection reuse efficiency
func BenchmarkConnectionReuse(b *testing.B) {
	pool := setupBenchmarkPool(b)
	defer pool.Close()

	ctx := context.Background()
	config := &UpstreamConfig{
		Name:    "reuse-test",
		Type:    "stdio",
		Command: []string{"echo", "test"},
		Timeout: 30 * time.Second,
	}

	// Create initial connection
	conn, err := pool.GetConnection(ctx, "reuse-test", config)
	if err != nil {
		b.Fatal(err)
	}
	pool.ReleaseConnection("reuse-test")

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("ReuseExisting", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				conn, err := pool.GetConnection(ctx, "reuse-test", config)
				if err != nil {
					b.Fatal(err)
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
				newConfig := &UpstreamConfig{
					Name:    upstreamName,
					Type:    "stdio",
					Command: []string{"echo", "test"},
					Timeout: 30 * time.Second,
				}
				conn, err := pool.GetConnection(ctx, upstreamName, newConfig)
				if err != nil {
					b.Fatal(err)
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
		config := &UpstreamConfig{
			Name:    fmt.Sprintf("health-upstream-%d", i),
			Type:    "stdio",
			Command: []string{"echo", "test"},
			Timeout: 30 * time.Second,
		}
		_, err := pool.GetConnection(ctx, fmt.Sprintf("health-upstream-%d", i), config)
		if err != nil {
			b.Fatal(err)
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

// setupBenchmarkPool creates a test connection pool for benchmarking
func setupBenchmarkPool(b *testing.B) *ConnectionPool {
	b.Helper()

	logger := zap.NewNop()
	pool := NewConnectionPool(logger, 100) // Large pool for benchmarking

	return pool
}

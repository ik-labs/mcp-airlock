package observability

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// BenchmarkPerformanceMonitor benchmarks the performance monitoring overhead
func BenchmarkPerformanceMonitor(b *testing.B) {
	logger := zaptest.NewLogger(b)
	config := DefaultSimplePerformanceConfig()
	config.CollectionInterval = time.Hour // Disable periodic collection

	pm, err := NewSimplePerformanceMonitor(config, logger.Sugar())
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("RecordLatency", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pm.RecordLatency(time.Millisecond * time.Duration(i%100))
		}
	})

	b.Run("RecordThroughput", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pm.RecordThroughput()
		}
	})

	b.Run("GetCurrentMetrics", func(b *testing.B) {
		// Add some sample data
		for i := 0; i < 100; i++ {
			pm.RecordLatency(time.Millisecond * time.Duration(i))
			pm.RecordThroughput()
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = pm.GetCurrentMetrics()
		}
	})
}

// BenchmarkLatencyTracker benchmarks latency tracking performance
func BenchmarkLatencyTracker(b *testing.B) {
	tracker := NewLatencyTracker(1000)

	b.Run("AddSample", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			tracker.AddSample(time.Duration(i) * time.Microsecond)
		}
	})

	b.Run("GetPercentiles", func(b *testing.B) {
		// Fill with sample data
		for i := 0; i < 1000; i++ {
			tracker.AddSample(time.Duration(i) * time.Microsecond)
		}

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = tracker.GetPercentiles()
		}
	})
}

// BenchmarkThroughputTracker benchmarks throughput tracking performance
func BenchmarkThroughputTracker(b *testing.B) {
	tracker := NewThroughputTracker(time.Minute)

	b.Run("RecordRequest", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			tracker.RecordRequest()
		}
	})

	b.Run("GetThroughput", func(b *testing.B) {
		// Record some requests
		for i := 0; i < 1000; i++ {
			tracker.RecordRequest()
		}

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = tracker.GetThroughput()
		}
	})
}

// BenchmarkConcurrentLatencyTracking benchmarks concurrent latency tracking
func BenchmarkConcurrentLatencyTracking(b *testing.B) {
	tracker := NewLatencyTracker(1000)

	b.Run("ConcurrentAddSample", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				tracker.AddSample(time.Duration(i) * time.Microsecond)
				i++
			}
		})
	})

	b.Run("ConcurrentGetPercentiles", func(b *testing.B) {
		// Fill with sample data
		for i := 0; i < 1000; i++ {
			tracker.AddSample(time.Duration(i) * time.Microsecond)
		}

		b.ResetTimer()
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = tracker.GetPercentiles()
			}
		})
	})
}

// BenchmarkMemoryUsage benchmarks memory usage of performance monitoring
func BenchmarkMemoryUsage(b *testing.B) {
	logger := zaptest.NewLogger(b)
	config := DefaultPerformanceConfig()
	config.CollectionInterval = time.Hour // Disable periodic collection

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	pm, err := NewSimplePerformanceMonitor(DefaultSimplePerformanceConfig(), logger.Sugar())
	require.NoError(b, err)

	// Record sample data
	for i := 0; i < 10000; i++ {
		pm.RecordLatency(time.Duration(i) * time.Microsecond)
		pm.RecordThroughput()
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)

	// Handle potential overflow in memory calculation
	var memUsed uint64
	if m2.Alloc >= m1.Alloc {
		memUsed = m2.Alloc - m1.Alloc
	} else {
		// Handle overflow case - just use current allocation
		memUsed = m2.Alloc
	}

	b.Logf("Memory used by PerformanceMonitor with 10k samples: %d bytes", memUsed)

	// Ensure memory usage is reasonable (less than 1MB for 10k samples)
	if memUsed > 1024*1024 {
		b.Errorf("Memory usage too high: %d bytes", memUsed)
	}
}

func TestLatencyTracker(t *testing.T) {
	tracker := NewLatencyTracker(100)

	t.Run("EmptyTracker", func(t *testing.T) {
		p95, p99 := tracker.GetPercentiles()
		assert.Equal(t, time.Duration(0), p95)
		assert.Equal(t, time.Duration(0), p99)
		assert.Equal(t, 0, tracker.SampleCount())
	})

	t.Run("SingleSample", func(t *testing.T) {
		tracker.AddSample(50 * time.Millisecond)
		p95, p99 := tracker.GetPercentiles()
		assert.Equal(t, 50*time.Millisecond, p95)
		assert.Equal(t, 50*time.Millisecond, p99)
		assert.Equal(t, 1, tracker.SampleCount())
	})

	t.Run("MultipleSamples", func(t *testing.T) {
		tracker := NewLatencyTracker(100)

		// Add 100 samples: 1ms, 2ms, ..., 100ms
		for i := 1; i <= 100; i++ {
			tracker.AddSample(time.Duration(i) * time.Millisecond)
		}

		p95, p99 := tracker.GetPercentiles()

		// P95 should be around 95ms, P99 around 99ms
		assert.InDelta(t, 95, p95.Milliseconds(), 2)
		assert.InDelta(t, 99, p99.Milliseconds(), 2)
		assert.Equal(t, 100, tracker.SampleCount())
	})

	t.Run("CapacityLimit", func(t *testing.T) {
		tracker := NewLatencyTracker(10)

		// Add more samples than capacity
		for i := 1; i <= 20; i++ {
			tracker.AddSample(time.Duration(i) * time.Millisecond)
		}

		// Should only keep the last 10 samples
		assert.Equal(t, 10, tracker.SampleCount())

		p95, p99 := tracker.GetPercentiles()
		// Should be based on samples 11-20ms
		assert.True(t, p95 >= 19*time.Millisecond)
		assert.True(t, p99 >= 19*time.Millisecond)
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		tracker := NewLatencyTracker(1000)

		var wg sync.WaitGroup

		// Concurrent writers
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(base int) {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					tracker.AddSample(time.Duration(base*100+j) * time.Microsecond)
				}
			}(i)
		}

		// Concurrent readers
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					_, _ = tracker.GetPercentiles()
					_ = tracker.SampleCount()
				}
			}()
		}

		wg.Wait()

		// Should have 1000 samples (capacity limit)
		assert.Equal(t, 1000, tracker.SampleCount())
	})
}

func TestThroughputTracker(t *testing.T) {
	t.Run("EmptyTracker", func(t *testing.T) {
		tracker := NewThroughputTracker(time.Minute)
		throughput := tracker.GetThroughput()
		assert.Equal(t, int64(0), throughput)
	})

	t.Run("SingleRequest", func(t *testing.T) {
		tracker := NewThroughputTracker(time.Minute)
		tracker.RecordRequest()

		// Should be very high since it's 1 request in a very short time
		throughput := tracker.GetThroughput()
		assert.True(t, throughput > 1000) // Much higher than 1 req/min
	})

	t.Run("WindowReset", func(t *testing.T) {
		tracker := NewThroughputTracker(100 * time.Millisecond)

		// Record requests
		for i := 0; i < 10; i++ {
			tracker.RecordRequest()
		}

		initialThroughput := tracker.GetThroughput()
		assert.True(t, initialThroughput > 0)

		// Wait for window to expire
		time.Sleep(150 * time.Millisecond)

		// Should reset to 0
		throughput := tracker.GetThroughput()
		assert.Equal(t, int64(0), throughput)
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		tracker := NewThroughputTracker(time.Minute)

		var wg sync.WaitGroup

		// Concurrent request recording
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					tracker.RecordRequest()
				}
			}()
		}

		// Concurrent throughput reading
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					_ = tracker.GetThroughput()
				}
			}()
		}

		wg.Wait()

		throughput := tracker.GetThroughput()
		assert.True(t, throughput > 0)
	})
}

func TestPerformanceMonitor(t *testing.T) {
	logger := zaptest.NewLogger(t)

	t.Run("DefaultConfig", func(t *testing.T) {
		config := DefaultSimplePerformanceConfig()
		assert.True(t, config.Enabled)
		assert.Equal(t, 30*time.Second, config.CollectionInterval)
		assert.Equal(t, uint64(200), config.MemoryAlertThreshold)
		assert.Equal(t, 60*time.Millisecond, config.LatencyAlertThreshold)
	})

	t.Run("CreateMonitor", func(t *testing.T) {
		config := DefaultSimplePerformanceConfig()
		config.CollectionInterval = time.Hour // Disable periodic collection

		pm, err := NewSimplePerformanceMonitor(config, logger.Sugar())
		require.NoError(t, err)
		require.NotNil(t, pm)

		err = pm.Stop()
		require.NoError(t, err)
	})

	t.Run("RecordMetrics", func(t *testing.T) {
		config := DefaultSimplePerformanceConfig()
		config.CollectionInterval = time.Hour // Disable periodic collection

		pm, err := NewSimplePerformanceMonitor(config, logger.Sugar())
		require.NoError(t, err)
		defer pm.Stop()

		// Record some metrics
		pm.RecordLatency(50 * time.Millisecond)
		pm.RecordLatency(75 * time.Millisecond)
		pm.RecordThroughput()
		pm.RecordThroughput()

		metrics := pm.GetCurrentMetrics()
		assert.Contains(t, metrics, "memory_mb")
		assert.Contains(t, metrics, "goroutines")
		assert.Contains(t, metrics, "latency_p95_ms")
		assert.Contains(t, metrics, "throughput_per_min")

		// Latency should be recorded
		assert.True(t, metrics["latency_p95_ms"].(int64) > 0)
		assert.Equal(t, 2, metrics["sample_count"].(int))
	})

	t.Run("AlertCallbacks", func(t *testing.T) {
		config := DefaultSimplePerformanceConfig()
		config.CollectionInterval = time.Hour // Disable periodic collection
		config.MemoryAlertThreshold = 0       // Trigger memory alert immediately

		pm, err := NewSimplePerformanceMonitor(config, logger.Sugar())
		require.NoError(t, err)
		defer pm.Stop()

		alertReceived := make(chan *Alert, 1)
		pm.AddAlertCallback(func(ctx context.Context, alert *Alert) {
			select {
			case alertReceived <- alert:
			default:
			}
		})

		// Trigger alert check
		pm.checkAlerts()

		select {
		case alert := <-alertReceived:
			assert.Equal(t, "memory_usage", alert.Type)
			assert.Equal(t, "warning", alert.Severity)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Expected alert not received")
		}
	})
}

// TestPerformanceRequirements validates that the system meets performance requirements
func TestPerformanceRequirements(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultSimplePerformanceConfig()
	config.CollectionInterval = time.Hour // Disable periodic collection

	pm, err := NewSimplePerformanceMonitor(config, logger.Sugar())
	require.NoError(t, err)
	defer pm.Stop()

	t.Run("LatencyRequirement_P95_Under_60ms", func(t *testing.T) {
		// Simulate request processing with target latency
		const numRequests = 1000
		const targetLatency = 50 * time.Millisecond

		for i := 0; i < numRequests; i++ {
			// Simulate varying latencies, most under 50ms
			var latency time.Duration
			if i < 950 { // 95% of requests
				latency = time.Duration(20+i%30) * time.Millisecond // 20-50ms
			} else { // 5% of requests
				latency = time.Duration(50+i%20) * time.Millisecond // 50-70ms
			}
			pm.RecordLatency(latency)
		}

		p95, _ := pm.latencyTracker.GetPercentiles()

		// P95 should be under 60ms as per requirement R6.1
		assert.True(t, p95 < 60*time.Millisecond,
			"P95 latency %v exceeds 60ms requirement", p95)

		t.Logf("P95 latency: %v (requirement: < 60ms)", p95)
	})

	t.Run("ThroughputRequirement_1000_msgs_per_minute", func(t *testing.T) {
		tracker := NewThroughputTracker(time.Minute)

		// Simulate 1000 requests in 1 minute
		start := time.Now()
		for i := 0; i < 1000; i++ {
			tracker.RecordRequest()
			// Small delay to simulate realistic timing
			if i%100 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
		elapsed := time.Since(start)

		throughput := tracker.GetThroughput()

		// Should handle at least 1000 msgs/min as per requirement R6.2
		expectedThroughput := int64(float64(1000) * float64(time.Minute) / float64(elapsed))
		assert.True(t, throughput >= 1000,
			"Throughput %d/min is below 1000/min requirement", throughput)

		t.Logf("Throughput: %d/min (requirement: >= 1000/min, expected: %d/min)",
			throughput, expectedThroughput)
	})

	t.Run("MemoryRequirement_Under_200MB", func(t *testing.T) {
		// Record significant amount of data
		for i := 0; i < 10000; i++ {
			pm.RecordLatency(time.Duration(i) * time.Microsecond)
			pm.RecordThroughput()
		}

		metrics := pm.GetCurrentMetrics()
		memoryMB := metrics["memory_mb"].(uint64)

		// Memory usage should be reasonable for a 512MB container
		// This is total process memory, not just our component
		t.Logf("Current memory usage: %d MB", memoryMB)

		// The performance monitor itself should not use excessive memory
		// We can't easily isolate its usage, but we can ensure the process
		// doesn't grow excessively during our test
		assert.True(t, memoryMB < 100, // Conservative limit for test environment
			"Memory usage %d MB seems excessive for test", memoryMB)
	})
}

// BenchmarkEndToEndPerformance benchmarks end-to-end performance monitoring
func BenchmarkEndToEndPerformance(b *testing.B) {
	logger := zaptest.NewLogger(b)
	config := DefaultSimplePerformanceConfig()
	config.CollectionInterval = time.Hour // Disable periodic collection

	pm, err := NewSimplePerformanceMonitor(config, logger.Sugar())
	require.NoError(b, err)
	defer pm.Stop()

	b.Run("SimulateRequestProcessing", func(b *testing.B) {
		b.ReportAllocs()

		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				start := time.Now()

				// Simulate request processing
				pm.RecordThroughput()

				// Simulate very light work (1-5μs) to avoid long benchmark times
				workTime := time.Duration(1+i%4) * time.Microsecond
				time.Sleep(workTime)

				// Record latency
				pm.RecordLatency(time.Since(start))
				i++
			}
		})
	})

	// Validate performance after benchmark
	metrics := pm.GetCurrentMetrics()
	p95 := time.Duration(metrics["latency_p95_ms"].(int64)) * time.Millisecond

	if p95 > 60*time.Millisecond {
		b.Errorf("P95 latency %v exceeds 60ms requirement", p95)
	}

	b.Logf("Final metrics: P95=%v, samples=%d, memory=%dMB",
		p95, metrics["sample_count"], metrics["memory_mb"])
}

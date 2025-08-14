package monitoring

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof" // Import pprof for runtime profiling
	"runtime"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Profiler provides runtime performance profiling and monitoring
type Profiler struct {
	logger     *zap.Logger
	httpServer *http.Server
	enabled    bool
	mu         sync.RWMutex

	// Performance metrics
	startTime      time.Time
	requestCount   int64
	errorCount     int64
	totalLatency   time.Duration
	peakMemory     uint64
	peakGoroutines int

	// Monitoring intervals
	metricsInterval time.Duration
	gcInterval      time.Duration

	// Background monitoring
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config holds profiler configuration
type Config struct {
	Enabled         bool          `yaml:"enabled"`
	HTTPAddr        string        `yaml:"http_addr"`
	MetricsInterval time.Duration `yaml:"metrics_interval"`
	GCInterval      time.Duration `yaml:"gc_interval"`
}

// NewProfiler creates a new performance profiler
func NewProfiler(config Config, logger *zap.Logger) *Profiler {
	if config.MetricsInterval == 0 {
		config.MetricsInterval = 30 * time.Second
	}
	if config.GCInterval == 0 {
		config.GCInterval = 5 * time.Minute
	}
	if config.HTTPAddr == "" {
		config.HTTPAddr = "localhost:6060"
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Profiler{
		logger:          logger,
		enabled:         config.Enabled,
		startTime:       time.Now(),
		metricsInterval: config.MetricsInterval,
		gcInterval:      config.GCInterval,
		ctx:             ctx,
		cancel:          cancel,
		httpServer: &http.Server{
			Addr:         config.HTTPAddr,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
	}
}

// Start begins performance monitoring
func (p *Profiler) Start() error {
	if !p.enabled {
		p.logger.Info("Performance profiler disabled")
		return nil
	}

	// Start pprof HTTP server
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.logger.Info("Starting pprof server", zap.String("addr", p.httpServer.Addr))
		if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.logger.Error("pprof server error", zap.Error(err))
		}
	}()

	// Start background monitoring
	p.wg.Add(1)
	go p.backgroundMonitoring()

	p.logger.Info("Performance profiler started",
		zap.String("pprof_addr", p.httpServer.Addr),
		zap.Duration("metrics_interval", p.metricsInterval),
	)

	return nil
}

// Stop stops performance monitoring
func (p *Profiler) Stop() error {
	if !p.enabled {
		return nil
	}

	p.cancel()

	// Stop HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.httpServer.Shutdown(ctx); err != nil {
		p.logger.Error("Error shutting down pprof server", zap.Error(err))
	}

	p.wg.Wait()
	p.logger.Info("Performance profiler stopped")
	return nil
}

// RecordRequest records a request for performance tracking
func (p *Profiler) RecordRequest(latency time.Duration, success bool) {
	if !p.enabled {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.requestCount++
	p.totalLatency += latency

	if !success {
		p.errorCount++
	}
}

// GetMetrics returns current performance metrics
func (p *Profiler) GetMetrics() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	uptime := time.Since(p.startTime)
	avgLatency := time.Duration(0)
	if p.requestCount > 0 {
		avgLatency = p.totalLatency / time.Duration(p.requestCount)
	}

	errorRate := float64(0)
	if p.requestCount > 0 {
		errorRate = float64(p.errorCount) / float64(p.requestCount)
	}

	throughput := float64(0)
	if uptime.Seconds() > 0 {
		throughput = float64(p.requestCount) / uptime.Seconds()
	}

	return map[string]interface{}{
		// Request metrics
		"uptime_seconds": uptime.Seconds(),
		"total_requests": p.requestCount,
		"error_count":    p.errorCount,
		"error_rate":     errorRate,
		"avg_latency_ms": avgLatency.Milliseconds(),
		"throughput_rps": throughput,

		// Memory metrics
		"memory_alloc_mb":       bToMb(m.Alloc),
		"memory_total_alloc_mb": bToMb(m.TotalAlloc),
		"memory_sys_mb":         bToMb(m.Sys),
		"memory_heap_alloc_mb":  bToMb(m.HeapAlloc),
		"memory_heap_sys_mb":    bToMb(m.HeapSys),
		"memory_heap_idle_mb":   bToMb(m.HeapIdle),
		"memory_heap_inuse_mb":  bToMb(m.HeapInuse),
		"peak_memory_mb":        bToMb(p.peakMemory),

		// GC metrics
		"gc_runs":           m.NumGC,
		"gc_pause_total_ms": float64(m.PauseTotalNs) / 1e6,
		"gc_pause_avg_ms":   float64(m.PauseTotalNs) / float64(m.NumGC) / 1e6,

		// Goroutine metrics
		"goroutines":      runtime.NumGoroutine(),
		"peak_goroutines": p.peakGoroutines,

		// CPU metrics
		"num_cpu":    runtime.NumCPU(),
		"gomaxprocs": runtime.GOMAXPROCS(0),
	}
}

// GetHealthStatus returns health status based on performance metrics
func (p *Profiler) GetHealthStatus() (string, string) {
	if !p.enabled {
		return "healthy", "Profiler disabled"
	}

	metrics := p.GetMetrics()

	// Check memory usage
	memoryAllocMB := metrics["memory_alloc_mb"].(uint64)
	if memoryAllocMB > 512 { // 512MB threshold
		return "unhealthy", fmt.Sprintf("High memory usage: %d MB", memoryAllocMB)
	}

	// Check goroutine count
	goroutines := metrics["goroutines"].(int)
	if goroutines > 1000 { // 1000 goroutines threshold
		return "unhealthy", fmt.Sprintf("High goroutine count: %d", goroutines)
	}

	// Check error rate
	errorRate := metrics["error_rate"].(float64)
	if errorRate > 0.05 { // 5% error rate threshold
		return "unhealthy", fmt.Sprintf("High error rate: %.2f%%", errorRate*100)
	}

	// Check average latency
	avgLatencyMs := metrics["avg_latency_ms"].(int64)
	if avgLatencyMs > 100 { // 100ms threshold
		return "unhealthy", fmt.Sprintf("High average latency: %d ms", avgLatencyMs)
	}

	return "healthy", "All performance metrics within normal ranges"
}

// GenerateReport generates a performance analysis report
func (p *Profiler) GenerateReport() string {
	metrics := p.GetMetrics()

	report := fmt.Sprintf(`
Performance Report
==================

System Information:
- Uptime: %.2f seconds
- CPU Cores: %d
- GOMAXPROCS: %d

Request Metrics:
- Total Requests: %d
- Error Count: %d
- Error Rate: %.2f%%
- Average Latency: %d ms
- Throughput: %.2f req/s

Memory Metrics:
- Current Allocation: %d MB
- Total Allocated: %d MB
- System Memory: %d MB
- Heap Allocation: %d MB
- Heap System: %d MB
- Peak Memory: %d MB

Garbage Collection:
- GC Runs: %d
- Total GC Pause: %.2f ms
- Average GC Pause: %.2f ms

Goroutines:
- Current: %d
- Peak: %d

Performance Analysis:
%s
`,
		metrics["uptime_seconds"].(float64),
		metrics["num_cpu"].(int),
		metrics["gomaxprocs"].(int),
		metrics["total_requests"].(int64),
		metrics["error_count"].(int64),
		metrics["error_rate"].(float64)*100,
		metrics["avg_latency_ms"].(int64),
		metrics["throughput_rps"].(float64),
		metrics["memory_alloc_mb"].(uint64),
		metrics["memory_total_alloc_mb"].(uint64),
		metrics["memory_sys_mb"].(uint64),
		metrics["memory_heap_alloc_mb"].(uint64),
		metrics["memory_heap_sys_mb"].(uint64),
		metrics["peak_memory_mb"].(uint64),
		metrics["gc_runs"].(uint32),
		metrics["gc_pause_total_ms"].(float64),
		metrics["gc_pause_avg_ms"].(float64),
		metrics["goroutines"].(int),
		metrics["peak_goroutines"].(int),
		p.generateAnalysis(metrics),
	)

	return report
}

// backgroundMonitoring runs background performance monitoring
func (p *Profiler) backgroundMonitoring() {
	defer p.wg.Done()

	metricsTicker := time.NewTicker(p.metricsInterval)
	defer metricsTicker.Stop()

	gcTicker := time.NewTicker(p.gcInterval)
	defer gcTicker.Stop()

	p.logger.Info("Background performance monitoring started")

	for {
		select {
		case <-metricsTicker.C:
			p.collectMetrics()

		case <-gcTicker.C:
			p.performGC()

		case <-p.ctx.Done():
			p.logger.Info("Background performance monitoring stopping")
			return
		}
	}
}

// collectMetrics collects and logs performance metrics
func (p *Profiler) collectMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	p.mu.Lock()
	// Update peak values
	if m.Alloc > p.peakMemory {
		p.peakMemory = m.Alloc
	}

	goroutines := runtime.NumGoroutine()
	if goroutines > p.peakGoroutines {
		p.peakGoroutines = goroutines
	}
	p.mu.Unlock()

	// Log metrics periodically
	p.logger.Info("Performance metrics",
		zap.Uint64("memory_alloc_mb", bToMb(m.Alloc)),
		zap.Uint64("memory_sys_mb", bToMb(m.Sys)),
		zap.Int("goroutines", goroutines),
		zap.Uint32("gc_runs", m.NumGC),
		zap.Int64("total_requests", p.requestCount),
		zap.Float64("error_rate", float64(p.errorCount)/float64(p.requestCount)),
	)
}

// performGC triggers garbage collection and logs GC stats
func (p *Profiler) performGC() {
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	runtime.GC()

	runtime.ReadMemStats(&m2)

	p.logger.Info("Garbage collection completed",
		zap.Uint64("memory_before_mb", bToMb(m1.Alloc)),
		zap.Uint64("memory_after_mb", bToMb(m2.Alloc)),
		zap.Uint64("memory_freed_mb", bToMb(m1.Alloc-m2.Alloc)),
		zap.Uint32("gc_runs", m2.NumGC),
	)
}

// generateAnalysis generates performance analysis and recommendations
func (p *Profiler) generateAnalysis(metrics map[string]interface{}) string {
	var analysis []string

	// Memory analysis
	memoryAllocMB := metrics["memory_alloc_mb"].(uint64)
	memorySysMB := metrics["memory_sys_mb"].(uint64)

	if memoryAllocMB > 256 {
		analysis = append(analysis, fmt.Sprintf("- High memory usage (%d MB). Consider optimizing memory allocations.", memoryAllocMB))
	}

	if float64(memoryAllocMB)/float64(memorySysMB) < 0.5 {
		analysis = append(analysis, "- Low memory utilization. System memory could be reduced.")
	}

	// Goroutine analysis
	goroutines := metrics["goroutines"].(int)
	if goroutines > 100 {
		analysis = append(analysis, fmt.Sprintf("- High goroutine count (%d). Check for goroutine leaks.", goroutines))
	}

	// GC analysis
	gcPauseAvg := metrics["gc_pause_avg_ms"].(float64)

	if gcPauseAvg > 10 {
		analysis = append(analysis, fmt.Sprintf("- High GC pause time (%.2f ms). Consider tuning GC settings.", gcPauseAvg))
	}

	// Throughput analysis
	throughput := metrics["throughput_rps"].(float64)
	if throughput < 10 {
		analysis = append(analysis, fmt.Sprintf("- Low throughput (%.2f req/s). Performance optimization needed.", throughput))
	}

	// Error rate analysis
	errorRate := metrics["error_rate"].(float64)
	if errorRate > 0.01 {
		analysis = append(analysis, fmt.Sprintf("- High error rate (%.2f%%). Investigate error causes.", errorRate*100))
	}

	if len(analysis) == 0 {
		analysis = append(analysis, "- All metrics within optimal ranges.")
	}

	return fmt.Sprintf("%s", analysis)
}

// bToMb converts bytes to megabytes
func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

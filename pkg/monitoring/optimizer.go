package monitoring

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Optimizer provides automated performance optimization
type Optimizer struct {
	logger   *zap.Logger
	profiler *Profiler
	enabled  bool

	// Optimization settings
	gcTargetPercent    int
	maxGoroutines      int
	memoryThresholdMB  uint64
	latencyThresholdMs int64

	// Optimization state
	mu                sync.RWMutex
	lastOptimization  time.Time
	optimizationCount int64

	// Background optimization
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// OptimizerConfig holds optimizer configuration
type OptimizerConfig struct {
	Enabled              bool          `yaml:"enabled"`
	GCTargetPercent      int           `yaml:"gc_target_percent"`
	MaxGoroutines        int           `yaml:"max_goroutines"`
	MemoryThresholdMB    uint64        `yaml:"memory_threshold_mb"`
	LatencyThresholdMs   int64         `yaml:"latency_threshold_ms"`
	OptimizationInterval time.Duration `yaml:"optimization_interval"`
}

// OptimizationResult represents the result of an optimization
type OptimizationResult struct {
	Timestamp     time.Time              `json:"timestamp"`
	Type          string                 `json:"type"`
	Description   string                 `json:"description"`
	BeforeMetrics map[string]interface{} `json:"before_metrics"`
	AfterMetrics  map[string]interface{} `json:"after_metrics"`
	Success       bool                   `json:"success"`
	Error         string                 `json:"error,omitempty"`
}

// NewOptimizer creates a new performance optimizer
func NewOptimizer(config OptimizerConfig, profiler *Profiler, logger *zap.Logger) *Optimizer {
	if config.GCTargetPercent == 0 {
		config.GCTargetPercent = 100 // Default Go GC target
	}
	if config.MaxGoroutines == 0 {
		config.MaxGoroutines = 1000
	}
	if config.MemoryThresholdMB == 0 {
		config.MemoryThresholdMB = 512
	}
	if config.LatencyThresholdMs == 0 {
		config.LatencyThresholdMs = 100
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Optimizer{
		logger:             logger,
		profiler:           profiler,
		enabled:            config.Enabled,
		gcTargetPercent:    config.GCTargetPercent,
		maxGoroutines:      config.MaxGoroutines,
		memoryThresholdMB:  config.MemoryThresholdMB,
		latencyThresholdMs: config.LatencyThresholdMs,
		ctx:                ctx,
		cancel:             cancel,
	}
}

// Start begins automated optimization
func (o *Optimizer) Start() error {
	if !o.enabled {
		o.logger.Info("Performance optimizer disabled")
		return nil
	}

	// Start background optimization
	o.wg.Add(1)
	go o.backgroundOptimization()

	o.logger.Info("Performance optimizer started",
		zap.Int("gc_target_percent", o.gcTargetPercent),
		zap.Int("max_goroutines", o.maxGoroutines),
		zap.Uint64("memory_threshold_mb", o.memoryThresholdMB),
	)

	return nil
}

// Stop stops automated optimization
func (o *Optimizer) Stop() error {
	if !o.enabled {
		return nil
	}

	o.cancel()
	o.wg.Wait()
	o.logger.Info("Performance optimizer stopped")
	return nil
}

// OptimizeNow performs immediate optimization
func (o *Optimizer) OptimizeNow() []*OptimizationResult {
	if !o.enabled {
		return nil
	}

	var results []*OptimizationResult

	// Get current metrics
	beforeMetrics := o.profiler.GetMetrics()

	// Memory optimization
	if memResult := o.optimizeMemory(beforeMetrics); memResult != nil {
		results = append(results, memResult)
	}

	// GC optimization
	if gcResult := o.optimizeGC(beforeMetrics); gcResult != nil {
		results = append(results, gcResult)
	}

	// Goroutine optimization
	if goroutineResult := o.optimizeGoroutines(beforeMetrics); goroutineResult != nil {
		results = append(results, goroutineResult)
	}

	o.mu.Lock()
	o.lastOptimization = time.Now()
	o.optimizationCount += int64(len(results))
	o.mu.Unlock()

	if len(results) > 0 {
		o.logger.Info("Optimization completed",
			zap.Int("optimizations_applied", len(results)),
		)
	}

	return results
}

// GetOptimizationStats returns optimization statistics
func (o *Optimizer) GetOptimizationStats() map[string]interface{} {
	o.mu.RLock()
	defer o.mu.RUnlock()

	stats := map[string]interface{}{
		"enabled":              o.enabled,
		"optimization_count":   o.optimizationCount,
		"gc_target_percent":    o.gcTargetPercent,
		"max_goroutines":       o.maxGoroutines,
		"memory_threshold_mb":  o.memoryThresholdMB,
		"latency_threshold_ms": o.latencyThresholdMs,
	}

	if !o.lastOptimization.IsZero() {
		stats["last_optimization"] = o.lastOptimization
		stats["time_since_last_optimization"] = time.Since(o.lastOptimization)
	}

	return stats
}

// GenerateOptimizationRecommendations generates optimization recommendations
func (o *Optimizer) GenerateOptimizationRecommendations() []string {
	if !o.enabled {
		return []string{"Performance optimizer is disabled"}
	}

	metrics := o.profiler.GetMetrics()
	var recommendations []string

	// Memory recommendations
	memoryAllocMB := metrics["memory_alloc_mb"].(uint64)
	memorySysMB := metrics["memory_sys_mb"].(uint64)

	if memoryAllocMB > o.memoryThresholdMB {
		recommendations = append(recommendations,
			fmt.Sprintf("High memory usage (%d MB > %d MB threshold). Consider:\n"+
				"  - Implementing object pooling for frequently allocated objects\n"+
				"  - Reducing buffer sizes where possible\n"+
				"  - Adding memory profiling to identify allocation hotspots",
				memoryAllocMB, o.memoryThresholdMB))
	}

	memoryUtilization := float64(memoryAllocMB) / float64(memorySysMB)
	if memoryUtilization < 0.3 {
		recommendations = append(recommendations,
			fmt.Sprintf("Low memory utilization (%.1f%%). Consider:\n"+
				"  - Reducing GOMAXPROCS if running in containers\n"+
				"  - Tuning GC target percentage to reduce memory overhead",
				memoryUtilization*100))
	}

	// GC recommendations
	gcPauseAvg := metrics["gc_pause_avg_ms"].(float64)
	if gcPauseAvg > 10 {
		recommendations = append(recommendations,
			fmt.Sprintf("High GC pause time (%.2f ms). Consider:\n"+
				"  - Reducing GC target percentage (current: %d%%)\n"+
				"  - Implementing object pooling to reduce allocations\n"+
				"  - Using sync.Pool for temporary objects",
				gcPauseAvg, o.gcTargetPercent))
	}

	// Goroutine recommendations
	goroutines := metrics["goroutines"].(int)
	if goroutines > o.maxGoroutines {
		recommendations = append(recommendations,
			fmt.Sprintf("High goroutine count (%d > %d threshold). Consider:\n"+
				"  - Implementing worker pools to limit concurrent goroutines\n"+
				"  - Adding goroutine leak detection\n"+
				"  - Using context cancellation for proper cleanup",
				goroutines, o.maxGoroutines))
	}

	// Throughput recommendations
	throughput := metrics["throughput_rps"].(float64)
	if throughput < 50 {
		recommendations = append(recommendations,
			fmt.Sprintf("Low throughput (%.2f req/s). Consider:\n"+
				"  - Profiling CPU usage to identify bottlenecks\n"+
				"  - Implementing request batching where applicable\n"+
				"  - Optimizing critical path algorithms\n"+
				"  - Adding caching for frequently accessed data",
				throughput))
	}

	// Error rate recommendations
	errorRate := metrics["error_rate"].(float64)
	if errorRate > 0.01 {
		recommendations = append(recommendations,
			fmt.Sprintf("High error rate (%.2f%%). Consider:\n"+
				"  - Implementing circuit breakers for external dependencies\n"+
				"  - Adding retry logic with exponential backoff\n"+
				"  - Improving error handling and logging\n"+
				"  - Adding health checks for dependencies",
				errorRate*100))
	}

	// Latency recommendations
	avgLatencyMs := metrics["avg_latency_ms"].(int64)
	if avgLatencyMs > o.latencyThresholdMs {
		recommendations = append(recommendations,
			fmt.Sprintf("High average latency (%d ms > %d ms threshold). Consider:\n"+
				"  - Adding request tracing to identify slow operations\n"+
				"  - Implementing caching for expensive operations\n"+
				"  - Optimizing database queries and connections\n"+
				"  - Using connection pooling for external services",
				avgLatencyMs, o.latencyThresholdMs))
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "All performance metrics are within optimal ranges. No optimizations needed.")
	}

	return recommendations
}

// backgroundOptimization runs background optimization checks
func (o *Optimizer) backgroundOptimization() {
	defer o.wg.Done()

	ticker := time.NewTicker(5 * time.Minute) // Check every 5 minutes
	defer ticker.Stop()

	o.logger.Info("Background optimization started")

	for {
		select {
		case <-ticker.C:
			results := o.OptimizeNow()
			if len(results) > 0 {
				o.logger.Info("Background optimization applied",
					zap.Int("optimizations", len(results)),
				)
			}

		case <-o.ctx.Done():
			o.logger.Info("Background optimization stopping")
			return
		}
	}
}

// optimizeMemory performs memory optimization
func (o *Optimizer) optimizeMemory(beforeMetrics map[string]interface{}) *OptimizationResult {
	memoryAllocMB := beforeMetrics["memory_alloc_mb"].(uint64)

	if memoryAllocMB <= o.memoryThresholdMB {
		return nil // No optimization needed
	}

	result := &OptimizationResult{
		Timestamp:     time.Now(),
		Type:          "memory",
		BeforeMetrics: beforeMetrics,
	}

	// Force garbage collection
	runtime.GC()
	runtime.GC() // Run twice for better cleanup

	// Get after metrics
	afterMetrics := o.profiler.GetMetrics()
	result.AfterMetrics = afterMetrics

	memoryAfterMB := afterMetrics["memory_alloc_mb"].(uint64)
	memoryFreedMB := memoryAllocMB - memoryAfterMB

	result.Description = fmt.Sprintf("Forced garbage collection freed %d MB of memory", memoryFreedMB)
	result.Success = memoryFreedMB > 0

	return result
}

// optimizeGC performs garbage collection optimization
func (o *Optimizer) optimizeGC(beforeMetrics map[string]interface{}) *OptimizationResult {
	gcPauseAvg := beforeMetrics["gc_pause_avg_ms"].(float64)

	if gcPauseAvg <= 10 { // 10ms threshold
		return nil // No optimization needed
	}

	result := &OptimizationResult{
		Timestamp:     time.Now(),
		Type:          "gc",
		BeforeMetrics: beforeMetrics,
	}

	// Adjust GC target percentage to reduce pause times
	currentTarget := debug.SetGCPercent(-1)        // Get current value
	newTarget := int(float64(currentTarget) * 0.8) // Reduce by 20%

	if newTarget < 50 {
		newTarget = 50 // Minimum target
	}

	debug.SetGCPercent(newTarget)

	result.Description = fmt.Sprintf("Adjusted GC target from %d%% to %d%% to reduce pause times", currentTarget, newTarget)
	result.Success = true

	// Update internal tracking
	o.mu.Lock()
	o.gcTargetPercent = newTarget
	o.mu.Unlock()

	// Get after metrics (may not show immediate improvement)
	result.AfterMetrics = o.profiler.GetMetrics()

	return result
}

// optimizeGoroutines performs goroutine optimization
func (o *Optimizer) optimizeGoroutines(beforeMetrics map[string]interface{}) *OptimizationResult {
	goroutines := beforeMetrics["goroutines"].(int)

	if goroutines <= o.maxGoroutines {
		return nil // No optimization needed
	}

	result := &OptimizationResult{
		Timestamp:     time.Now(),
		Type:          "goroutines",
		BeforeMetrics: beforeMetrics,
	}

	// Log warning about high goroutine count
	// In a real implementation, this might trigger alerts or automatic scaling
	result.Description = fmt.Sprintf("High goroutine count detected (%d > %d). Manual investigation recommended.", goroutines, o.maxGoroutines)
	result.Success = false
	result.Error = "Automatic goroutine optimization not implemented - requires manual investigation"

	result.AfterMetrics = o.profiler.GetMetrics()

	return result
}

// TuneForLatency optimizes settings for low latency
func (o *Optimizer) TuneForLatency() error {
	if !o.enabled {
		return fmt.Errorf("optimizer is disabled")
	}

	o.logger.Info("Tuning for low latency")

	// Reduce GC target to minimize pause times
	debug.SetGCPercent(50)

	// Set GOMAXPROCS to number of CPUs for better scheduling
	runtime.GOMAXPROCS(runtime.NumCPU())

	o.mu.Lock()
	o.gcTargetPercent = 50
	o.mu.Unlock()

	o.logger.Info("Latency tuning applied",
		zap.Int("gc_target_percent", 50),
		zap.Int("gomaxprocs", runtime.NumCPU()),
	)

	return nil
}

// TuneForThroughput optimizes settings for high throughput
func (o *Optimizer) TuneForThroughput() error {
	if !o.enabled {
		return fmt.Errorf("optimizer is disabled")
	}

	o.logger.Info("Tuning for high throughput")

	// Increase GC target to reduce GC frequency
	debug.SetGCPercent(200)

	// Allow more goroutines for higher concurrency
	o.mu.Lock()
	o.gcTargetPercent = 200
	o.maxGoroutines = 2000
	o.mu.Unlock()

	o.logger.Info("Throughput tuning applied",
		zap.Int("gc_target_percent", 200),
		zap.Int("max_goroutines", 2000),
	)

	return nil
}

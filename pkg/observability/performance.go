// Package observability provides performance monitoring and alerting for MCP Airlock
package observability

import (
	"context"
	"runtime"
	"sync"
	"time"

	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
)

// PerformanceConfig holds configuration for performance monitoring
type PerformanceConfig struct {
	Enabled               bool          `yaml:"enabled"`
	CollectionInterval    time.Duration `yaml:"collection_interval"`
	MemoryAlertThreshold  uint64        `yaml:"memory_alert_threshold_mb"`
	LatencyAlertThreshold time.Duration `yaml:"latency_alert_threshold"`
	ThroughputAlertMin    int64         `yaml:"throughput_alert_min_per_minute"`
	GCAlertThreshold      time.Duration `yaml:"gc_alert_threshold"`
	GoroutineAlertMax     int           `yaml:"goroutine_alert_max"`
}

// DefaultPerformanceConfig returns default performance monitoring configuration
func DefaultPerformanceConfig() *PerformanceConfig {
	return &PerformanceConfig{
		Enabled:               true,
		CollectionInterval:    30 * time.Second,
		MemoryAlertThreshold:  200, // 200MB for 512MB container
		LatencyAlertThreshold: 60 * time.Millisecond,
		ThroughputAlertMin:    1000, // 1000 msgs/min minimum
		GCAlertThreshold:      100 * time.Millisecond,
		GoroutineAlertMax:     1000,
	}
}

// PerformanceMonitor provides runtime performance monitoring and alerting
type PerformanceMonitor struct {
	config    *PerformanceConfig
	logger    *zap.Logger
	telemetry *Telemetry

	// Metrics instruments
	memoryUsage    metric.Int64UpDownCounter
	gcDuration     metric.Float64Histogram
	goroutineCount metric.Int64UpDownCounter
	heapObjects    metric.Int64UpDownCounter
	cpuUsage       metric.Float64Gauge
	latencyP95     metric.Float64Gauge
	latencyP99     metric.Float64Gauge
	throughput     metric.Int64Counter

	// Performance tracking
	latencyTracker    *LatencyTracker
	throughputTracker *ThroughputTracker

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Alert callbacks
	alertCallbacks []AlertCallback
}

// AlertCallback defines the signature for alert callbacks
type AlertCallback func(ctx context.Context, alert *Alert)

// Alert represents a performance alert
type Alert struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Message     string                 `json:"message"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
	Threshold   interface{}            `json:"threshold"`
	ActualValue interface{}            `json:"actual_value"`
}

// LatencyTracker tracks request latency percentiles
type LatencyTracker struct {
	mu         sync.RWMutex
	samples    []time.Duration
	maxSamples int
	lastReset  time.Time
}

// ThroughputTracker tracks request throughput
type ThroughputTracker struct {
	mu           sync.RWMutex
	requestCount int64
	windowStart  time.Time
	windowSize   time.Duration
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(config *PerformanceConfig, logger *zap.Logger, telemetry *Telemetry) (*PerformanceMonitor, error) {
	if config == nil {
		config = DefaultPerformanceConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	pm := &PerformanceMonitor{
		config:            config,
		logger:            logger,
		telemetry:         telemetry,
		ctx:               ctx,
		cancel:            cancel,
		latencyTracker:    NewLatencyTracker(1000), // Keep last 1000 samples
		throughputTracker: NewThroughputTracker(time.Minute),
		alertCallbacks:    make([]AlertCallback, 0),
	}

	// Initialize metrics if telemetry is available
	if telemetry != nil && telemetry.meter != nil {
		if err := pm.initMetrics(); err != nil {
			cancel()
			return nil, err
		}
	}

	return pm, nil
}

// initMetrics initializes performance monitoring metrics
func (pm *PerformanceMonitor) initMetrics() error {
	var err error

	// Memory usage gauge
	pm.memoryUsage, err = pm.telemetry.meter.Int64UpDownCounter(
		"airlock_memory_usage_bytes",
		metric.WithDescription("Current memory usage in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return err
	}

	// GC duration histogram
	pm.gcDuration, err = pm.telemetry.meter.Float64Histogram(
		"airlock_gc_duration_seconds",
		metric.WithDescription("Garbage collection duration"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
	)
	if err != nil {
		return err
	}

	// Goroutine count gauge
	pm.goroutineCount, err = pm.telemetry.meter.Int64UpDownCounter(
		"airlock_goroutines_total",
		metric.WithDescription("Number of active goroutines"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	// Heap objects gauge
	pm.heapObjects, err = pm.telemetry.meter.Int64UpDownCounter(
		"airlock_heap_objects_total",
		metric.WithDescription("Number of objects in heap"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	// CPU usage gauge
	pm.cpuUsage, err = pm.telemetry.meter.Float64Gauge(
		"airlock_cpu_usage_percent",
		metric.WithDescription("CPU usage percentage"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	// Latency percentile gauges
	pm.latencyP95, err = pm.telemetry.meter.Float64Gauge(
		"airlock_latency_p95_seconds",
		metric.WithDescription("95th percentile request latency"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	pm.latencyP99, err = pm.telemetry.meter.Float64Gauge(
		"airlock_latency_p99_seconds",
		metric.WithDescription("99th percentile request latency"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	// Throughput counter
	pm.throughput, err = pm.telemetry.meter.Int64Counter(
		"airlock_throughput_requests_per_minute",
		metric.WithDescription("Request throughput per minute"),
		metric.WithUnit("1/min"),
	)
	if err != nil {
		return err
	}

	return nil
}

// Start begins performance monitoring
func (pm *PerformanceMonitor) Start() error {
	if !pm.config.Enabled {
		pm.logger.Info("Performance monitoring disabled")
		return nil
	}

	pm.wg.Add(1)
	go pm.monitoringLoop()

	pm.logger.Info("Performance monitoring started",
		zap.Duration("collection_interval", pm.config.CollectionInterval),
		zap.Uint64("memory_alert_threshold_mb", pm.config.MemoryAlertThreshold),
		zap.Duration("latency_alert_threshold", pm.config.LatencyAlertThreshold),
	)

	return nil
}

// Stop stops performance monitoring
func (pm *PerformanceMonitor) Stop() error {
	pm.cancel()
	pm.wg.Wait()

	pm.logger.Info("Performance monitoring stopped")
	return nil
}

// AddAlertCallback adds a callback for performance alerts
func (pm *PerformanceMonitor) AddAlertCallback(callback AlertCallback) {
	pm.alertCallbacks = append(pm.alertCallbacks, callback)
}

// RecordLatency records a request latency sample
func (pm *PerformanceMonitor) RecordLatency(latency time.Duration) {
	pm.latencyTracker.AddSample(latency)
}

// RecordThroughput records a request for throughput calculation
func (pm *PerformanceMonitor) RecordThroughput() {
	pm.throughputTracker.RecordRequest()
}

// monitoringLoop runs the main monitoring loop
func (pm *PerformanceMonitor) monitoringLoop() {
	defer pm.wg.Done()

	ticker := time.NewTicker(pm.config.CollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.collectMetrics()
			pm.checkAlerts()
		}
	}
}

// collectMetrics collects runtime performance metrics
func (pm *PerformanceMonitor) collectMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	ctx := pm.ctx

	// Memory metrics
	if pm.memoryUsage != nil {
		pm.memoryUsage.Add(ctx, int64(m.Alloc))
	}

	// Heap objects
	if pm.heapObjects != nil {
		pm.heapObjects.Add(ctx, int64(m.HeapObjects))
	}

	// Goroutine count
	if pm.goroutineCount != nil {
		pm.goroutineCount.Add(ctx, int64(runtime.NumGoroutine()))
	}

	// GC metrics
	if pm.gcDuration != nil && len(m.PauseNs) > 0 {
		// Get the most recent GC pause
		lastGC := time.Duration(m.PauseNs[(m.NumGC+255)%256])
		pm.gcDuration.Record(ctx, lastGC.Seconds())
	}

	// Latency percentiles
	p95, p99 := pm.latencyTracker.GetPercentiles()
	if pm.latencyP95 != nil {
		pm.latencyP95.Record(ctx, p95.Seconds())
	}
	if pm.latencyP99 != nil {
		pm.latencyP99.Record(ctx, p99.Seconds())
	}

	// Throughput
	throughput := pm.throughputTracker.GetThroughput()
	if pm.throughput != nil {
		pm.throughput.Add(ctx, throughput)
	}

	// Log performance summary
	pm.logger.Debug("Performance metrics collected",
		zap.Uint64("memory_mb", m.Alloc/(1024*1024)),
		zap.Uint64("heap_objects", m.HeapObjects),
		zap.Int("goroutines", runtime.NumGoroutine()),
		zap.Duration("gc_pause", time.Duration(m.PauseNs[(m.NumGC+255)%256])),
		zap.Duration("latency_p95", p95),
		zap.Duration("latency_p99", p99),
		zap.Int64("throughput_per_min", throughput),
	)
}

// checkAlerts checks for performance threshold violations
func (pm *PerformanceMonitor) checkAlerts() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Memory usage alert
	memoryMB := m.Alloc / (1024 * 1024)
	if memoryMB > pm.config.MemoryAlertThreshold {
		pm.sendAlert(&Alert{
			Type:        "memory_usage",
			Severity:    "warning",
			Message:     "Memory usage exceeds threshold",
			Timestamp:   time.Now(),
			Threshold:   pm.config.MemoryAlertThreshold,
			ActualValue: memoryMB,
			Metadata: map[string]interface{}{
				"heap_objects": m.HeapObjects,
				"heap_size_mb": m.HeapSys / (1024 * 1024),
			},
		})
	}

	// Latency alert
	p95, _ := pm.latencyTracker.GetPercentiles()
	if p95 > pm.config.LatencyAlertThreshold {
		pm.sendAlert(&Alert{
			Type:        "latency_high",
			Severity:    "warning",
			Message:     "P95 latency exceeds threshold",
			Timestamp:   time.Now(),
			Threshold:   pm.config.LatencyAlertThreshold,
			ActualValue: p95,
			Metadata: map[string]interface{}{
				"sample_count": pm.latencyTracker.SampleCount(),
			},
		})
	}

	// Throughput alert
	throughput := pm.throughputTracker.GetThroughput()
	if throughput < pm.config.ThroughputAlertMin {
		pm.sendAlert(&Alert{
			Type:        "throughput_low",
			Severity:    "warning",
			Message:     "Throughput below minimum threshold",
			Timestamp:   time.Now(),
			Threshold:   pm.config.ThroughputAlertMin,
			ActualValue: throughput,
			Metadata: map[string]interface{}{
				"window_size": pm.throughputTracker.windowSize.String(),
			},
		})
	}

	// GC pause alert
	if len(m.PauseNs) > 0 {
		lastGC := time.Duration(m.PauseNs[(m.NumGC+255)%256])
		if lastGC > pm.config.GCAlertThreshold {
			pm.sendAlert(&Alert{
				Type:        "gc_pause_high",
				Severity:    "warning",
				Message:     "GC pause time exceeds threshold",
				Timestamp:   time.Now(),
				Threshold:   pm.config.GCAlertThreshold,
				ActualValue: lastGC,
				Metadata: map[string]interface{}{
					"gc_count":     m.NumGC,
					"heap_size_mb": m.HeapSys / (1024 * 1024),
				},
			})
		}
	}

	// Goroutine count alert
	goroutines := runtime.NumGoroutine()
	if goroutines > pm.config.GoroutineAlertMax {
		pm.sendAlert(&Alert{
			Type:        "goroutine_count_high",
			Severity:    "warning",
			Message:     "Goroutine count exceeds threshold",
			Timestamp:   time.Now(),
			Threshold:   pm.config.GoroutineAlertMax,
			ActualValue: goroutines,
			Metadata: map[string]interface{}{
				"memory_mb": memoryMB,
			},
		})
	}
}

// sendAlert sends an alert to all registered callbacks
func (pm *PerformanceMonitor) sendAlert(alert *Alert) {
	pm.logger.Warn("Performance alert triggered",
		zap.String("type", alert.Type),
		zap.String("severity", alert.Severity),
		zap.String("message", alert.Message),
		zap.Any("threshold", alert.Threshold),
		zap.Any("actual_value", alert.ActualValue),
		zap.Any("metadata", alert.Metadata),
	)

	// Send to all callbacks
	for _, callback := range pm.alertCallbacks {
		go func(cb AlertCallback) {
			defer func() {
				if r := recover(); r != nil {
					pm.logger.Error("Alert callback panicked", zap.Any("panic", r))
				}
			}()
			cb(pm.ctx, alert)
		}(callback)
	}
}

// GetCurrentMetrics returns current performance metrics
func (pm *PerformanceMonitor) GetCurrentMetrics() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	p95, p99 := pm.latencyTracker.GetPercentiles()
	throughput := pm.throughputTracker.GetThroughput()

	return map[string]interface{}{
		"memory_mb":          m.Alloc / (1024 * 1024),
		"heap_objects":       m.HeapObjects,
		"goroutines":         runtime.NumGoroutine(),
		"gc_pause_ns":        m.PauseNs[(m.NumGC+255)%256],
		"latency_p95_ms":     p95.Nanoseconds() / 1e6,
		"latency_p99_ms":     p99.Nanoseconds() / 1e6,
		"throughput_per_min": throughput,
		"sample_count":       pm.latencyTracker.SampleCount(),
	}
}

// NewLatencyTracker creates a new latency tracker
func NewLatencyTracker(maxSamples int) *LatencyTracker {
	return &LatencyTracker{
		samples:    make([]time.Duration, 0, maxSamples),
		maxSamples: maxSamples,
		lastReset:  time.Now(),
	}
}

// AddSample adds a latency sample
func (lt *LatencyTracker) AddSample(latency time.Duration) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	// Reset samples every hour to prevent stale data
	if time.Since(lt.lastReset) > time.Hour {
		lt.samples = lt.samples[:0]
		lt.lastReset = time.Now()
	}

	// Add sample, removing oldest if at capacity
	if len(lt.samples) >= lt.maxSamples {
		copy(lt.samples, lt.samples[1:])
		lt.samples[len(lt.samples)-1] = latency
	} else {
		lt.samples = append(lt.samples, latency)
	}
}

// GetPercentiles calculates P95 and P99 latency percentiles
func (lt *LatencyTracker) GetPercentiles() (p95, p99 time.Duration) {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	if len(lt.samples) == 0 {
		return 0, 0
	}

	// Create a copy and sort
	sorted := make([]time.Duration, len(lt.samples))
	copy(sorted, lt.samples)

	// Simple insertion sort for small arrays
	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}

	// Calculate percentiles
	p95Index := int(float64(len(sorted)) * 0.95)
	p99Index := int(float64(len(sorted)) * 0.99)

	if p95Index >= len(sorted) {
		p95Index = len(sorted) - 1
	}
	if p99Index >= len(sorted) {
		p99Index = len(sorted) - 1
	}

	return sorted[p95Index], sorted[p99Index]
}

// SampleCount returns the current number of samples
func (lt *LatencyTracker) SampleCount() int {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	return len(lt.samples)
}

// NewThroughputTracker creates a new throughput tracker
func NewThroughputTracker(windowSize time.Duration) *ThroughputTracker {
	return &ThroughputTracker{
		windowStart: time.Now(),
		windowSize:  windowSize,
	}
}

// RecordRequest records a request for throughput calculation
func (tt *ThroughputTracker) RecordRequest() {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	now := time.Now()

	// Reset window if expired
	if now.Sub(tt.windowStart) > tt.windowSize {
		tt.requestCount = 0
		tt.windowStart = now
	}

	tt.requestCount++
}

// GetThroughput returns current throughput (requests per minute)
func (tt *ThroughputTracker) GetThroughput() int64 {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	elapsed := time.Since(tt.windowStart)
	if elapsed == 0 {
		return 0
	}

	// Convert to requests per minute
	return int64(float64(tt.requestCount) * float64(time.Minute) / float64(elapsed))
}

// Package observability provides simplified performance monitoring for MCP Airlock
package observability

import (
	"context"
	"runtime"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SimplePerformanceConfig holds configuration for simplified performance monitoring
type SimplePerformanceConfig struct {
	Enabled               bool          `yaml:"enabled"`
	CollectionInterval    time.Duration `yaml:"collection_interval"`
	MemoryAlertThreshold  uint64        `yaml:"memory_alert_threshold_mb"`
	LatencyAlertThreshold time.Duration `yaml:"latency_alert_threshold"`
	ThroughputAlertMin    int64         `yaml:"throughput_alert_min_per_minute"`
	GCAlertThreshold      time.Duration `yaml:"gc_alert_threshold"`
	GoroutineAlertMax     int           `yaml:"goroutine_alert_max"`
}

// DefaultSimplePerformanceConfig returns default performance monitoring configuration
func DefaultSimplePerformanceConfig() *SimplePerformanceConfig {
	return &SimplePerformanceConfig{
		Enabled:               true,
		CollectionInterval:    30 * time.Second,
		MemoryAlertThreshold:  200, // 200MB for 512MB container
		LatencyAlertThreshold: 60 * time.Millisecond,
		ThroughputAlertMin:    1000, // 1000 msgs/min minimum
		GCAlertThreshold:      100 * time.Millisecond,
		GoroutineAlertMax:     1000,
	}
}

// SimplePerformanceMonitor provides runtime performance monitoring without external dependencies
type SimplePerformanceMonitor struct {
	config *SimplePerformanceConfig
	logger *zap.SugaredLogger

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

// NewSimplePerformanceMonitor creates a new simplified performance monitor
func NewSimplePerformanceMonitor(config *SimplePerformanceConfig, logger *zap.SugaredLogger) (*SimplePerformanceMonitor, error) {
	if config == nil {
		config = DefaultSimplePerformanceConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	pm := &SimplePerformanceMonitor{
		config:            config,
		logger:            logger,
		ctx:               ctx,
		cancel:            cancel,
		latencyTracker:    NewLatencyTracker(1000), // Keep last 1000 samples
		throughputTracker: NewThroughputTracker(time.Minute),
		alertCallbacks:    make([]AlertCallback, 0),
	}

	return pm, nil
}

// Start begins performance monitoring
func (pm *SimplePerformanceMonitor) Start() error {
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
func (pm *SimplePerformanceMonitor) Stop() error {
	pm.cancel()
	pm.wg.Wait()

	pm.logger.Info("Performance monitoring stopped")
	return nil
}

// AddAlertCallback adds a callback for performance alerts
func (pm *SimplePerformanceMonitor) AddAlertCallback(callback AlertCallback) {
	pm.alertCallbacks = append(pm.alertCallbacks, callback)
}

// RecordLatency records a request latency sample
func (pm *SimplePerformanceMonitor) RecordLatency(latency time.Duration) {
	pm.latencyTracker.AddSample(latency)
}

// RecordThroughput records a request for throughput calculation
func (pm *SimplePerformanceMonitor) RecordThroughput() {
	pm.throughputTracker.RecordRequest()
}

// monitoringLoop runs the main monitoring loop
func (pm *SimplePerformanceMonitor) monitoringLoop() {
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
func (pm *SimplePerformanceMonitor) collectMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Latency percentiles
	p95, p99 := pm.latencyTracker.GetPercentiles()

	// Throughput
	throughput := pm.throughputTracker.GetThroughput()

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
func (pm *SimplePerformanceMonitor) checkAlerts() {
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
func (pm *SimplePerformanceMonitor) sendAlert(alert *Alert) {
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
func (pm *SimplePerformanceMonitor) GetCurrentMetrics() map[string]interface{} {
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

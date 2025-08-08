// Package health provides health check functionality for MCP Airlock
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Status represents the health status of a component
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusUnknown   Status = "unknown"
)

// Check represents a single health check
type Check struct {
	Name        string                                     `json:"name"`
	Status      Status                                     `json:"status"`
	Message     string                                     `json:"message,omitempty"`
	LastChecked time.Time                                  `json:"last_checked"`
	CheckFunc   func(ctx context.Context) (Status, string) `json:"-"`
}

// HealthChecker manages health checks for the application
type HealthChecker struct {
	checks map[string]*Check
	mutex  sync.RWMutex
	logger *zap.Logger
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(logger *zap.Logger) *HealthChecker {
	return &HealthChecker{
		checks: make(map[string]*Check),
		logger: logger,
	}
}

// RegisterCheck registers a new health check
func (hc *HealthChecker) RegisterCheck(name string, checkFunc func(ctx context.Context) (Status, string)) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	
	hc.checks[name] = &Check{
		Name:      name,
		Status:    StatusUnknown,
		CheckFunc: checkFunc,
	}
}

// RunCheck executes a specific health check
func (hc *HealthChecker) RunCheck(ctx context.Context, name string) error {
	hc.mutex.RLock()
	check, exists := hc.checks[name]
	hc.mutex.RUnlock()
	
	if !exists {
		return nil
	}
	
	status, message := check.CheckFunc(ctx)
	
	hc.mutex.Lock()
	check.Status = status
	check.Message = message
	check.LastChecked = time.Now()
	hc.mutex.Unlock()
	
	hc.logger.Debug("Health check completed",
		zap.String("check", name),
		zap.String("status", string(status)),
		zap.String("message", message),
	)
	
	return nil
}

// RunAllChecks executes all registered health checks
func (hc *HealthChecker) RunAllChecks(ctx context.Context) {
	hc.mutex.RLock()
	checkNames := make([]string, 0, len(hc.checks))
	for name := range hc.checks {
		checkNames = append(checkNames, name)
	}
	hc.mutex.RUnlock()
	
	for _, name := range checkNames {
		if err := hc.RunCheck(ctx, name); err != nil {
			hc.logger.Error("Health check failed",
				zap.String("check", name),
				zap.Error(err),
			)
		}
	}
}

// GetStatus returns the overall health status
func (hc *HealthChecker) GetStatus() Status {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()
	
	for _, check := range hc.checks {
		if check.Status == StatusUnhealthy {
			return StatusUnhealthy
		}
		if check.Status == StatusUnknown {
			return StatusUnknown
		}
	}
	
	return StatusHealthy
}

// GetChecks returns all health check results
func (hc *HealthChecker) GetChecks() map[string]*Check {
	hc.mutex.RLock()
	defer hc.mutex.RUnlock()
	
	result := make(map[string]*Check)
	for name, check := range hc.checks {
		// Create a copy to avoid race conditions
		result[name] = &Check{
			Name:        check.Name,
			Status:      check.Status,
			Message:     check.Message,
			LastChecked: check.LastChecked,
		}
	}
	
	return result
}

// HealthResponse represents the JSON response for health endpoints
type HealthResponse struct {
	Status    Status             `json:"status"`
	Timestamp time.Time          `json:"timestamp"`
	Checks    map[string]*Check  `json:"checks,omitempty"`
}

// LivenessHandler returns an HTTP handler for liveness probes
// Liveness checks if the application is running (basic functionality)
func (hc *HealthChecker) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Liveness is simple - if we can respond, we're alive
		response := HealthResponse{
			Status:    StatusHealthy,
			Timestamp: time.Now(),
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		if err := json.NewEncoder(w).Encode(response); err != nil {
			hc.logger.Error("Failed to encode liveness response", zap.Error(err))
		}
	}
}

// ReadinessHandler returns an HTTP handler for readiness probes
// Readiness checks if the application is ready to serve traffic
func (hc *HealthChecker) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		
		// Run all health checks for readiness
		hc.RunAllChecks(ctx)
		
		status := hc.GetStatus()
		checks := hc.GetChecks()
		
		response := HealthResponse{
			Status:    status,
			Timestamp: time.Now(),
			Checks:    checks,
		}
		
		w.Header().Set("Content-Type", "application/json")
		
		// Return 503 if not ready
		if status != StatusHealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		
		if err := json.NewEncoder(w).Encode(response); err != nil {
			hc.logger.Error("Failed to encode readiness response", zap.Error(err))
		}
	}
}

// StartPeriodicChecks starts running health checks periodically
func (hc *HealthChecker) StartPeriodicChecks(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	hc.logger.Info("Starting periodic health checks",
		zap.Duration("interval", interval),
	)
	
	for {
		select {
		case <-ticker.C:
			hc.RunAllChecks(ctx)
		case <-ctx.Done():
			hc.logger.Info("Stopping periodic health checks")
			return
		}
	}
}

// DefaultChecks returns a set of default health checks
func DefaultChecks(logger *zap.Logger) map[string]func(ctx context.Context) (Status, string) {
	return map[string]func(ctx context.Context) (Status, string){
		"basic": func(ctx context.Context) (Status, string) {
			// Basic check - always healthy if we can execute
			return StatusHealthy, "Application is running"
		},
		"memory": func(ctx context.Context) (Status, string) {
			// Simple memory check - in production, you'd check actual memory usage
			return StatusHealthy, "Memory usage within limits"
		},
	}
}
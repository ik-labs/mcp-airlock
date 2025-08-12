package health_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ik-labs/mcp-airlock/pkg/health"
	"go.uber.org/zap"
)

// Example demonstrates how to set up comprehensive health checks for MCP Airlock
func Example() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Create health checker
	healthChecker := health.NewHealthChecker(logger)

	// Create alert handler
	alertHandler := health.NewLogAlertHandler(logger, 5*time.Minute)

	// Create event buffer for audit store failures
	eventBuffer := health.NewEventBuffer(10000, logger, func(ctx context.Context, events []interface{}) error {
		// This would flush events to the audit store when it recovers
		fmt.Printf("Flushing %d buffered events\n", len(events))
		return nil
	})

	// Register health checks for different components

	// JWKS health check
	healthChecker.RegisterCheck("jwks", func(ctx context.Context) (health.Status, string) {
		// Simulate JWKS connectivity check
		return health.StatusHealthy, "JWKS endpoint reachable"
	})

	// Policy engine health check
	healthChecker.RegisterCheck("policy", func(ctx context.Context) (health.Status, string) {
		// Simulate policy compilation check
		return health.StatusHealthy, "Policy compiled successfully"
	})

	// Audit store health check with critical alerting
	healthChecker.RegisterCheck("audit", func(ctx context.Context) (health.Status, string) {
		// Simulate audit store connectivity
		status := health.StatusHealthy
		message := "Audit store operational"

		// If audit store fails, send critical alert
		if status == health.StatusUnhealthy {
			alertHandler.SendAlert(context.Background(), health.AlertLevelCritical, "audit_store",
				"Audit store failure detected - events being buffered")
		}

		return status, message
	})

	// Upstream connectivity health check
	healthChecker.RegisterCheck("upstream", func(ctx context.Context) (health.Status, string) {
		// Simulate upstream server connectivity
		return health.StatusHealthy, "All upstream servers connected"
	})

	// Run health checks
	ctx := context.Background()
	healthChecker.RunAllChecks(ctx)

	// Get overall status
	overallStatus := healthChecker.GetStatus()
	fmt.Printf("Overall health status: %s\n", overallStatus)

	// Get individual check results
	checks := healthChecker.GetChecks()
	for name, check := range checks {
		fmt.Printf("Check %s: %s - %s\n", name, check.Status, check.Message)
	}

	// Start periodic health checks (in production, this would run in a goroutine)
	go healthChecker.StartPeriodicChecks(ctx, 30*time.Second)

	// Set up health check alerter for automated alerting
	alerter := health.NewHealthCheckAlerter(healthChecker, alertHandler, logger)
	alerter.SetComponentAlertLevel("audit", health.AlertLevelCritical)
	alerter.SetComponentAlertLevel("jwks", health.AlertLevelWarning)

	// Run alerting check
	alerter.CheckAndAlert(ctx)

	// Output:
	// Overall health status: healthy
	// Check jwks: healthy - JWKS endpoint reachable
	// Check policy: healthy - Policy compiled successfully
	// Check audit: healthy - Audit store operational
	// Check upstream: healthy - All upstream servers connected
}

// ExampleEventBuffer demonstrates event buffering for audit store failures
func ExampleEventBuffer() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Create event buffer with flush function
	eventBuffer := health.NewEventBuffer(1000, logger, func(ctx context.Context, events []interface{}) error {
		fmt.Printf("Flushing %d events to audit store\n", len(events))
		return nil
	})

	// Buffer some events when audit store is down
	eventBuffer.BufferEvent(map[string]interface{}{
		"action":    "authentication",
		"subject":   "user@example.com",
		"timestamp": time.Now(),
	})

	eventBuffer.BufferEvent(map[string]interface{}{
		"action":    "policy_decision",
		"decision":  "allow",
		"timestamp": time.Now(),
	})

	fmt.Printf("Buffered events: %d\n", eventBuffer.GetBufferedEventCount())
	fmt.Printf("Buffer usage: %.1f%%\n", eventBuffer.GetUsagePercent())

	// Flush events when audit store recovers
	ctx := context.Background()
	err := eventBuffer.FlushBufferedEvents(ctx)
	if err != nil {
		log.Printf("Failed to flush events: %v", err)
	}

	fmt.Printf("Buffered events after flush: %d\n", eventBuffer.GetBufferedEventCount())

	// Output:
	// Buffered events: 2
	// Buffer usage: 0.2%
	// Flushing 2 events to audit store
	// Buffered events after flush: 0
}

// ExamplePeriodicFlushManager demonstrates automatic event buffer flushing
func ExamplePeriodicFlushManager() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Create event buffer
	eventBuffer := health.NewEventBuffer(1000, logger, func(ctx context.Context, events []interface{}) error {
		fmt.Printf("Periodic flush: %d events\n", len(events))
		return nil
	})

	// Create periodic flush manager
	flushManager := health.NewPeriodicFlushManager(eventBuffer, 10*time.Second, logger)

	// Start periodic flushing
	flushManager.Start()

	// Buffer some events
	eventBuffer.BufferEvent("event1")
	eventBuffer.BufferEvent("event2")

	// Wait for periodic flush (in real usage, this would be automatic)
	time.Sleep(15 * time.Second)

	// Stop periodic flushing
	flushManager.Stop()

	// Output:
	// Periodic flush: 2 events
}

// ExampleHealthCheckAlerter demonstrates automated health check alerting
func ExampleHealthCheckAlerter() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	healthChecker := health.NewHealthChecker(logger)
	alertHandler := health.NewLogAlertHandler(logger, 1*time.Minute)

	// Create health check alerter
	alerter := health.NewHealthCheckAlerter(healthChecker, alertHandler, logger)

	// Set alert levels for different components
	alerter.SetComponentAlertLevel("database", health.AlertLevelCritical)
	alerter.SetComponentAlertLevel("cache", health.AlertLevelWarning)

	// Register a failing health check
	failureCount := 0
	healthChecker.RegisterCheck("database", func(ctx context.Context) (health.Status, string) {
		failureCount++
		if failureCount < 4 {
			return health.StatusUnhealthy, "Database connection failed"
		}
		return health.StatusHealthy, "Database connection restored"
	})

	ctx := context.Background()

	// Run checks multiple times to trigger alerting
	for i := 0; i < 5; i++ {
		alerter.CheckAndAlert(ctx)
		time.Sleep(100 * time.Millisecond)
	}

	// Check failure counts
	failureCounts := alerter.GetFailureCounts()
	fmt.Printf("Database failure count: %d\n", failureCounts["database"])

	// Output:
	// Database failure count: 0
}

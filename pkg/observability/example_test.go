// Package observability provides usage examples
package observability

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ExampleTelemetry demonstrates basic telemetry usage
func ExampleTelemetry() {
	// Create logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Setup telemetry (disabled for example)
	telemetry, err := SetupTelemetry(
		false, // tracing disabled for example
		"",
		false, // metrics disabled for example
		"",
		logger,
	)
	if err != nil {
		panic(err)
	}

	// Setup middleware
	middleware := SetupMiddleware(telemetry, logger, true)

	// Simulate a request
	ctx := context.Background()
	correlationID := GenerateCorrelationID()

	// Start request tracing
	ctx, reqCtx := middleware.StartRequest(ctx, correlationID, "tenant1", "read_file", "mcp://repo/test.txt", "GET")

	// Simulate authentication
	ctx, finishAuth := middleware.TraceAuthentication(ctx, "tenant1")
	time.Sleep(1 * time.Millisecond) // Simulate processing
	finishAuth("success", nil)

	// Simulate policy decision
	ctx, finishPolicy := middleware.TracePolicyDecision(ctx, "tenant1", "read_file", "mcp://repo/test.txt")
	time.Sleep(1 * time.Millisecond) // Simulate processing
	finishPolicy("allow", "rule1", nil)

	// Simulate upstream call
	ctx, finishUpstream := middleware.TraceUpstreamCall(ctx, "docs-server", "tenant1")
	time.Sleep(5 * time.Millisecond) // Simulate processing
	finishUpstream("success", nil)

	// Finish request
	middleware.FinishRequest(ctx, reqCtx, "success", nil)

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	GracefulShutdown(shutdownCtx, telemetry, logger)

	fmt.Println("Telemetry example completed")
	// Output: Telemetry example completed
}

// ExampleGenerateCorrelationID demonstrates context utilities
func ExampleGenerateCorrelationID() {
	ctx := context.Background()

	// Generate correlation ID
	correlationID := GenerateCorrelationID()
	fmt.Printf("Generated correlation ID length: %d\n", len(correlationID))

	// Enrich context with metadata
	ctx = EnrichContext(ctx, correlationID, "tenant1", "read_file", "mcp://repo/test.txt", "GET")

	// Retrieve metadata
	metadata := GetRequestMetadata(ctx)
	fmt.Printf("Tenant: %s\n", metadata.Tenant)
	fmt.Printf("Tool: %s\n", metadata.Tool)
	fmt.Printf("Resource: %s\n", metadata.Resource)

	// Output:
	// Generated correlation ID length: 32
	// Tenant: tenant1
	// Tool: read_file
	// Resource: mcp://repo/test.txt
}

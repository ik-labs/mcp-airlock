// Package observability provides integration tests
package observability

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestObservabilityIntegration(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Test setup telemetry
	telemetry, err := SetupTelemetry(
		true, // tracing enabled
		"http://localhost:4318",
		true, // metrics enabled
		"http://localhost:4318",
		logger,
	)
	require.NoError(t, err)
	require.NotNil(t, telemetry)

	// Test setup middleware
	middleware := SetupMiddleware(telemetry, logger, true)
	require.NotNil(t, middleware)

	// Test a complete request flow
	ctx := context.Background()
	correlationID := GenerateCorrelationID()

	// Start request
	ctx, reqCtx := middleware.StartRequest(ctx, correlationID, "tenant1", "read_file", "mcp://repo/test.txt", "GET")
	assert.NotNil(t, reqCtx)
	assert.Equal(t, correlationID, reqCtx.CorrelationID)

	// Simulate authentication
	ctx, finishAuth := middleware.TraceAuthentication(ctx, "tenant1")
	time.Sleep(1 * time.Millisecond) // Simulate processing time
	finishAuth("success", nil)

	// Simulate policy decision
	ctx, finishPolicy := middleware.TracePolicyDecision(ctx, "tenant1", "read_file", "mcp://repo/test.txt")
	time.Sleep(1 * time.Millisecond) // Simulate processing time
	finishPolicy("allow", "rule1", nil)

	// Simulate upstream call
	ctx, finishUpstream := middleware.TraceUpstreamCall(ctx, "docs-server", "tenant1")
	time.Sleep(5 * time.Millisecond) // Simulate processing time
	finishUpstream("success", nil)

	// Simulate redaction
	ctx, finishRedaction := middleware.TraceRedaction(ctx, "tenant1")
	time.Sleep(1 * time.Millisecond) // Simulate processing time
	patterns := map[string]int{
		"email": 2,
		"phone": 1,
	}
	finishRedaction(patterns, nil)

	// Finish request
	middleware.FinishRequest(ctx, reqCtx, "success", nil)

	// Test graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = GracefulShutdown(shutdownCtx, telemetry, logger)
	assert.NoError(t, err)
}

func TestObservabilityIntegrationDisabled(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Test with observability disabled
	telemetry, err := SetupTelemetry(
		false, // tracing disabled
		"",
		false, // metrics disabled
		"",
		logger,
	)
	require.NoError(t, err)
	require.NotNil(t, telemetry)

	// Test setup middleware
	middleware := SetupMiddleware(telemetry, logger, false) // disabled
	require.NotNil(t, middleware)

	// Test that operations work when disabled
	ctx := context.Background()
	correlationID := GenerateCorrelationID()

	ctx, reqCtx := middleware.StartRequest(ctx, correlationID, "tenant1", "read_file", "mcp://repo/test.txt", "GET")
	assert.NotNil(t, reqCtx)

	middleware.FinishRequest(ctx, reqCtx, "success", nil)

	// Test graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = GracefulShutdown(shutdownCtx, telemetry, logger)
	assert.NoError(t, err)
}

func TestObservabilityErrorScenarios(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Test setup telemetry
	telemetry, err := SetupTelemetry(
		true, // tracing enabled
		"http://localhost:4318",
		true, // metrics enabled
		"http://localhost:4318",
		logger,
	)
	require.NoError(t, err)
	require.NotNil(t, telemetry)

	// Test setup middleware
	middleware := SetupMiddleware(telemetry, logger, true)
	require.NotNil(t, middleware)

	ctx := context.Background()
	correlationID := GenerateCorrelationID()

	// Test error scenarios
	ctx, reqCtx := middleware.StartRequest(ctx, correlationID, "tenant1", "write_file", "mcp://repo/test.txt", "POST")

	// Simulate authentication failure
	ctx, finishAuth := middleware.TraceAuthentication(ctx, "tenant1")
	finishAuth("failure", assert.AnError)

	// Simulate policy denial
	ctx, finishPolicy := middleware.TracePolicyDecision(ctx, "tenant1", "write_file", "mcp://repo/test.txt")
	finishPolicy("deny", "rule2", nil)

	// Simulate upstream error
	ctx, finishUpstream := middleware.TraceUpstreamCall(ctx, "docs-server", "tenant1")
	finishUpstream("error", assert.AnError)

	// Record various errors
	middleware.RecordError(ctx, "auth", "invalid_token", "tenant1", assert.AnError)
	middleware.RecordError(ctx, "policy", "compilation_error", "tenant1", assert.AnError)
	middleware.RecordError(ctx, "upstream", "timeout", "tenant1", assert.AnError)

	// Finish request with error
	middleware.FinishRequest(ctx, reqCtx, "error", assert.AnError)

	// Test graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = GracefulShutdown(shutdownCtx, telemetry, logger)
	assert.NoError(t, err)
}

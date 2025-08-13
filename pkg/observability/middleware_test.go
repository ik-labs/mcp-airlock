// Package observability provides middleware tests
package observability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestNewMiddleware(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &MiddlewareConfig{
		ServiceName: "test-service",
		Enabled:     true,
	}

	telemetryConfig := &TelemetryConfig{
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(telemetryConfig, logger)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	middleware := NewMiddleware(telemetry, logger, config)
	assert.NotNil(t, middleware)
	assert.Equal(t, telemetry, middleware.telemetry)
	assert.Equal(t, logger, middleware.logger)
	assert.Equal(t, config, middleware.config)
}

func TestMiddlewareStartFinishRequest(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &MiddlewareConfig{
		ServiceName: "test-service",
		Enabled:     true,
	}

	telemetryConfig := &TelemetryConfig{
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(telemetryConfig, logger)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	middleware := NewMiddleware(telemetry, logger, config)

	ctx := context.Background()

	// Test successful request
	ctx, reqCtx := middleware.StartRequest(ctx, "corr-123", "tenant1", "read_file", "mcp://repo/test.txt", "GET")

	assert.NotNil(t, reqCtx)
	assert.Equal(t, "corr-123", reqCtx.CorrelationID)
	assert.Equal(t, "tenant1", reqCtx.Tenant)
	assert.Equal(t, "read_file", reqCtx.Tool)
	assert.Equal(t, "mcp://repo/test.txt", reqCtx.Resource)
	assert.Equal(t, "GET", reqCtx.Method)
	assert.False(t, reqCtx.StartTime.IsZero())

	// Simulate some processing time
	time.Sleep(10 * time.Millisecond)

	middleware.FinishRequest(ctx, reqCtx, "success", nil)

	// Test request with error
	ctx, reqCtx = middleware.StartRequest(ctx, "corr-124", "tenant1", "write_file", "mcp://repo/test.txt", "POST")
	testErr := errors.New("test error")
	middleware.FinishRequest(ctx, reqCtx, "error", testErr)
}

func TestMiddlewareDisabled(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &MiddlewareConfig{
		ServiceName: "test-service",
		Enabled:     false, // Disabled
	}

	middleware := NewMiddleware(nil, logger, config)

	ctx := context.Background()

	// Test that operations work when disabled
	ctx, reqCtx := middleware.StartRequest(ctx, "corr-123", "tenant1", "read_file", "mcp://repo/test.txt", "GET")
	assert.NotNil(t, reqCtx)

	middleware.FinishRequest(ctx, reqCtx, "success", nil)
}

func TestMiddlewareTraceAuthentication(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &MiddlewareConfig{
		ServiceName: "test-service",
		Enabled:     true,
	}

	telemetryConfig := &TelemetryConfig{
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(telemetryConfig, logger)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	middleware := NewMiddleware(telemetry, logger, config)

	ctx := context.Background()

	// Test successful authentication
	ctx, finish := middleware.TraceAuthentication(ctx, "tenant1")
	time.Sleep(5 * time.Millisecond)
	finish("success", nil)

	// Test failed authentication
	ctx, finish = middleware.TraceAuthentication(ctx, "tenant1")
	time.Sleep(5 * time.Millisecond)
	finish("failure", errors.New("invalid token"))
}

func TestMiddlewareTracePolicyDecision(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &MiddlewareConfig{
		ServiceName: "test-service",
		Enabled:     true,
	}

	telemetryConfig := &TelemetryConfig{
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(telemetryConfig, logger)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	middleware := NewMiddleware(telemetry, logger, config)

	ctx := context.Background()

	// Test allow decision
	ctx, finish := middleware.TracePolicyDecision(ctx, "tenant1", "read_file", "mcp://repo/test.txt")
	time.Sleep(5 * time.Millisecond)
	finish("allow", "rule1", nil)

	// Test deny decision
	ctx, finish = middleware.TracePolicyDecision(ctx, "tenant1", "write_file", "mcp://repo/test.txt")
	time.Sleep(5 * time.Millisecond)
	finish("deny", "rule2", nil)

	// Test policy error
	ctx, finish = middleware.TracePolicyDecision(ctx, "tenant1", "read_file", "mcp://repo/test.txt")
	time.Sleep(5 * time.Millisecond)
	finish("", "", errors.New("policy engine error"))
}

func TestMiddlewareTraceUpstreamCall(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &MiddlewareConfig{
		ServiceName: "test-service",
		Enabled:     true,
	}

	telemetryConfig := &TelemetryConfig{
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(telemetryConfig, logger)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	middleware := NewMiddleware(telemetry, logger, config)

	ctx := context.Background()

	// Test successful upstream call
	ctx, finish := middleware.TraceUpstreamCall(ctx, "docs-server", "tenant1")
	time.Sleep(10 * time.Millisecond)
	finish("success", nil)

	// Test failed upstream call
	ctx, finish = middleware.TraceUpstreamCall(ctx, "docs-server", "tenant1")
	time.Sleep(10 * time.Millisecond)
	finish("error", errors.New("upstream timeout"))
}

func TestMiddlewareTraceRedaction(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &MiddlewareConfig{
		ServiceName: "test-service",
		Enabled:     true,
	}

	telemetryConfig := &TelemetryConfig{
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(telemetryConfig, logger)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	middleware := NewMiddleware(telemetry, logger, config)

	ctx := context.Background()

	// Test redaction with patterns
	ctx, finish := middleware.TraceRedaction(ctx, "tenant1")
	time.Sleep(5 * time.Millisecond)
	patterns := map[string]int{
		"email":       3,
		"phone":       1,
		"credit_card": 0, // No matches
	}
	finish(patterns, nil)

	// Test redaction error
	ctx, finish = middleware.TraceRedaction(ctx, "tenant1")
	time.Sleep(5 * time.Millisecond)
	finish(nil, errors.New("redaction error"))
}

func TestMiddlewareRecordConnectionEvent(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &MiddlewareConfig{
		ServiceName: "test-service",
		Enabled:     true,
	}

	telemetryConfig := &TelemetryConfig{
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(telemetryConfig, logger)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	middleware := NewMiddleware(telemetry, logger, config)

	ctx := context.Background()

	// Test connection events
	middleware.RecordConnectionEvent(ctx, "tenant1", "connected")
	middleware.RecordConnectionEvent(ctx, "tenant1", "disconnected")
	middleware.RecordConnectionEvent(ctx, "tenant1", "other_event")
}

func TestMiddlewareRecordError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &MiddlewareConfig{
		ServiceName: "test-service",
		Enabled:     true,
	}

	telemetryConfig := &TelemetryConfig{
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(telemetryConfig, logger)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	middleware := NewMiddleware(telemetry, logger, config)

	ctx := context.Background()

	// Test error recording
	testErr := errors.New("test error")
	middleware.RecordError(ctx, "auth", "invalid_token", "tenant1", testErr)
	middleware.RecordError(ctx, "policy", "compilation_error", "tenant1", testErr)
	middleware.RecordError(ctx, "upstream", "timeout", "tenant1", testErr)
}

func BenchmarkMiddlewareOperations(b *testing.B) {
	logger := zaptest.NewLogger(b)
	config := &MiddlewareConfig{
		ServiceName: "bench-service",
		Enabled:     true,
	}

	telemetryConfig := &TelemetryConfig{
		ServiceName:     "bench-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(telemetryConfig, logger)
	require.NoError(b, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	middleware := NewMiddleware(telemetry, logger, config)

	ctx := context.Background()

	b.Run("StartFinishRequest", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ctx, reqCtx := middleware.StartRequest(ctx, "corr-123", "tenant1", "read_file", "mcp://repo/test.txt", "GET")
			middleware.FinishRequest(ctx, reqCtx, "success", nil)
		}
	})

	b.Run("TraceAuthentication", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, finish := middleware.TraceAuthentication(ctx, "tenant1")
			finish("success", nil)
		}
	})

	b.Run("TracePolicyDecision", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, finish := middleware.TracePolicyDecision(ctx, "tenant1", "read_file", "mcp://repo/test.txt")
			finish("allow", "rule1", nil)
		}
	})
}

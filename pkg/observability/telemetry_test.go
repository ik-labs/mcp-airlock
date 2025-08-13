// Package observability provides OpenTelemetry tracing and metrics tests
package observability

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.uber.org/zap/zaptest"
)

func TestNewTelemetry(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name    string
		config  *TelemetryConfig
		wantErr bool
	}{
		{
			name:    "nil config uses defaults",
			config:  nil,
			wantErr: false,
		},
		{
			name: "tracing enabled",
			config: &TelemetryConfig{
				ServiceName:     "test-service",
				ServiceVersion:  "1.0.0",
				TracingEnabled:  true,
				TracingEndpoint: "http://localhost:4318/v1/traces",
			},
			wantErr: false,
		},
		{
			name: "metrics enabled",
			config: &TelemetryConfig{
				ServiceName:     "test-service",
				ServiceVersion:  "1.0.0",
				MetricsEnabled:  true,
				MetricsEndpoint: "http://localhost:4318/v1/metrics",
			},
			wantErr: false,
		},
		{
			name: "both enabled",
			config: &TelemetryConfig{
				ServiceName:     "test-service",
				ServiceVersion:  "1.0.0",
				TracingEnabled:  true,
				TracingEndpoint: "http://localhost:4318/v1/traces",
				MetricsEnabled:  true,
				MetricsEndpoint: "http://localhost:4318/v1/metrics",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			telemetry, err := NewTelemetry(tt.config, logger)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, telemetry)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, telemetry)

				// Test shutdown
				if telemetry != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					err = telemetry.Shutdown(ctx)
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestTelemetryTracing(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &TelemetryConfig{
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
	}

	telemetry, err := NewTelemetry(config, logger)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	ctx := context.Background()

	// Test span creation
	ctx, span := telemetry.StartSpan(ctx, "test-span",
		attribute.String("test.key", "test.value"),
	)

	assert.NotNil(t, span)
	assert.True(t, span.IsRecording())

	// Test adding attributes
	telemetry.AddSpanAttributes(ctx,
		attribute.String("additional.key", "additional.value"),
	)

	// Test adding events
	telemetry.AddSpanEvent(ctx, "test.event",
		attribute.String("event.key", "event.value"),
	)

	// Test setting status
	telemetry.SetSpanStatus(ctx, codes.Ok, "success")

	span.End()
}

func TestTelemetryMetrics(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &TelemetryConfig{
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(config, logger)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	ctx := context.Background()

	// Test request metrics
	telemetry.RecordRequest(ctx, "tenant1", "read_file", "GET", "success", 100*time.Millisecond)

	// Test auth metrics
	telemetry.RecordAuth(ctx, "tenant1", "success")

	// Test policy metrics
	telemetry.RecordPolicyDecision(ctx, "tenant1", "read_file", "mcp://repo/test.txt", "allow", "rule1")

	// Test redaction metrics
	telemetry.RecordRedaction(ctx, "tenant1", "email", 3)

	// Test error metrics
	telemetry.RecordError(ctx, "auth", "invalid_token", "tenant1")

	// Test connection metrics
	telemetry.RecordConnectionChange(ctx, "tenant1", 1)
	telemetry.RecordConnectionChange(ctx, "tenant1", -1)

	// Test upstream metrics
	telemetry.RecordUpstreamCall(ctx, "docs-server", "tenant1", "success", 50*time.Millisecond)
}

func TestTelemetryDisabled(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &TelemetryConfig{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		// Both tracing and metrics disabled
	}

	telemetry, err := NewTelemetry(config, logger)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	ctx := context.Background()

	// Test that operations don't panic when disabled
	ctx, span := telemetry.StartSpan(ctx, "test-span")
	assert.NotNil(t, span) // Should return a no-op span

	telemetry.AddSpanAttributes(ctx, attribute.String("key", "value"))
	telemetry.AddSpanEvent(ctx, "event")
	telemetry.SetSpanStatus(ctx, codes.Ok, "ok")

	// Metrics should be no-ops
	telemetry.RecordRequest(ctx, "tenant1", "tool", "method", "status", time.Millisecond)
	telemetry.RecordAuth(ctx, "tenant1", "success")
	telemetry.RecordPolicyDecision(ctx, "tenant1", "tool", "resource", "allow", "rule")
	telemetry.RecordRedaction(ctx, "tenant1", "pattern", 1)
	telemetry.RecordError(ctx, "component", "error", "tenant1")
	telemetry.RecordConnectionChange(ctx, "tenant1", 1)
	telemetry.RecordUpstreamCall(ctx, "upstream", "tenant1", "success", time.Millisecond)

	span.End()
}

func TestTelemetryGetters(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &TelemetryConfig{
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(config, logger)
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	// Test getters
	tracer := telemetry.GetTracer()
	assert.NotNil(t, tracer)

	meter := telemetry.GetMeter()
	assert.NotNil(t, meter)
}

func BenchmarkTelemetryOperations(b *testing.B) {
	logger := zaptest.NewLogger(b)
	config := &TelemetryConfig{
		ServiceName:     "bench-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(config, logger)
	require.NoError(b, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(ctx)
	}()

	ctx := context.Background()

	b.Run("StartSpan", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, span := telemetry.StartSpan(ctx, "bench-span",
				attribute.String("tenant", "tenant1"),
				attribute.String("tool", "read_file"),
			)
			span.End()
		}
	})

	b.Run("RecordRequest", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			telemetry.RecordRequest(ctx, "tenant1", "read_file", "GET", "success", time.Millisecond)
		}
	})

	b.Run("RecordPolicyDecision", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			telemetry.RecordPolicyDecision(ctx, "tenant1", "read_file", "mcp://repo/test.txt", "allow", "rule1")
		}
	})
}

func TestTelemetryShutdown(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &TelemetryConfig{
		ServiceName:     "test-service",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  true,
		TracingEndpoint: "http://localhost:4318/v1/traces",
		MetricsEnabled:  true,
		MetricsEndpoint: "http://localhost:4318/v1/metrics",
	}

	telemetry, err := NewTelemetry(config, logger)
	require.NoError(t, err)

	// Test shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = telemetry.Shutdown(ctx)
	assert.NoError(t, err)

	// Test double shutdown (should not error)
	err = telemetry.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestTelemetryResourceCreation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &TelemetryConfig{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
	}

	telemetry := &Telemetry{
		config: config,
		logger: logger,
	}

	resource, err := telemetry.createResource()
	require.NoError(t, err)
	assert.NotNil(t, resource)

	// Check that resource has expected attributes
	attrs := resource.Attributes()
	found := false
	for _, attr := range attrs {
		if attr.Key == "service.name" && attr.Value.AsString() == "test-service" {
			found = true
			break
		}
	}
	assert.True(t, found, "service.name attribute not found in resource")
}

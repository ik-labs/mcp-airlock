// Package observability provides context utilities tests
package observability

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestCorrelationID(t *testing.T) {
	ctx := context.Background()

	// Test empty context
	assert.Empty(t, GetCorrelationID(ctx))

	// Test with correlation ID
	correlationID := "test-correlation-123"
	ctx = WithCorrelationID(ctx, correlationID)
	assert.Equal(t, correlationID, GetCorrelationID(ctx))
}

func TestTenant(t *testing.T) {
	ctx := context.Background()

	// Test empty context
	assert.Empty(t, GetTenant(ctx))

	// Test with tenant
	tenant := "tenant-123"
	ctx = WithTenant(ctx, tenant)
	assert.Equal(t, tenant, GetTenant(ctx))
}

func TestTool(t *testing.T) {
	ctx := context.Background()

	// Test empty context
	assert.Empty(t, GetTool(ctx))

	// Test with tool
	tool := "read_file"
	ctx = WithTool(ctx, tool)
	assert.Equal(t, tool, GetTool(ctx))
}

func TestResource(t *testing.T) {
	ctx := context.Background()

	// Test empty context
	assert.Empty(t, GetResource(ctx))

	// Test with resource
	resource := "mcp://repo/test.txt"
	ctx = WithResource(ctx, resource)
	assert.Equal(t, resource, GetResource(ctx))
}

func TestMethod(t *testing.T) {
	ctx := context.Background()

	// Test empty context
	assert.Empty(t, GetMethod(ctx))

	// Test with method
	method := "GET"
	ctx = WithMethod(ctx, method)
	assert.Equal(t, method, GetMethod(ctx))
}

func TestGenerateCorrelationID(t *testing.T) {
	// Test that correlation IDs are generated
	id1 := GenerateCorrelationID()
	id2 := GenerateCorrelationID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2) // Should be unique
	assert.Len(t, id1, 32)       // Should be 32 hex characters (16 bytes)
	assert.Len(t, id2, 32)
}

func TestTraceContext(t *testing.T) {
	ctx := context.Background()

	// Test with no active trace
	assert.Empty(t, GetTraceID(ctx))
	assert.Empty(t, GetSpanID(ctx))
	assert.False(t, IsTracing(ctx))

	// Set up a test tracer provider
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(shutdownCtx)
	}()

	// Create a span for testing
	ctx, span := telemetry.StartSpan(ctx, "test-span")
	defer span.End()

	// Test with active trace
	traceID := GetTraceID(ctx)
	spanID := GetSpanID(ctx)

	assert.NotEmpty(t, traceID)
	assert.NotEmpty(t, spanID)
	assert.True(t, IsTracing(ctx))
	assert.Len(t, traceID, 32) // Trace ID should be 32 hex characters
	assert.Len(t, spanID, 16)  // Span ID should be 16 hex characters
}

func TestExtractInjectTraceContext(t *testing.T) {
	ctx := context.Background()

	// Create headers
	headers := make(http.Header)

	// Test extracting from empty headers
	extractedCtx := ExtractTraceContext(ctx, headers)
	assert.NotNil(t, extractedCtx)

	// Set up a test tracer provider
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(shutdownCtx)
	}()

	// Create a span and inject context
	ctx, span := telemetry.StartSpan(ctx, "test-span")
	defer span.End()

	InjectTraceContext(ctx, headers)

	// Verify headers were set
	assert.NotEmpty(t, headers.Get("traceparent"))

	// Extract context from headers
	newCtx := context.Background()
	extractedCtx = ExtractTraceContext(newCtx, headers)

	// The extracted context should have trace information
	assert.NotNil(t, extractedCtx)
}

func TestRequestMetadata(t *testing.T) {
	ctx := context.Background()

	// Test empty context
	metadata := GetRequestMetadata(ctx)
	assert.NotNil(t, metadata)
	assert.Empty(t, metadata.CorrelationID)
	assert.Empty(t, metadata.TraceID)
	assert.Empty(t, metadata.SpanID)
	assert.Empty(t, metadata.Tenant)
	assert.Empty(t, metadata.Tool)
	assert.Empty(t, metadata.Resource)
	assert.Empty(t, metadata.Method)

	// Enrich context
	ctx = EnrichContext(ctx, "corr-123", "tenant1", "read_file", "mcp://repo/test.txt", "GET")

	// Set up a test tracer provider
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		telemetry.Shutdown(shutdownCtx)
	}()

	// Add trace context
	ctx, span := telemetry.StartSpan(ctx, "test-span")
	defer span.End()

	// Test enriched context
	metadata = GetRequestMetadata(ctx)
	assert.Equal(t, "corr-123", metadata.CorrelationID)
	assert.Equal(t, "tenant1", metadata.Tenant)
	assert.Equal(t, "read_file", metadata.Tool)
	assert.Equal(t, "mcp://repo/test.txt", metadata.Resource)
	assert.Equal(t, "GET", metadata.Method)
	assert.NotEmpty(t, metadata.TraceID)
	assert.NotEmpty(t, metadata.SpanID)
}

func TestEnrichContext(t *testing.T) {
	ctx := context.Background()

	// Enrich context with all metadata
	enrichedCtx := EnrichContext(ctx, "corr-123", "tenant1", "read_file", "mcp://repo/test.txt", "GET")

	// Verify all values are set
	assert.Equal(t, "corr-123", GetCorrelationID(enrichedCtx))
	assert.Equal(t, "tenant1", GetTenant(enrichedCtx))
	assert.Equal(t, "read_file", GetTool(enrichedCtx))
	assert.Equal(t, "mcp://repo/test.txt", GetResource(enrichedCtx))
	assert.Equal(t, "GET", GetMethod(enrichedCtx))
}

func TestContextChaining(t *testing.T) {
	ctx := context.Background()

	// Test chaining context operations
	ctx = WithCorrelationID(ctx, "corr-123")
	ctx = WithTenant(ctx, "tenant1")
	ctx = WithTool(ctx, "read_file")
	ctx = WithResource(ctx, "mcp://repo/test.txt")
	ctx = WithMethod(ctx, "GET")

	// Verify all values are preserved
	assert.Equal(t, "corr-123", GetCorrelationID(ctx))
	assert.Equal(t, "tenant1", GetTenant(ctx))
	assert.Equal(t, "read_file", GetTool(ctx))
	assert.Equal(t, "mcp://repo/test.txt", GetResource(ctx))
	assert.Equal(t, "GET", GetMethod(ctx))
}

func TestContextOverwrite(t *testing.T) {
	ctx := context.Background()

	// Set initial value
	ctx = WithTenant(ctx, "tenant1")
	assert.Equal(t, "tenant1", GetTenant(ctx))

	// Overwrite value
	ctx = WithTenant(ctx, "tenant2")
	assert.Equal(t, "tenant2", GetTenant(ctx))
}

func BenchmarkContextOperations(b *testing.B) {
	ctx := context.Background()

	b.Run("WithCorrelationID", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ctx = WithCorrelationID(ctx, "corr-123")
		}
	})

	b.Run("GetCorrelationID", func(b *testing.B) {
		ctx = WithCorrelationID(ctx, "corr-123")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			GetCorrelationID(ctx)
		}
	})

	b.Run("EnrichContext", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			EnrichContext(ctx, "corr-123", "tenant1", "read_file", "mcp://repo/test.txt", "GET")
		}
	})

	b.Run("GetRequestMetadata", func(b *testing.B) {
		ctx = EnrichContext(ctx, "corr-123", "tenant1", "read_file", "mcp://repo/test.txt", "GET")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			GetRequestMetadata(ctx)
		}
	})

	b.Run("GenerateCorrelationID", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			GenerateCorrelationID()
		}
	})
}

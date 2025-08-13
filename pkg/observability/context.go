// Package observability provides context utilities for tracing and correlation
package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Context keys for storing observability data
type contextKey string

const (
	correlationIDKey contextKey = "correlation_id"
	tenantKey        contextKey = "tenant"
	toolKey          contextKey = "tool"
	resourceKey      contextKey = "resource"
	methodKey        contextKey = "method"
)

// WithCorrelationID adds a correlation ID to the context
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, correlationIDKey, correlationID)
}

// GetCorrelationID retrieves the correlation ID from the context
func GetCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value(correlationIDKey).(string); ok {
		return id
	}
	return ""
}

// WithTenant adds tenant information to the context
func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey, tenant)
}

// GetTenant retrieves the tenant from the context
func GetTenant(ctx context.Context) string {
	if tenant, ok := ctx.Value(tenantKey).(string); ok {
		return tenant
	}
	return ""
}

// WithTool adds tool information to the context
func WithTool(ctx context.Context, tool string) context.Context {
	return context.WithValue(ctx, toolKey, tool)
}

// GetTool retrieves the tool from the context
func GetTool(ctx context.Context) string {
	if tool, ok := ctx.Value(toolKey).(string); ok {
		return tool
	}
	return ""
}

// WithResource adds resource information to the context
func WithResource(ctx context.Context, resource string) context.Context {
	return context.WithValue(ctx, resourceKey, resource)
}

// GetResource retrieves the resource from the context
func GetResource(ctx context.Context) string {
	if resource, ok := ctx.Value(resourceKey).(string); ok {
		return resource
	}
	return ""
}

// WithMethod adds method information to the context
func WithMethod(ctx context.Context, method string) context.Context {
	return context.WithValue(ctx, methodKey, method)
}

// GetMethod retrieves the method from the context
func GetMethod(ctx context.Context) string {
	if method, ok := ctx.Value(methodKey).(string); ok {
		return method
	}
	return ""
}

// GenerateCorrelationID generates a new correlation ID
func GenerateCorrelationID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a simple timestamp-based ID if random generation fails
		return "fallback-" + hex.EncodeToString([]byte("correlation"))[:16]
	}
	return hex.EncodeToString(bytes)
}

// ExtractTraceContext extracts OpenTelemetry trace context from HTTP headers
func ExtractTraceContext(ctx context.Context, headers http.Header) context.Context {
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)

	return propagator.Extract(ctx, propagation.HeaderCarrier(headers))
}

// InjectTraceContext injects OpenTelemetry trace context into HTTP headers
func InjectTraceContext(ctx context.Context, headers http.Header) {
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)

	propagator.Inject(ctx, propagation.HeaderCarrier(headers))
}

// GetTraceID retrieves the trace ID from the current span context
func GetTraceID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// GetSpanID retrieves the span ID from the current span context
func GetSpanID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().SpanID().String()
	}
	return ""
}

// IsTracing returns true if the context has an active trace
func IsTracing(ctx context.Context) bool {
	span := trace.SpanFromContext(ctx)
	return span.SpanContext().IsValid()
}

// RequestMetadata holds metadata about the current request
type RequestMetadata struct {
	CorrelationID string
	TraceID       string
	SpanID        string
	Tenant        string
	Tool          string
	Resource      string
	Method        string
}

// GetRequestMetadata extracts all request metadata from the context
func GetRequestMetadata(ctx context.Context) *RequestMetadata {
	return &RequestMetadata{
		CorrelationID: GetCorrelationID(ctx),
		TraceID:       GetTraceID(ctx),
		SpanID:        GetSpanID(ctx),
		Tenant:        GetTenant(ctx),
		Tool:          GetTool(ctx),
		Resource:      GetResource(ctx),
		Method:        GetMethod(ctx),
	}
}

// EnrichContext adds all available metadata to the context
func EnrichContext(ctx context.Context, correlationID, tenant, tool, resource, method string) context.Context {
	ctx = WithCorrelationID(ctx, correlationID)
	ctx = WithTenant(ctx, tenant)
	ctx = WithTool(ctx, tool)
	ctx = WithResource(ctx, resource)
	ctx = WithMethod(ctx, method)
	return ctx
}

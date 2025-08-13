// Package observability provides middleware for tracing and metrics
package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// MiddlewareConfig holds configuration for observability middleware
type MiddlewareConfig struct {
	ServiceName string
	Enabled     bool
}

// Middleware provides observability middleware for request processing
type Middleware struct {
	telemetry *Telemetry
	logger    *zap.Logger
	config    *MiddlewareConfig
}

// NewMiddleware creates a new observability middleware
func NewMiddleware(telemetry *Telemetry, logger *zap.Logger, config *MiddlewareConfig) *Middleware {
	return &Middleware{
		telemetry: telemetry,
		logger:    logger,
		config:    config,
	}
}

// RequestContext holds request-specific observability data
type RequestContext struct {
	StartTime     time.Time
	CorrelationID string
	Tenant        string
	Tool          string
	Resource      string
	Method        string
}

// StartRequest begins request tracing and metrics collection
func (m *Middleware) StartRequest(ctx context.Context, correlationID, tenant, tool, resource, method string) (context.Context, *RequestContext) {
	if !m.config.Enabled || m.telemetry == nil {
		return ctx, &RequestContext{
			StartTime:     time.Now(),
			CorrelationID: correlationID,
			Tenant:        tenant,
			Tool:          tool,
			Resource:      resource,
			Method:        method,
		}
	}

	// Start tracing span
	spanAttrs := []attribute.KeyValue{
		attribute.String("correlation_id", correlationID),
		attribute.String("tenant", tenant),
		attribute.String("tool", tool),
		attribute.String("resource", resource),
		attribute.String("method", method),
		attribute.String("service.name", m.config.ServiceName),
	}

	ctx, _ = m.telemetry.StartSpan(ctx, "mcp.request", spanAttrs...)

	// Add span event for request start
	m.telemetry.AddSpanEvent(ctx, "request.start",
		attribute.String("correlation_id", correlationID),
	)

	reqCtx := &RequestContext{
		StartTime:     time.Now(),
		CorrelationID: correlationID,
		Tenant:        tenant,
		Tool:          tool,
		Resource:      resource,
		Method:        method,
	}

	return ctx, reqCtx
}

// FinishRequest completes request tracing and records metrics
func (m *Middleware) FinishRequest(ctx context.Context, reqCtx *RequestContext, status string, err error) {
	if !m.config.Enabled || m.telemetry == nil {
		return
	}

	duration := time.Since(reqCtx.StartTime)

	// Set span status and attributes
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(
			attribute.String("status", status),
			attribute.Float64("duration_ms", float64(duration.Nanoseconds())/1e6),
		)

		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			m.telemetry.AddSpanEvent(ctx, "request.error",
				attribute.String("error", err.Error()),
			)
		} else {
			span.SetStatus(codes.Ok, "")
		}

		m.telemetry.AddSpanEvent(ctx, "request.finish",
			attribute.String("status", status),
			attribute.Float64("duration_ms", float64(duration.Nanoseconds())/1e6),
		)

		span.End()
	}

	// Record metrics
	m.telemetry.RecordRequest(ctx, reqCtx.Tenant, reqCtx.Tool, reqCtx.Method, status, duration)

	// Log structured request completion
	m.logger.Info("Request completed",
		zap.String("correlation_id", reqCtx.CorrelationID),
		zap.String("tenant", reqCtx.Tenant),
		zap.String("tool", reqCtx.Tool),
		zap.String("method", reqCtx.Method),
		zap.String("status", status),
		zap.Duration("duration", duration),
		zap.Error(err),
	)
}

// TraceAuthentication traces authentication operations
func (m *Middleware) TraceAuthentication(ctx context.Context, tenant string) (context.Context, func(result string, err error)) {
	if !m.config.Enabled || m.telemetry == nil {
		return ctx, func(string, error) {}
	}

	ctx, span := m.telemetry.StartSpan(ctx, "mcp.auth",
		attribute.String("tenant", tenant),
		attribute.String("component", "authentication"),
	)

	startTime := time.Now()

	return ctx, func(result string, err error) {
		duration := time.Since(startTime)

		// Set span attributes and status
		span.SetAttributes(
			attribute.String("auth.result", result),
			attribute.Float64("duration_ms", float64(duration.Nanoseconds())/1e6),
		)

		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			m.telemetry.AddSpanEvent(ctx, "auth.error",
				attribute.String("error", err.Error()),
			)
		} else {
			span.SetStatus(codes.Ok, "")
		}

		span.End()

		// Record auth metrics
		m.telemetry.RecordAuth(ctx, tenant, result)

		// Log auth event
		m.logger.Info("Authentication completed",
			zap.String("tenant", tenant),
			zap.String("result", result),
			zap.Duration("duration", duration),
			zap.Error(err),
		)
	}
}

// TracePolicyDecision traces policy evaluation operations
func (m *Middleware) TracePolicyDecision(ctx context.Context, tenant, tool, resource string) (context.Context, func(decision, ruleID string, err error)) {
	if !m.config.Enabled || m.telemetry == nil {
		return ctx, func(string, string, error) {}
	}

	ctx, span := m.telemetry.StartSpan(ctx, "mcp.policy",
		attribute.String("tenant", tenant),
		attribute.String("tool", tool),
		attribute.String("resource", resource),
		attribute.String("component", "policy"),
	)

	startTime := time.Now()

	return ctx, func(decision, ruleID string, err error) {
		duration := time.Since(startTime)

		// Set span attributes and status
		span.SetAttributes(
			attribute.String("policy.decision", decision),
			attribute.String("policy.rule_id", ruleID),
			attribute.Float64("duration_ms", float64(duration.Nanoseconds())/1e6),
		)

		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			m.telemetry.AddSpanEvent(ctx, "policy.error",
				attribute.String("error", err.Error()),
			)
		} else {
			span.SetStatus(codes.Ok, "")
		}

		span.End()

		// Record policy metrics
		m.telemetry.RecordPolicyDecision(ctx, tenant, tool, resource, decision, ruleID)

		// Log policy decision
		m.logger.Info("Policy decision completed",
			zap.String("tenant", tenant),
			zap.String("tool", tool),
			zap.String("resource", resource),
			zap.String("decision", decision),
			zap.String("rule_id", ruleID),
			zap.Duration("duration", duration),
			zap.Error(err),
		)
	}
}

// TraceUpstreamCall traces calls to upstream MCP servers
func (m *Middleware) TraceUpstreamCall(ctx context.Context, upstream, tenant string) (context.Context, func(status string, err error)) {
	if !m.config.Enabled || m.telemetry == nil {
		return ctx, func(string, error) {}
	}

	ctx, span := m.telemetry.StartSpan(ctx, "mcp.upstream",
		attribute.String("upstream", upstream),
		attribute.String("tenant", tenant),
		attribute.String("component", "upstream"),
	)

	startTime := time.Now()

	return ctx, func(status string, err error) {
		duration := time.Since(startTime)

		// Set span attributes and status
		span.SetAttributes(
			attribute.String("upstream.status", status),
			attribute.Float64("duration_ms", float64(duration.Nanoseconds())/1e6),
		)

		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			m.telemetry.AddSpanEvent(ctx, "upstream.error",
				attribute.String("error", err.Error()),
			)
		} else {
			span.SetStatus(codes.Ok, "")
		}

		span.End()

		// Record upstream metrics
		m.telemetry.RecordUpstreamCall(ctx, upstream, tenant, status, duration)

		// Log upstream call
		m.logger.Info("Upstream call completed",
			zap.String("upstream", upstream),
			zap.String("tenant", tenant),
			zap.String("status", status),
			zap.Duration("duration", duration),
			zap.Error(err),
		)
	}
}

// TraceRedaction traces data redaction operations
func (m *Middleware) TraceRedaction(ctx context.Context, tenant string) (context.Context, func(patterns map[string]int, err error)) {
	if !m.config.Enabled || m.telemetry == nil {
		return ctx, func(map[string]int, error) {}
	}

	ctx, span := m.telemetry.StartSpan(ctx, "mcp.redaction",
		attribute.String("tenant", tenant),
		attribute.String("component", "redaction"),
	)

	startTime := time.Now()

	return ctx, func(patterns map[string]int, err error) {
		duration := time.Since(startTime)

		// Calculate total redactions
		totalRedactions := 0
		for _, count := range patterns {
			totalRedactions += count
		}

		// Set span attributes and status
		span.SetAttributes(
			attribute.Int("redaction.total_count", totalRedactions),
			attribute.Int("redaction.pattern_count", len(patterns)),
			attribute.Float64("duration_ms", float64(duration.Nanoseconds())/1e6),
		)

		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			m.telemetry.AddSpanEvent(ctx, "redaction.error",
				attribute.String("error", err.Error()),
			)
		} else {
			span.SetStatus(codes.Ok, "")
		}

		// Add event for each pattern that matched
		for pattern, count := range patterns {
			if count > 0 {
				m.telemetry.AddSpanEvent(ctx, "redaction.pattern_match",
					attribute.String("pattern", pattern),
					attribute.Int("count", count),
				)
			}
		}

		span.End()

		// Record redaction metrics for each pattern
		for pattern, count := range patterns {
			if count > 0 {
				m.telemetry.RecordRedaction(ctx, tenant, pattern, count)
			}
		}

		// Log redaction event
		m.logger.Info("Redaction completed",
			zap.String("tenant", tenant),
			zap.Int("total_redactions", totalRedactions),
			zap.Int("patterns_matched", len(patterns)),
			zap.Duration("duration", duration),
			zap.Error(err),
		)
	}
}

// RecordConnectionEvent records connection lifecycle events
func (m *Middleware) RecordConnectionEvent(ctx context.Context, tenant, event string) {
	if !m.config.Enabled || m.telemetry == nil {
		return
	}

	// Record connection change in metrics
	delta := int64(0)
	switch event {
	case "connected":
		delta = 1
	case "disconnected":
		delta = -1
	}

	if delta != 0 {
		m.telemetry.RecordConnectionChange(ctx, tenant, delta)
	}

	// Add span event if we're in a span
	m.telemetry.AddSpanEvent(ctx, "connection."+event,
		attribute.String("tenant", tenant),
	)

	// Log connection event
	m.logger.Info("Connection event",
		zap.String("tenant", tenant),
		zap.String("event", event),
	)
}

// RecordError records error events with context
func (m *Middleware) RecordError(ctx context.Context, component, errorType, tenant string, err error) {
	if !m.config.Enabled || m.telemetry == nil {
		return
	}

	// Record error metric
	m.telemetry.RecordError(ctx, component, errorType, tenant)

	// Add span event
	m.telemetry.AddSpanEvent(ctx, "error."+component,
		attribute.String("error_type", errorType),
		attribute.String("error", err.Error()),
	)

	// Set span status to error
	m.telemetry.SetSpanStatus(ctx, codes.Error, err.Error())

	// Log error
	m.logger.Error("Component error",
		zap.String("component", component),
		zap.String("error_type", errorType),
		zap.String("tenant", tenant),
		zap.Error(err),
	)
}

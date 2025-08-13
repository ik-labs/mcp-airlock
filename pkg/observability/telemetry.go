// Package observability provides OpenTelemetry tracing and metrics for MCP Airlock
package observability

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	// Service information
	serviceName    = "mcp-airlock"
	serviceVersion = "1.0.0"

	// Instrumentation scope
	instrumentationName = "github.com/ik-labs/mcp-airlock/pkg/observability"
)

// TelemetryConfig holds OpenTelemetry configuration
type TelemetryConfig struct {
	ServiceName     string
	ServiceVersion  string
	TracingEnabled  bool
	TracingEndpoint string
	MetricsEnabled  bool
	MetricsEndpoint string
}

// Telemetry provides OpenTelemetry tracing and metrics functionality
type Telemetry struct {
	config         *TelemetryConfig
	logger         *zap.Logger
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	tracer         trace.Tracer
	meter          metric.Meter

	// Metrics instruments
	requestCounter    metric.Int64Counter
	requestDuration   metric.Float64Histogram
	authCounter       metric.Int64Counter
	policyCounter     metric.Int64Counter
	redactionCounter  metric.Int64Counter
	errorCounter      metric.Int64Counter
	activeConnections metric.Int64UpDownCounter
	upstreamDuration  metric.Float64Histogram
}

// NewTelemetry creates a new telemetry instance
func NewTelemetry(config *TelemetryConfig, logger *zap.Logger) (*Telemetry, error) {
	if config == nil {
		config = &TelemetryConfig{
			ServiceName:    serviceName,
			ServiceVersion: serviceVersion,
		}
	}

	t := &Telemetry{
		config: config,
		logger: logger,
	}

	// Initialize resource
	res, err := t.createResource()
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Initialize tracing if enabled
	if config.TracingEnabled {
		if err := t.initTracing(res); err != nil {
			return nil, fmt.Errorf("failed to initialize tracing: %w", err)
		}
	}

	// Initialize metrics if enabled
	if config.MetricsEnabled {
		if err := t.initMetrics(res); err != nil {
			return nil, fmt.Errorf("failed to initialize metrics: %w", err)
		}
	}

	// Set global propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return t, nil
}

// createResource creates the OpenTelemetry resource
func (t *Telemetry) createResource() (*resource.Resource, error) {
	return resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(t.config.ServiceName),
		semconv.ServiceVersion(t.config.ServiceVersion),
		attribute.String("service.instance.id", fmt.Sprintf("%s-%d", t.config.ServiceName, time.Now().Unix())),
	), nil
}

// initTracing initializes OpenTelemetry tracing
func (t *Telemetry) initTracing(res *resource.Resource) error {
	// Create OTLP trace exporter
	exporter, err := otlptracehttp.New(
		context.Background(),
		otlptracehttp.WithEndpoint(t.config.TracingEndpoint),
		otlptracehttp.WithInsecure(), // Use HTTPS in production
	)
	if err != nil {
		return fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Create trace provider
	t.tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()), // Configure sampling in production
	)

	// Set global trace provider
	otel.SetTracerProvider(t.tracerProvider)

	// Create tracer
	t.tracer = t.tracerProvider.Tracer(
		instrumentationName,
		trace.WithInstrumentationVersion(t.config.ServiceVersion),
	)

	t.logger.Info("OpenTelemetry tracing initialized",
		zap.String("endpoint", t.config.TracingEndpoint),
	)

	return nil
}

// initMetrics initializes OpenTelemetry metrics
func (t *Telemetry) initMetrics(res *resource.Resource) error {
	// Create OTLP metric exporter
	exporter, err := otlpmetrichttp.New(
		context.Background(),
		otlpmetrichttp.WithEndpoint(t.config.MetricsEndpoint),
		otlpmetrichttp.WithInsecure(), // Use HTTPS in production
	)
	if err != nil {
		return fmt.Errorf("failed to create metric exporter: %w", err)
	}

	// Create meter provider
	t.meterProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter,
			sdkmetric.WithInterval(30*time.Second),
		)),
	)

	// Set global meter provider
	otel.SetMeterProvider(t.meterProvider)

	// Create meter
	t.meter = t.meterProvider.Meter(
		instrumentationName,
		metric.WithInstrumentationVersion(t.config.ServiceVersion),
	)

	// Initialize metric instruments
	if err := t.initMetricInstruments(); err != nil {
		return fmt.Errorf("failed to initialize metric instruments: %w", err)
	}

	t.logger.Info("OpenTelemetry metrics initialized",
		zap.String("endpoint", t.config.MetricsEndpoint),
	)

	return nil
}

// initMetricInstruments creates all metric instruments
func (t *Telemetry) initMetricInstruments() error {
	var err error

	// Request counter
	t.requestCounter, err = t.meter.Int64Counter(
		"airlock_requests_total",
		metric.WithDescription("Total number of MCP requests processed"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create request counter: %w", err)
	}

	// Request duration histogram
	t.requestDuration, err = t.meter.Float64Histogram(
		"airlock_request_duration_seconds",
		metric.WithDescription("Duration of MCP request processing"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
	)
	if err != nil {
		return fmt.Errorf("failed to create request duration histogram: %w", err)
	}

	// Authentication counter
	t.authCounter, err = t.meter.Int64Counter(
		"airlock_auth_events_total",
		metric.WithDescription("Total number of authentication events"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create auth counter: %w", err)
	}

	// Policy decision counter
	t.policyCounter, err = t.meter.Int64Counter(
		"airlock_policy_decisions_total",
		metric.WithDescription("Total number of policy decisions"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create policy counter: %w", err)
	}

	// Redaction counter
	t.redactionCounter, err = t.meter.Int64Counter(
		"airlock_redactions_total",
		metric.WithDescription("Total number of data redactions performed"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create redaction counter: %w", err)
	}

	// Error counter
	t.errorCounter, err = t.meter.Int64Counter(
		"airlock_errors_total",
		metric.WithDescription("Total number of errors"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create error counter: %w", err)
	}

	// Active connections gauge
	t.activeConnections, err = t.meter.Int64UpDownCounter(
		"airlock_active_connections",
		metric.WithDescription("Number of active MCP connections"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return fmt.Errorf("failed to create active connections gauge: %w", err)
	}

	// Upstream duration histogram
	t.upstreamDuration, err = t.meter.Float64Histogram(
		"airlock_upstream_duration_seconds",
		metric.WithDescription("Duration of upstream MCP calls"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
	)
	if err != nil {
		return fmt.Errorf("failed to create upstream duration histogram: %w", err)
	}

	return nil
}

// StartSpan starts a new trace span with the given name and attributes
func (t *Telemetry) StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if t.tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}

	return t.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// RecordRequest records a request metric with attributes
func (t *Telemetry) RecordRequest(ctx context.Context, tenant, tool, method, status string, duration time.Duration) {
	if t.requestCounter == nil || t.requestDuration == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("tenant", tenant),
		attribute.String("tool", tool),
		attribute.String("method", method),
		attribute.String("status", status),
	}

	t.requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	t.requestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
}

// RecordAuth records an authentication event
func (t *Telemetry) RecordAuth(ctx context.Context, tenant, result string) {
	if t.authCounter == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("tenant", tenant),
		attribute.String("result", result), // "success", "failure", "invalid_token"
	}

	t.authCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordPolicyDecision records a policy decision
func (t *Telemetry) RecordPolicyDecision(ctx context.Context, tenant, tool, resource, decision, ruleID string) {
	if t.policyCounter == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("tenant", tenant),
		attribute.String("tool", tool),
		attribute.String("resource", resource),
		attribute.String("decision", decision), // "allow", "deny"
		attribute.String("rule_id", ruleID),
	}

	t.policyCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordRedaction records a data redaction event
func (t *Telemetry) RecordRedaction(ctx context.Context, tenant, pattern string, count int) {
	if t.redactionCounter == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("tenant", tenant),
		attribute.String("pattern", pattern),
	}

	t.redactionCounter.Add(ctx, int64(count), metric.WithAttributes(attrs...))
}

// RecordError records an error event
func (t *Telemetry) RecordError(ctx context.Context, component, errorType, tenant string) {
	if t.errorCounter == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("component", component), // "auth", "policy", "upstream", "redaction"
		attribute.String("error_type", errorType),
		attribute.String("tenant", tenant),
	}

	t.errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordConnectionChange records a change in active connections
func (t *Telemetry) RecordConnectionChange(ctx context.Context, tenant string, delta int64) {
	if t.activeConnections == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("tenant", tenant),
	}

	t.activeConnections.Add(ctx, delta, metric.WithAttributes(attrs...))
}

// RecordUpstreamCall records an upstream call duration
func (t *Telemetry) RecordUpstreamCall(ctx context.Context, upstream, tenant, status string, duration time.Duration) {
	if t.upstreamDuration == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("upstream", upstream),
		attribute.String("tenant", tenant),
		attribute.String("status", status), // "success", "error", "timeout"
	}

	t.upstreamDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))
}

// AddSpanAttributes adds attributes to the current span
func (t *Telemetry) AddSpanAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(attrs...)
	}
}

// AddSpanEvent adds an event to the current span
func (t *Telemetry) AddSpanEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.AddEvent(name, trace.WithAttributes(attrs...))
	}
}

// SetSpanStatus sets the status of the current span
func (t *Telemetry) SetSpanStatus(ctx context.Context, code codes.Code, description string) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetStatus(code, description)
	}
}

// Shutdown gracefully shuts down the telemetry providers
func (t *Telemetry) Shutdown(ctx context.Context) error {
	var errs []error

	if t.tracerProvider != nil {
		if err := t.tracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to shutdown tracer provider: %w", err))
		}
	}

	if t.meterProvider != nil {
		if err := t.meterProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to shutdown meter provider: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("telemetry shutdown errors: %v", errs)
	}

	t.logger.Info("OpenTelemetry telemetry shutdown completed")
	return nil
}

// GetTracer returns the tracer instance
func (t *Telemetry) GetTracer() trace.Tracer {
	return t.tracer
}

// GetMeter returns the meter instance
func (t *Telemetry) GetMeter() metric.Meter {
	return t.meter
}

// Package observability provides integration utilities for setting up telemetry
package observability

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// SetupTelemetry initializes telemetry based on configuration
func SetupTelemetry(tracingEnabled bool, tracingEndpoint string, metricsEnabled bool, metricsEndpoint string, logger *zap.Logger) (*Telemetry, error) {
	config := &TelemetryConfig{
		ServiceName:     "mcp-airlock",
		ServiceVersion:  "1.0.0",
		TracingEnabled:  tracingEnabled,
		TracingEndpoint: tracingEndpoint,
		MetricsEnabled:  metricsEnabled,
		MetricsEndpoint: metricsEndpoint,
	}

	telemetry, err := NewTelemetry(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize telemetry: %w", err)
	}

	logger.Info("Telemetry initialized",
		zap.Bool("tracing_enabled", tracingEnabled),
		zap.String("tracing_endpoint", tracingEndpoint),
		zap.Bool("metrics_enabled", metricsEnabled),
		zap.String("metrics_endpoint", metricsEndpoint),
	)

	return telemetry, nil
}

// SetupMiddleware creates observability middleware
func SetupMiddleware(telemetry *Telemetry, logger *zap.Logger, enabled bool) *Middleware {
	config := &MiddlewareConfig{
		ServiceName: "mcp-airlock",
		Enabled:     enabled,
	}

	return NewMiddleware(telemetry, logger, config)
}

// GracefulShutdown performs graceful shutdown of telemetry
func GracefulShutdown(ctx context.Context, telemetry *Telemetry, logger *zap.Logger) error {
	if telemetry == nil {
		return nil
	}

	logger.Info("Shutting down telemetry...")

	if err := telemetry.Shutdown(ctx); err != nil {
		logger.Error("Failed to shutdown telemetry", zap.Error(err))
		return err
	}

	logger.Info("Telemetry shutdown completed")
	return nil
}

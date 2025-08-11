package redact

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RedactionMiddleware provides redaction capabilities for MCP request/response processing
type RedactionMiddleware struct {
	redactor RedactorInterface
	logger   *zap.Logger

	// Audit tracking
	auditLogger AuditLogger

	// Configuration (protected by configMu)
	configMu          sync.RWMutex
	enabled           bool
	redactRequests    bool
	redactResponses   bool
	redactBeforeLog   bool
	redactBeforeProxy bool
}

// AuditLogger interface for logging redaction events
type AuditLogger interface {
	LogRedactionEvent(ctx context.Context, event *RedactionAuditEvent) error
}

// RedactionAuditEvent represents a redaction event for audit purposes
type RedactionAuditEvent struct {
	CorrelationID  string         `json:"correlation_id"`
	Tenant         string         `json:"tenant"`
	Subject        string         `json:"subject"`
	Tool           string         `json:"tool"`
	Direction      string         `json:"direction"` // "request" or "response"
	RedactionCount int            `json:"redaction_count"`
	PatternsHit    map[string]int `json:"patterns_hit"`
	ProcessingTime time.Duration  `json:"processing_time"`
	Timestamp      time.Time      `json:"timestamp"`
	DataSize       int            `json:"data_size"`
}

// MiddlewareConfig holds configuration for the redaction middleware
type MiddlewareConfig struct {
	Enabled           bool `yaml:"enabled" json:"enabled"`
	RedactRequests    bool `yaml:"redact_requests" json:"redact_requests"`
	RedactResponses   bool `yaml:"redact_responses" json:"redact_responses"`
	RedactBeforeLog   bool `yaml:"redact_before_log" json:"redact_before_log"`
	RedactBeforeProxy bool `yaml:"redact_before_proxy" json:"redact_before_proxy"`
}

// DefaultMiddlewareConfig returns default middleware configuration
func DefaultMiddlewareConfig() *MiddlewareConfig {
	return &MiddlewareConfig{
		Enabled:           true,
		RedactRequests:    true,
		RedactResponses:   true,
		RedactBeforeLog:   true,
		RedactBeforeProxy: true,
	}
}

// NewRedactionMiddleware creates a new redaction middleware
func NewRedactionMiddleware(redactor RedactorInterface, logger *zap.Logger, config *MiddlewareConfig) *RedactionMiddleware {
	if config == nil {
		config = DefaultMiddlewareConfig()
	}

	return &RedactionMiddleware{
		redactor:          redactor,
		logger:            logger,
		enabled:           config.Enabled,
		redactRequests:    config.RedactRequests,
		redactResponses:   config.RedactResponses,
		redactBeforeLog:   config.RedactBeforeLog,
		redactBeforeProxy: config.RedactBeforeProxy,
	}
}

// SetAuditLogger sets the audit logger for redaction events
func (rm *RedactionMiddleware) SetAuditLogger(auditLogger AuditLogger) {
	rm.auditLogger = auditLogger
}

// ProcessRequest applies redaction to request data before logging and proxying
func (rm *RedactionMiddleware) ProcessRequest(ctx context.Context, data []byte) ([]byte, error) {
	rm.configMu.RLock()
	enabled := rm.enabled
	redactRequests := rm.redactRequests
	rm.configMu.RUnlock()

	if !enabled || !redactRequests {
		return data, nil
	}

	correlationID := rm.getCorrelationID(ctx)

	rm.logger.Debug("Processing request redaction",
		zap.String("correlation_id", correlationID),
		zap.Int("data_size", len(data)),
	)

	result, err := rm.redactor.RedactRequest(ctx, data)
	if err != nil {
		rm.logger.Error("Request redaction failed",
			zap.String("correlation_id", correlationID),
			zap.Error(err),
		)
		return data, fmt.Errorf("request redaction failed: %w", err)
	}

	// Log redaction event for audit
	if err := rm.logRedactionEvent(ctx, "request", result, len(data)); err != nil {
		rm.logger.Warn("Failed to log redaction audit event",
			zap.String("correlation_id", correlationID),
			zap.Error(err),
		)
	}

	rm.logger.Debug("Request redaction completed",
		zap.String("correlation_id", correlationID),
		zap.Int("original_size", len(data)),
		zap.Int("redacted_size", len(result.Data)),
		zap.Int("redaction_count", result.RedactionCount),
		zap.Duration("processing_time", result.ProcessingTime),
	)

	return result.Data, nil
}

// ProcessResponse applies redaction to response data before logging
func (rm *RedactionMiddleware) ProcessResponse(ctx context.Context, data []byte) ([]byte, error) {
	rm.configMu.RLock()
	enabled := rm.enabled
	redactResponses := rm.redactResponses
	rm.configMu.RUnlock()

	if !enabled || !redactResponses {
		return data, nil
	}

	correlationID := rm.getCorrelationID(ctx)

	rm.logger.Debug("Processing response redaction",
		zap.String("correlation_id", correlationID),
		zap.Int("data_size", len(data)),
	)

	result, err := rm.redactor.RedactResponse(ctx, data)
	if err != nil {
		rm.logger.Error("Response redaction failed",
			zap.String("correlation_id", correlationID),
			zap.Error(err),
		)
		return data, fmt.Errorf("response redaction failed: %w", err)
	}

	// Log redaction event for audit
	if err := rm.logRedactionEvent(ctx, "response", result, len(data)); err != nil {
		rm.logger.Warn("Failed to log redaction audit event",
			zap.String("correlation_id", correlationID),
			zap.Error(err),
		)
	}

	rm.logger.Debug("Response redaction completed",
		zap.String("correlation_id", correlationID),
		zap.Int("original_size", len(data)),
		zap.Int("redacted_size", len(result.Data)),
		zap.Int("redaction_count", result.RedactionCount),
		zap.Duration("processing_time", result.ProcessingTime),
	)

	return result.Data, nil
}

// ProcessJSONMessage applies redaction to JSON-RPC messages
func (rm *RedactionMiddleware) ProcessJSONMessage(ctx context.Context, message map[string]interface{}, direction string) (map[string]interface{}, error) {
	rm.configMu.RLock()
	enabled := rm.enabled
	redactRequests := rm.redactRequests
	redactResponses := rm.redactResponses
	rm.configMu.RUnlock()

	if !enabled {
		return message, nil
	}

	// Skip redaction if not configured for this direction
	if (direction == "request" && !redactRequests) || (direction == "response" && !redactResponses) {
		return message, nil
	}

	correlationID := rm.getCorrelationID(ctx)

	// Marshal message to JSON for redaction
	data, err := json.Marshal(message)
	if err != nil {
		return message, fmt.Errorf("failed to marshal message for redaction: %w", err)
	}

	// Apply redaction
	var result *RedactionResult
	if direction == "request" {
		result, err = rm.redactor.RedactRequest(ctx, data)
	} else {
		result, err = rm.redactor.RedactResponse(ctx, data)
	}

	if err != nil {
		rm.logger.Error("JSON message redaction failed",
			zap.String("correlation_id", correlationID),
			zap.String("direction", direction),
			zap.Error(err),
		)
		return message, fmt.Errorf("JSON message redaction failed: %w", err)
	}

	// Unmarshal redacted data back to message
	var redactedMessage map[string]interface{}
	if err := json.Unmarshal(result.Data, &redactedMessage); err != nil {
		rm.logger.Error("Failed to unmarshal redacted message",
			zap.String("correlation_id", correlationID),
			zap.String("direction", direction),
			zap.Error(err),
		)
		return message, fmt.Errorf("failed to unmarshal redacted message: %w", err)
	}

	// Log redaction event for audit
	if err := rm.logRedactionEvent(ctx, direction, result, len(data)); err != nil {
		rm.logger.Warn("Failed to log redaction audit event",
			zap.String("correlation_id", correlationID),
			zap.Error(err),
		)
	}

	rm.logger.Debug("JSON message redaction completed",
		zap.String("correlation_id", correlationID),
		zap.String("direction", direction),
		zap.Int("redaction_count", result.RedactionCount),
		zap.Duration("processing_time", result.ProcessingTime),
	)

	return redactedMessage, nil
}

// RedactForLogging applies redaction specifically for logging purposes
func (rm *RedactionMiddleware) RedactForLogging(ctx context.Context, data []byte) ([]byte, error) {
	rm.configMu.RLock()
	enabled := rm.enabled
	redactBeforeLog := rm.redactBeforeLog
	rm.configMu.RUnlock()

	if !enabled || !redactBeforeLog {
		return data, nil
	}

	result, err := rm.redactor.RedactRequest(ctx, data)
	if err != nil {
		rm.logger.Warn("Logging redaction failed, using original data",
			zap.String("correlation_id", rm.getCorrelationID(ctx)),
			zap.Error(err),
		)
		return data, nil // Don't fail logging, just use original data
	}

	return result.Data, nil
}

// RedactForProxy applies redaction specifically before proxying to upstream
func (rm *RedactionMiddleware) RedactForProxy(ctx context.Context, data []byte) ([]byte, error) {
	rm.configMu.RLock()
	enabled := rm.enabled
	redactBeforeProxy := rm.redactBeforeProxy
	rm.configMu.RUnlock()

	if !enabled || !redactBeforeProxy {
		return data, nil
	}

	result, err := rm.redactor.RedactRequest(ctx, data)
	if err != nil {
		return data, fmt.Errorf("proxy redaction failed: %w", err)
	}

	return result.Data, nil
}

// GetStats returns middleware statistics
func (rm *RedactionMiddleware) GetStats() map[string]interface{} {
	rm.configMu.RLock()
	stats := map[string]interface{}{
		"enabled":             rm.enabled,
		"redact_requests":     rm.redactRequests,
		"redact_responses":    rm.redactResponses,
		"redact_before_log":   rm.redactBeforeLog,
		"redact_before_proxy": rm.redactBeforeProxy,
	}
	rm.configMu.RUnlock()

	// Include redactor stats if available
	if rm.redactor != nil {
		stats["redactor"] = rm.redactor.Stats()
	}

	return stats
}

// UpdateConfig updates the middleware configuration
func (rm *RedactionMiddleware) UpdateConfig(config *MiddlewareConfig) {
	if config == nil {
		return
	}

	rm.configMu.Lock()
	rm.enabled = config.Enabled
	rm.redactRequests = config.RedactRequests
	rm.redactResponses = config.RedactResponses
	rm.redactBeforeLog = config.RedactBeforeLog
	rm.redactBeforeProxy = config.RedactBeforeProxy

	// Capture values for logging while holding the lock
	enabled := rm.enabled
	redactRequests := rm.redactRequests
	redactResponses := rm.redactResponses
	redactBeforeLog := rm.redactBeforeLog
	redactBeforeProxy := rm.redactBeforeProxy
	rm.configMu.Unlock()

	rm.logger.Info("Redaction middleware configuration updated",
		zap.Bool("enabled", enabled),
		zap.Bool("redact_requests", redactRequests),
		zap.Bool("redact_responses", redactResponses),
		zap.Bool("redact_before_log", redactBeforeLog),
		zap.Bool("redact_before_proxy", redactBeforeProxy),
	)
}

// LoadPatterns loads redaction patterns into the underlying redactor
func (rm *RedactionMiddleware) LoadPatterns(patterns []Pattern) error {
	if rm.redactor == nil {
		return fmt.Errorf("redactor not initialized")
	}

	err := rm.redactor.LoadPatterns(patterns)
	if err != nil {
		rm.logger.Error("Failed to load redaction patterns", zap.Error(err))
		return fmt.Errorf("failed to load redaction patterns: %w", err)
	}

	rm.logger.Info("Redaction patterns loaded successfully",
		zap.Int("pattern_count", len(patterns)),
	)

	return nil
}

// logRedactionEvent logs a redaction event for audit purposes
func (rm *RedactionMiddleware) logRedactionEvent(ctx context.Context, direction string, result *RedactionResult, originalSize int) error {
	if rm.auditLogger == nil {
		return nil // No audit logger configured
	}

	event := &RedactionAuditEvent{
		CorrelationID:  rm.getCorrelationID(ctx),
		Tenant:         rm.getTenant(ctx),
		Subject:        rm.getSubject(ctx),
		Tool:           rm.getTool(ctx),
		Direction:      direction,
		RedactionCount: result.RedactionCount,
		PatternsHit:    result.PatternsHit,
		ProcessingTime: result.ProcessingTime,
		Timestamp:      time.Now().UTC(),
		DataSize:       originalSize,
	}

	return rm.auditLogger.LogRedactionEvent(ctx, event)
}

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// Context keys for request metadata
const (
	correlationIDKey contextKey = "correlation_id"
	tenantKey        contextKey = "tenant"
	subjectKey       contextKey = "subject"
	toolKey          contextKey = "tool"
)

// Helper functions to create contexts with proper typed keys
func withCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDKey, id)
}

func withTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey, tenant)
}

func withSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, subjectKey, subject)
}

func withTool(ctx context.Context, tool string) context.Context {
	return context.WithValue(ctx, toolKey, tool)
}

// Helper methods to extract context values
func (rm *RedactionMiddleware) getCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value(correlationIDKey).(string); ok {
		return id
	}
	return "unknown"
}

func (rm *RedactionMiddleware) getTenant(ctx context.Context) string {
	if tenant, ok := ctx.Value(tenantKey).(string); ok {
		return tenant
	}
	return "unknown"
}

func (rm *RedactionMiddleware) getSubject(ctx context.Context) string {
	if subject, ok := ctx.Value(subjectKey).(string); ok {
		return subject
	}
	return "unknown"
}

func (rm *RedactionMiddleware) getTool(ctx context.Context) string {
	if tool, ok := ctx.Value(toolKey).(string); ok {
		return tool
	}
	return "unknown"
}

package audit

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// SecurityAuditLogger provides unified audit logging for all security events
type SecurityAuditLogger struct {
	auditLogger AuditLogger
	logger      *zap.Logger
}

// NewSecurityAuditLogger creates a new security audit logger
func NewSecurityAuditLogger(auditLogger AuditLogger, logger *zap.Logger) *SecurityAuditLogger {
	return &SecurityAuditLogger{
		auditLogger: auditLogger,
		logger:      logger,
	}
}

// LogAuthenticationEvent logs an authentication event
func (sal *SecurityAuditLogger) LogAuthenticationEvent(ctx context.Context, correlationID, subject, decision, reason string, latency time.Duration, metadata map[string]interface{}) error {
	event := NewEvent(ActionTokenValidate).
		WithCorrelationID(correlationID).
		WithSubject(subject).
		WithDecision(decision).
		WithReason(reason).
		WithLatency(latency).
		WithMetadataMap(metadata).
		Build()

	// Extract tenant from metadata if available
	if tenant, ok := metadata["tenant"].(string); ok {
		event.Tenant = tenant
	}

	return sal.auditLogger.LogEvent(ctx, event)
}

// LogAuthorizationEvent logs an authorization/policy decision event
func (sal *SecurityAuditLogger) LogAuthorizationEvent(ctx context.Context, correlationID, tenant, subject, resource, decision, reason string, latency time.Duration, metadata map[string]interface{}) error {
	event := NewEvent(ActionPolicyEvaluate).
		WithCorrelationID(correlationID).
		WithTenant(tenant).
		WithSubject(subject).
		WithResource(resource).
		WithDecision(decision).
		WithReason(reason).
		WithLatency(latency).
		WithMetadataMap(metadata).
		Build()

	return sal.auditLogger.LogEvent(ctx, event)
}

// LogRedactionEvent logs a redaction event
func (sal *SecurityAuditLogger) LogRedactionEvent(ctx context.Context, correlationID, tenant, subject, tool, direction string, redactionCount int, patternsHit map[string]int, processingTime time.Duration, dataSize int) error {
	metadata := map[string]interface{}{
		"tool":            tool,
		"direction":       direction,
		"patterns_hit":    patternsHit,
		"processing_time": processingTime,
		"data_size":       dataSize,
	}

	event := NewEvent(ActionRedactData).
		WithCorrelationID(correlationID).
		WithTenant(tenant).
		WithSubject(subject).
		WithDecision(DecisionAllow).
		WithReason("DLP patterns matched").
		WithRedactionCount(redactionCount).
		WithLatency(processingTime).
		WithMetadataMap(metadata).
		Build()

	return sal.auditLogger.LogEvent(ctx, event)
}

// LogSecurityViolationEvent logs a security violation event
func (sal *SecurityAuditLogger) LogSecurityViolationEvent(ctx context.Context, correlationID, tenant, subject, violation, resource string, metadata map[string]interface{}) error {
	event := NewEvent(EventTypeSecurityViolation).
		WithCorrelationID(correlationID).
		WithTenant(tenant).
		WithSubject(subject).
		WithResource(resource).
		WithDecision(DecisionDeny).
		WithReason(violation).
		WithMetadataMap(metadata).
		Build()

	return sal.auditLogger.LogEvent(ctx, event)
}

// LogRateLimitEvent logs a rate limiting event
func (sal *SecurityAuditLogger) LogRateLimitEvent(ctx context.Context, correlationID, tenant, subject string, metadata map[string]interface{}) error {
	event := NewEvent(ActionRateLimitHit).
		WithCorrelationID(correlationID).
		WithTenant(tenant).
		WithSubject(subject).
		WithDecision(DecisionDeny).
		WithReason("Rate limit exceeded").
		WithMetadataMap(metadata).
		Build()

	return sal.auditLogger.LogEvent(ctx, event)
}

// LogPathTraversalAttempt logs a path traversal security violation
func (sal *SecurityAuditLogger) LogPathTraversalAttempt(ctx context.Context, correlationID, tenant, subject, attemptedPath, resource string) error {
	metadata := map[string]interface{}{
		"attempted_path": attemptedPath,
		"violation_type": "path_traversal",
	}

	return sal.LogSecurityViolationEvent(ctx, correlationID, tenant, subject, "Path traversal attempt detected", resource, metadata)
}

// LogResourceAccessEvent logs a resource access event
func (sal *SecurityAuditLogger) LogResourceAccessEvent(ctx context.Context, correlationID, tenant, subject, resource, action string, metadata map[string]interface{}) error {
	event := NewEvent(action).
		WithCorrelationID(correlationID).
		WithTenant(tenant).
		WithSubject(subject).
		WithResource(resource).
		WithDecision(DecisionAllow).
		WithMetadataMap(metadata).
		Build()

	return sal.auditLogger.LogEvent(ctx, event)
}

// LogSystemEvent logs a system-level event
func (sal *SecurityAuditLogger) LogSystemEvent(ctx context.Context, correlationID, action, reason string, metadata map[string]interface{}) error {
	event := NewEvent(action).
		WithCorrelationID(correlationID).
		WithDecision(DecisionAllow).
		WithReason(reason).
		WithMetadataMap(metadata).
		Build()

	return sal.auditLogger.LogEvent(ctx, event)
}

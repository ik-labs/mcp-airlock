package audit

import (
	"context"
	"time"

	"github.com/ik-labs/mcp-airlock/pkg/auth"
	"github.com/ik-labs/mcp-airlock/pkg/policy"
	"github.com/ik-labs/mcp-airlock/pkg/redact"
)

// RedactionAuditAdapter adapts the SecurityAuditLogger to the redaction middleware's AuditLogger interface
type RedactionAuditAdapter struct {
	securityLogger *SecurityAuditLogger
}

// NewRedactionAuditAdapter creates a new redaction audit adapter
func NewRedactionAuditAdapter(securityLogger *SecurityAuditLogger) *RedactionAuditAdapter {
	return &RedactionAuditAdapter{
		securityLogger: securityLogger,
	}
}

// LogRedactionEvent implements the redaction middleware's AuditLogger interface
func (raa *RedactionAuditAdapter) LogRedactionEvent(ctx context.Context, event *redact.RedactionAuditEvent) error {
	return raa.securityLogger.LogRedactionEvent(
		ctx,
		event.CorrelationID,
		event.Tenant,
		event.Subject,
		event.Tool,
		event.Direction,
		event.RedactionCount,
		event.PatternsHit,
		event.ProcessingTime,
		event.DataSize,
	)
}

// AuthenticationAuditAdapter adapts the SecurityAuditLogger to the auth middleware's AuditLogger interface
type AuthenticationAuditAdapter struct {
	securityLogger *SecurityAuditLogger
}

// NewAuthenticationAuditAdapter creates a new authentication audit adapter
func NewAuthenticationAuditAdapter(securityLogger *SecurityAuditLogger) *AuthenticationAuditAdapter {
	return &AuthenticationAuditAdapter{
		securityLogger: securityLogger,
	}
}

// LogEvent implements the auth middleware's AuditLogger interface
func (aaa *AuthenticationAuditAdapter) LogEvent(ctx context.Context, event *auth.AuthenticationAuditEvent) error {
	latency := time.Duration(event.LatencyMs) * time.Millisecond
	return aaa.securityLogger.LogAuthenticationEvent(
		ctx,
		event.CorrelationID,
		event.Subject,
		event.Decision,
		event.Reason,
		latency,
		event.Metadata,
	)
}

// PolicyAuditAdapter adapts the SecurityAuditLogger to the policy middleware's AuditLogger interface
type PolicyAuditAdapter struct {
	securityLogger *SecurityAuditLogger
}

// NewPolicyAuditAdapter creates a new policy audit adapter
func NewPolicyAuditAdapter(securityLogger *SecurityAuditLogger) *PolicyAuditAdapter {
	return &PolicyAuditAdapter{
		securityLogger: securityLogger,
	}
}

// LogEvent implements the policy middleware's AuditLogger interface
func (paa *PolicyAuditAdapter) LogEvent(ctx context.Context, event *policy.PolicyAuditEvent) error {
	latency := time.Duration(event.LatencyMs) * time.Millisecond
	return paa.securityLogger.LogAuthorizationEvent(
		ctx,
		event.CorrelationID,
		event.Tenant,
		event.Subject,
		event.Resource,
		event.Decision,
		event.Reason,
		latency,
		event.Metadata,
	)
}

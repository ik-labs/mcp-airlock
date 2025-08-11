package audit

import (
	"context"
	"time"
)

// RedactionAuditAdapter adapts the SecurityAuditLogger to the redaction middleware's AuditLogger interface
type RedactionAuditAdapter struct {
	securityLogger *SecurityAuditLogger
}

// RedactionAuditEvent represents a redaction event for audit purposes (from redaction middleware)
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

// NewRedactionAuditAdapter creates a new redaction audit adapter
func NewRedactionAuditAdapter(securityLogger *SecurityAuditLogger) *RedactionAuditAdapter {
	return &RedactionAuditAdapter{
		securityLogger: securityLogger,
	}
}

// LogRedactionEvent implements the redaction middleware's AuditLogger interface
func (raa *RedactionAuditAdapter) LogRedactionEvent(ctx context.Context, event *RedactionAuditEvent) error {
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

// AuthenticationAuditEvent represents an authentication audit event (from auth middleware)
type AuthenticationAuditEvent struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	CorrelationID string                 `json:"correlation_id"`
	Tenant        string                 `json:"tenant"`
	Subject       string                 `json:"subject"`
	Action        string                 `json:"action"`
	Resource      string                 `json:"resource"`
	Decision      string                 `json:"decision"`
	Reason        string                 `json:"reason"`
	Metadata      map[string]interface{} `json:"metadata"`
	LatencyMs     int64                  `json:"latency_ms,omitempty"`
}

// NewAuthenticationAuditAdapter creates a new authentication audit adapter
func NewAuthenticationAuditAdapter(securityLogger *SecurityAuditLogger) *AuthenticationAuditAdapter {
	return &AuthenticationAuditAdapter{
		securityLogger: securityLogger,
	}
}

// LogEvent implements the auth middleware's AuditLogger interface
func (aaa *AuthenticationAuditAdapter) LogEvent(ctx context.Context, event *AuthenticationAuditEvent) error {
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

// PolicyAuditEvent represents a policy audit event (from policy middleware)
type PolicyAuditEvent struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	CorrelationID string                 `json:"correlation_id"`
	Tenant        string                 `json:"tenant"`
	Subject       string                 `json:"subject"`
	Action        string                 `json:"action"`
	Resource      string                 `json:"resource"`
	Decision      string                 `json:"decision"`
	Reason        string                 `json:"reason"`
	Metadata      map[string]interface{} `json:"metadata"`
	LatencyMs     int64                  `json:"latency_ms,omitempty"`
}

// NewPolicyAuditAdapter creates a new policy audit adapter
func NewPolicyAuditAdapter(securityLogger *SecurityAuditLogger) *PolicyAuditAdapter {
	return &PolicyAuditAdapter{
		securityLogger: securityLogger,
	}
}

// LogEvent implements the policy middleware's AuditLogger interface
func (paa *PolicyAuditAdapter) LogEvent(ctx context.Context, event *PolicyAuditEvent) error {
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

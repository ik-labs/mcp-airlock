package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// EventBuilder provides a fluent interface for creating audit events
type EventBuilder struct {
	event *AuditEvent
}

// NewEvent creates a new audit event builder with required fields
func NewEvent(action string) *EventBuilder {
	return &EventBuilder{
		event: &AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now().UTC(),
			Action:    action,
			Metadata:  make(map[string]interface{}),
		},
	}
}

// WithCorrelationID sets the correlation ID for request tracing
func (b *EventBuilder) WithCorrelationID(correlationID string) *EventBuilder {
	b.event.CorrelationID = correlationID
	return b
}

// WithTenant sets the tenant context
func (b *EventBuilder) WithTenant(tenant string) *EventBuilder {
	b.event.Tenant = tenant
	return b
}

// WithSubject sets the subject (user/service) performing the action
func (b *EventBuilder) WithSubject(subject string) *EventBuilder {
	b.event.Subject = subject
	return b
}

// WithResource sets the resource being accessed
func (b *EventBuilder) WithResource(resource string) *EventBuilder {
	b.event.Resource = resource
	return b
}

// WithDecision sets the authorization decision
func (b *EventBuilder) WithDecision(decision string) *EventBuilder {
	b.event.Decision = decision
	return b
}

// WithReason sets the reason for the decision
func (b *EventBuilder) WithReason(reason string) *EventBuilder {
	b.event.Reason = reason
	return b
}

// WithLatency sets the operation latency in milliseconds
func (b *EventBuilder) WithLatency(latency time.Duration) *EventBuilder {
	b.event.LatencyMs = latency.Milliseconds()
	return b
}

// WithRedactionCount sets the number of redactions performed
func (b *EventBuilder) WithRedactionCount(count int) *EventBuilder {
	b.event.RedactionCount = count
	return b
}

// WithMetadata adds metadata key-value pairs
func (b *EventBuilder) WithMetadata(key string, value interface{}) *EventBuilder {
	b.event.Metadata[key] = value
	return b
}

// WithMetadataMap adds multiple metadata key-value pairs
func (b *EventBuilder) WithMetadataMap(metadata map[string]interface{}) *EventBuilder {
	for k, v := range metadata {
		b.event.Metadata[k] = v
	}
	return b
}

// Build returns the constructed audit event
func (b *EventBuilder) Build() *AuditEvent {
	return b.event
}

// Helper functions for common audit events

// NewAuthenticationEvent creates an authentication audit event
func NewAuthenticationEvent(correlationID, subject, decision, reason string) *AuditEvent {
	return NewEvent(ActionTokenValidate).
		WithCorrelationID(correlationID).
		WithSubject(subject).
		WithDecision(decision).
		WithReason(reason).
		Build()
}

// NewAuthorizationEvent creates an authorization audit event
func NewAuthorizationEvent(correlationID, tenant, subject, resource, decision, reason string) *AuditEvent {
	return NewEvent(ActionPolicyEvaluate).
		WithCorrelationID(correlationID).
		WithTenant(tenant).
		WithSubject(subject).
		WithResource(resource).
		WithDecision(decision).
		WithReason(reason).
		Build()
}

// NewResourceAccessEvent creates a resource access audit event
func NewResourceAccessEvent(correlationID, tenant, subject, resource, action string) *AuditEvent {
	return NewEvent(action).
		WithCorrelationID(correlationID).
		WithTenant(tenant).
		WithSubject(subject).
		WithResource(resource).
		WithDecision(DecisionAllow).
		Build()
}

// NewRedactionEvent creates a redaction audit event
func NewRedactionEvent(correlationID, tenant string, redactionCount int) *AuditEvent {
	return NewEvent(ActionRedactData).
		WithCorrelationID(correlationID).
		WithTenant(tenant).
		WithRedactionCount(redactionCount).
		WithDecision(DecisionAllow).
		WithReason("DLP patterns matched").
		Build()
}

// NewSecurityViolationEvent creates a security violation audit event
func NewSecurityViolationEvent(correlationID, tenant, subject, violation, resource string) *AuditEvent {
	return NewEvent(EventTypeSecurityViolation).
		WithCorrelationID(correlationID).
		WithTenant(tenant).
		WithSubject(subject).
		WithResource(resource).
		WithDecision(DecisionDeny).
		WithReason(violation).
		Build()
}

// NewRateLimitEvent creates a rate limiting audit event
func NewRateLimitEvent(correlationID, tenant, subject string, metadata map[string]interface{}) *AuditEvent {
	return NewEvent(ActionRateLimitHit).
		WithCorrelationID(correlationID).
		WithTenant(tenant).
		WithSubject(subject).
		WithDecision(DecisionDeny).
		WithReason("Rate limit exceeded").
		WithMetadataMap(metadata).
		Build()
}

// NewTombstoneEvent creates a tombstone event for subject erasure
func NewTombstoneEvent(correlationID, subject, reason string) *AuditEvent {
	return NewEvent(ActionTombstone).
		WithCorrelationID(correlationID).
		WithSubject(subject).
		WithDecision(DecisionAllow).
		WithReason(reason).
		WithMetadata("erased_subject", subject).
		Build()
}

// NewRetentionCleanupEvent creates a retention cleanup audit event
func NewRetentionCleanupEvent(correlationID string, deletedCount int, cutoffTime time.Time) *AuditEvent {
	return NewEvent(ActionRetentionCleanup).
		WithCorrelationID(correlationID).
		WithDecision(DecisionAllow).
		WithReason("Automatic retention cleanup").
		WithMetadata("deleted_count", deletedCount).
		WithMetadata("cutoff_time", cutoffTime.Format(time.RFC3339)).
		Build()
}

// ContextKey type for context values
type ContextKey string

const (
	// ContextKeyCorrelationID is the context key for correlation IDs
	ContextKeyCorrelationID ContextKey = "correlation_id"
	// ContextKeyTenant is the context key for tenant information
	ContextKeyTenant ContextKey = "tenant"
	// ContextKeySubject is the context key for subject information
	ContextKeySubject ContextKey = "subject"
)

// GetCorrelationID extracts correlation ID from context
func GetCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value(ContextKeyCorrelationID).(string); ok {
		return id
	}
	return ""
}

// GetTenant extracts tenant from context
func GetTenant(ctx context.Context) string {
	if tenant, ok := ctx.Value(ContextKeyTenant).(string); ok {
		return tenant
	}
	return ""
}

// GetSubject extracts subject from context
func GetSubject(ctx context.Context) string {
	if subject, ok := ctx.Value(ContextKeySubject).(string); ok {
		return subject
	}
	return ""
}

// WithCorrelationID adds correlation ID to context
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, ContextKeyCorrelationID, correlationID)
}

// WithTenant adds tenant to context
func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, ContextKeyTenant, tenant)
}

// WithSubject adds subject to context
func WithSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, ContextKeySubject, subject)
}

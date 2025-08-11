// Package audit provides tamper-evident audit logging with Blake3 hash chaining
// for compliance and security monitoring in the MCP Airlock gateway.
package audit

import (
	"context"
	"io"
	"time"
)

// AuditLogger defines the interface for audit event logging with hash chaining
type AuditLogger interface {
	// LogEvent records an audit event with hash chaining for tamper detection
	LogEvent(ctx context.Context, event *AuditEvent) error

	// Query retrieves audit events based on filter criteria
	Query(ctx context.Context, filter *QueryFilter) ([]*AuditEvent, error)

	// Export writes audit events to the provided writer in the specified format
	Export(ctx context.Context, format string, writer io.Writer) error

	// Close gracefully shuts down the audit logger
	Close() error

	// GetLastHash returns the hash of the most recent audit event
	GetLastHash(ctx context.Context) (string, error)

	// ValidateChain verifies the integrity of the hash chain
	ValidateChain(ctx context.Context) error
}

// AuditEvent represents a single audit log entry with hash chaining
type AuditEvent struct {
	// Core event fields
	ID            string    `json:"id" db:"id"`
	Timestamp     time.Time `json:"timestamp" db:"timestamp"`
	CorrelationID string    `json:"correlation_id" db:"correlation_id"`

	// Security context
	Tenant  string `json:"tenant" db:"tenant"`
	Subject string `json:"subject" db:"subject"`

	// Event details
	Action   string `json:"action" db:"action"`
	Resource string `json:"resource" db:"resource"`
	Decision string `json:"decision" db:"decision"`
	Reason   string `json:"reason" db:"reason"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata" db:"metadata"`

	// Hash chaining for tamper detection
	Hash         string `json:"hash" db:"hash"`
	PreviousHash string `json:"previous_hash" db:"previous_hash"`

	// Performance metrics
	LatencyMs int64 `json:"latency_ms,omitempty" db:"latency_ms"`

	// Redaction counts (no sensitive data)
	RedactionCount int `json:"redaction_count,omitempty" db:"redaction_count"`
}

// QueryFilter defines criteria for querying audit events
type QueryFilter struct {
	// Time range
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`

	// Security context filters
	Tenant  string `json:"tenant,omitempty"`
	Subject string `json:"subject,omitempty"`

	// Event filters
	Action   string `json:"action,omitempty"`
	Decision string `json:"decision,omitempty"`

	// Correlation tracking
	CorrelationID string `json:"correlation_id,omitempty"`

	// Pagination
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`

	// Ordering
	OrderBy   string `json:"order_by,omitempty"`
	OrderDesc bool   `json:"order_desc,omitempty"`
}

// AuditConfig defines configuration for the audit logging system
type AuditConfig struct {
	// Backend configuration
	Backend  string `yaml:"backend" json:"backend"`   // "sqlite", "postgres"
	Database string `yaml:"database" json:"database"` // connection string or file path

	// Retention policy
	RetentionDays int `yaml:"retention_days" json:"retention_days"` // default: 30

	// Export settings
	ExportFormat string `yaml:"export_format" json:"export_format"` // "jsonl", "csv"
	ExportPath   string `yaml:"export_path" json:"export_path"`     // S3 bucket or file path

	// Performance tuning
	BatchSize    int           `yaml:"batch_size" json:"batch_size"`       // events per batch write
	FlushTimeout time.Duration `yaml:"flush_timeout" json:"flush_timeout"` // max time before flush

	// Security settings
	EncryptionKey string `yaml:"encryption_key" json:"encryption_key"` // KMS key for S3 export
}

// EventType constants for common audit event types
const (
	EventTypeAuthentication    = "authentication"
	EventTypeAuthorization     = "authorization"
	EventTypePolicyDecision    = "policy_decision"
	EventTypeRedaction         = "redaction"
	EventTypeResourceAccess    = "resource_access"
	EventTypeSecurityViolation = "security_violation"
	EventTypeSystemEvent       = "system_event"
)

// Decision constants for audit events
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
	DecisionError = "error"
)

// Action constants for common audit actions
const (
	ActionLogin          = "login"
	ActionLogout         = "logout"
	ActionTokenValidate  = "token_validate"
	ActionPolicyEvaluate = "policy_evaluate"
	ActionResourceRead   = "resource_read"
	ActionResourceWrite  = "resource_write"
	ActionToolCall       = "tool_call"
	ActionRedactData     = "redact_data"
	ActionRateLimitHit   = "rate_limit_hit"
	ActionPathTraversal  = "path_traversal_attempt"
)

// Package audit provides tamper-evident audit logging with Blake3 hash chaining
// for compliance and security monitoring in the MCP Airlock gateway.
package audit

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
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

	// Flush ensures all pending events are written and returns any error
	Flush() error

	// CleanupExpiredEvents removes events older than the retention period
	CleanupExpiredEvents(ctx context.Context) (int, error)

	// CreateTombstone creates a tombstone event for subject erasure
	CreateTombstone(ctx context.Context, subject, reason string) error

	// ExportToS3 exports audit events to S3 with optional KMS encryption
	ExportToS3(ctx context.Context, bucket, prefix string, kmsKeyID string) error
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

// Validate checks if the audit event has valid required fields
func (e *AuditEvent) Validate() error {
	if e.ID == "" {
		return fmt.Errorf("audit event ID is required")
	}
	if e.Action == "" {
		return fmt.Errorf("audit event Action is required")
	}
	if e.Subject == "" {
		return fmt.Errorf("audit event Subject is required")
	}
	if e.CorrelationID == "" {
		return fmt.Errorf("audit event CorrelationID is required")
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("audit event Timestamp is required")
	}

	// Validate Decision if set
	if e.Decision != "" {
		switch e.Decision {
		case DecisionAllow, DecisionDeny, DecisionError:
			// Valid decision
		default:
			return fmt.Errorf("invalid Decision value: %s (must be one of: %s, %s, %s)",
				e.Decision, DecisionAllow, DecisionDeny, DecisionError)
		}
	}

	// Validate non-negative numeric fields
	if e.LatencyMs < 0 {
		return fmt.Errorf("LatencyMs must be non-negative, got: %d", e.LatencyMs)
	}
	if e.RedactionCount < 0 {
		return fmt.Errorf("RedactionCount must be non-negative, got: %d", e.RedactionCount)
	}

	return nil
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

	// S3 export settings
	S3Bucket string `yaml:"s3_bucket" json:"s3_bucket"`   // S3 bucket for exports
	S3Prefix string `yaml:"s3_prefix" json:"s3_prefix"`   // S3 key prefix
	S3Region string `yaml:"s3_region" json:"s3_region"`   // AWS region
	KMSKeyID string `yaml:"kms_key_id" json:"kms_key_id"` // KMS key for encryption

	// Retention cleanup settings
	CleanupInterval time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"` // how often to run cleanup
}

// Validate checks if the audit configuration has valid required fields and values
func (c *AuditConfig) Validate() error {
	if c.Backend == "" {
		return fmt.Errorf("Backend is required")
	}
	if c.Database == "" {
		return fmt.Errorf("atabase path/connection string is required")
	}
	if c.RetentionDays < 0 {
		return fmt.Errorf("RetentionDays must be non-negative, got: %d", c.RetentionDays)
	}
	if c.BatchSize <= 0 {
		return fmt.Errorf("BatchSize must be positive, got: %d", c.BatchSize)
	}
	if c.FlushTimeout < 0 {
		return fmt.Errorf("FlushTimeout must be non-negative, got: %v", c.FlushTimeout)
	}
	if c.CleanupInterval < 0 {
		return fmt.Errorf("CleanupInterval must be non-negative, got: %v", c.CleanupInterval)
	}

	// Validate export format if specified
	if c.ExportFormat != "" {
		switch c.ExportFormat {
		case "jsonl", "csv":
			// Valid formats
		default:
			return fmt.Errorf("unsupported ExportFormat: %s (supported: jsonl, csv)", c.ExportFormat)
		}
	}

	// Backend-specific validation
	switch c.Backend {
	case "sqlite":
		// SQLite-specific validation could go here
		// For now, Database field validation is sufficient
	default:
		return fmt.Errorf("unsupported Backend: %s", c.Backend)
	}

	return nil
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
	ActionLogin            = "login"
	ActionLogout           = "logout"
	ActionTokenValidate    = "token_validate"
	ActionPolicyEvaluate   = "policy_evaluate"
	ActionResourceRead     = "resource_read"
	ActionResourceWrite    = "resource_write"
	ActionToolCall         = "tool_call"
	ActionRedactData       = "redact_data"
	ActionRateLimitHit     = "rate_limit_hit"
	ActionPathTraversal    = "path_traversal_attempt"
	ActionTombstone        = "tombstone"
	ActionRetentionCleanup = "retention_cleanup"
)

// S3Client interface for S3 operations (allows mocking)
type S3Client interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

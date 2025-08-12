package audit

import (
	"fmt"
	"time"
)

// NewAuditLogger creates a new audit logger based on the configuration
func NewAuditLogger(config *AuditConfig) (AuditLogger, error) {
	if config == nil {
		return nil, fmt.Errorf("audit config cannot be nil")
	}

	// Validate configuration before proceeding
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid audit config: %w", err)
	}

	switch config.Backend {
	case "sqlite":
		return NewSQLiteAuditLogger(config)
	default:
		return nil, fmt.Errorf("unsupported audit backend: %s", config.Backend)
	}
}

// DefaultConfig returns a default audit configuration for SQLite
func DefaultConfig(databasePath string) *AuditConfig {
	return &AuditConfig{
		Backend:         "sqlite",
		Database:        databasePath,
		RetentionDays:   30,
		ExportFormat:    "jsonl",
		BatchSize:       100,
		FlushTimeout:    5 * time.Second,
		CleanupInterval: 24 * time.Hour,
	}
}

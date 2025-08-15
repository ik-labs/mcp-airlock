package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewAuditLogger(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_factory.db")

	config := &AuditConfig{
		Backend:         "sqlite",
		Database:        dbPath,
		RetentionDays:   30,
		BatchSize:       100,
		FlushTimeout:    5 * time.Second,
		CleanupInterval: 24 * time.Hour,
	}

	logger, err := NewAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer func(logger AuditLogger) {
		err := logger.Close()
		if err != nil {
			
		}
	}(logger)

	if logger == nil {
		t.Fatal("Logger should not be nil")
	}

	// Verify it's a SQLite logger
	if _, ok := logger.(*SQLiteAuditLogger); !ok {
		t.Error("Expected SQLiteAuditLogger")
	}
}

func TestNewAuditLogger_UnsupportedBackend(t *testing.T) {
	config := &AuditConfig{
		Backend:         "unsupported",
		Database:        "/tmp/test.db",
		RetentionDays:   30,
		BatchSize:       100,
		FlushTimeout:    5 * time.Second,
		CleanupInterval: 24 * time.Hour,
	}

	logger, err := NewAuditLogger(config)
	if err == nil {
		t.Fatal("Expected error for unsupported backend")
	}
	if logger != nil {
		t.Error("Logger should be nil for unsupported backend")
	}

	expectedError := "invalid audit config: unsupported Backend: unsupported"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestDefaultConfig(t *testing.T) {
	dbPath := "/tmp/test.db"
	config := DefaultConfig(dbPath)

	if config.Backend != "sqlite" {
		t.Errorf("Expected backend 'sqlite', got '%s'", config.Backend)
	}
	if config.Database != dbPath {
		t.Errorf("Expected database '%s', got '%s'", dbPath, config.Database)
	}
	if config.RetentionDays != 30 {
		t.Errorf("Expected retention days 30, got %d", config.RetentionDays)
	}
	if config.ExportFormat != "jsonl" {
		t.Errorf("Expected export format 'jsonl', got '%s'", config.ExportFormat)
	}
	if config.BatchSize != 100 {
		t.Errorf("Expected batch size 100, got %d", config.BatchSize)
	}
	if config.FlushTimeout != 5*time.Second {
		t.Errorf("Expected flush timeout 5s, got %v", config.FlushTimeout)
	}
}

func TestNewAuditLogger_NilConfig(t *testing.T) {
	logger, err := NewAuditLogger(nil)
	if err == nil {
		t.Fatal("Expected error for nil config")
	}
	if logger != nil {
		t.Error("Logger should be nil for nil config")
	}

	expectedError := "audit config cannot be nil"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestNewAuditLogger_InvalidConfig(t *testing.T) {
	config := &AuditConfig{
		Backend:   "sqlite",
		Database:  "", // Missing required field
		BatchSize: -1, // Invalid value
	}

	logger, err := NewAuditLogger(config)
	if err == nil {
		t.Fatal("Expected error for invalid config")
	}
	if logger != nil {
		t.Error("Logger should be nil for invalid config")
	}

	// Should contain validation error
	if !strings.Contains(err.Error(), "invalid audit config") {
		t.Errorf("Expected validation error, got '%s'", err.Error())
	}
}

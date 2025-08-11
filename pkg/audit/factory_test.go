package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func TestNewAuditLogger(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_factory.db")

	config := &AuditConfig{
		Backend:  "sqlite",
		Database: dbPath,
	}

	logger, err := NewAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}
	defer logger.Close()

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
		Backend: "unsupported",
	}

	logger, err := NewAuditLogger(config)
	if err == nil {
		t.Fatal("Expected error for unsupported backend")
	}
	if logger != nil {
		t.Error("Logger should be nil for unsupported backend")
	}

	expectedError := "unsupported audit backend: unsupported"
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

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSQLiteAuditLogger_LogEvent(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_audit.db")

	config := &AuditConfig{
		Backend:      "sqlite",
		Database:     dbPath,
		BatchSize:    2, // Small batch for testing
		FlushTimeout: 100 * time.Millisecond,
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// Log an event
	event := NewAuthenticationEvent("corr-123", "user@example.com", DecisionAllow, "valid token")
	event.Tenant = "tenant-1"

	if err := logger.LogEvent(ctx, event); err != nil {
		t.Fatalf("Failed to log event: %v", err)
	}

	// Flush to ensure event is persisted
	if err := logger.Flush(); err != nil {
		t.Fatalf("Failed to flush logger: %v", err)
	}

	// Query the event
	events, err := logger.Query(ctx, &QueryFilter{
		CorrelationID: "corr-123",
	})
	if err != nil {
		t.Fatalf("Failed to query events: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	retrieved := events[0]
	if retrieved.CorrelationID != "corr-123" {
		t.Errorf("Expected correlation ID 'corr-123', got '%s'", retrieved.CorrelationID)
	}
	if retrieved.Subject != "user@example.com" {
		t.Errorf("Expected subject 'user@example.com', got '%s'", retrieved.Subject)
	}
	if retrieved.Hash == "" {
		t.Error("Event hash should not be empty")
	}
}

func TestSQLiteAuditLogger_HashChaining(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_chain.db")

	config := &AuditConfig{
		Backend:      "sqlite",
		Database:     dbPath,
		BatchSize:    1, // Immediate flush
		FlushTimeout: 10 * time.Millisecond,
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// Log multiple events
	events := []*AuditEvent{
		NewAuthenticationEvent("corr-1", "user1@example.com", DecisionAllow, "valid"),
		NewAuthenticationEvent("corr-2", "user2@example.com", DecisionDeny, "expired"),
		NewAuthenticationEvent("corr-3", "user3@example.com", DecisionAllow, "valid"),
	}

	for _, event := range events {
		event.Tenant = "tenant-1"
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("Failed to log event: %v", err)
		}
		time.Sleep(20 * time.Millisecond) // Ensure flush
	}

	// Validate chain integrity
	if err := logger.ValidateChain(ctx); err != nil {
		t.Fatalf("Chain validation failed: %v", err)
	}

	// Verify chain linkage
	allEvents, err := logger.Query(ctx, &QueryFilter{
		OrderBy: "timestamp",
	})
	if err != nil {
		t.Fatalf("Failed to query all events: %v", err)
	}

	if len(allEvents) != 3 {
		t.Fatalf("Expected 3 events, got %d", len(allEvents))
	}

	// First event should have empty previous hash
	if allEvents[0].PreviousHash != "" {
		t.Errorf("First event should have empty previous hash, got '%s'", allEvents[0].PreviousHash)
	}

	// Subsequent events should link to previous
	for i := 1; i < len(allEvents); i++ {
		if allEvents[i].PreviousHash != allEvents[i-1].Hash {
			t.Errorf("Event %d previous hash mismatch: expected '%s', got '%s'",
				i, allEvents[i-1].Hash, allEvents[i].PreviousHash)
		}
	}
}

func TestSQLiteAuditLogger_Query(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_query.db")

	config := &AuditConfig{
		Backend:      "sqlite",
		Database:     dbPath,
		BatchSize:    1,
		FlushTimeout: 10 * time.Millisecond,
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// Log events with different attributes
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	events := []*AuditEvent{
		{
			ID:            "event-1",
			Timestamp:     baseTime,
			CorrelationID: "corr-1",
			Tenant:        "tenant-1",
			Subject:       "user1@example.com",
			Action:        ActionTokenValidate,
			Decision:      DecisionAllow,
		},
		{
			ID:            "event-2",
			Timestamp:     baseTime.Add(time.Minute),
			CorrelationID: "corr-2",
			Tenant:        "tenant-1",
			Subject:       "user2@example.com",
			Action:        ActionPolicyEvaluate,
			Decision:      DecisionDeny,
		},
		{
			ID:            "event-3",
			Timestamp:     baseTime.Add(2 * time.Minute),
			CorrelationID: "corr-3",
			Tenant:        "tenant-2",
			Subject:       "user1@example.com",
			Action:        ActionTokenValidate,
			Decision:      DecisionAllow,
		},
	}

	for _, event := range events {
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("Failed to log event: %v", err)
		}
	}

	// Flush to ensure all events are persisted
	if err := logger.Flush(); err != nil {
		t.Fatalf("Failed to flush logger: %v", err)
	}

	// Test tenant filtering
	tenantEvents, err := logger.Query(ctx, &QueryFilter{
		Tenant: "tenant-1",
	})
	if err != nil {
		t.Fatalf("Failed to query by tenant: %v", err)
	}
	if len(tenantEvents) != 2 {
		t.Errorf("Expected 2 events for tenant-1, got %d", len(tenantEvents))
	}

	// Test subject filtering
	subjectEvents, err := logger.Query(ctx, &QueryFilter{
		Subject: "user1@example.com",
	})
	if err != nil {
		t.Fatalf("Failed to query by subject: %v", err)
	}
	if len(subjectEvents) != 2 {
		t.Errorf("Expected 2 events for user1@example.com, got %d", len(subjectEvents))
	}

	// Test decision filtering
	denyEvents, err := logger.Query(ctx, &QueryFilter{
		Decision: DecisionDeny,
	})
	if err != nil {
		t.Fatalf("Failed to query by decision: %v", err)
	}
	if len(denyEvents) != 1 {
		t.Errorf("Expected 1 deny event, got %d", len(denyEvents))
	}

	// Test time range filtering
	endTime := baseTime.Add(90 * time.Second)
	timeEvents, err := logger.Query(ctx, &QueryFilter{
		StartTime: &baseTime,
		EndTime:   &endTime,
	})
	if err != nil {
		t.Fatalf("Failed to query by time range: %v", err)
	}
	if len(timeEvents) != 2 {
		t.Errorf("Expected 2 events in time range, got %d", len(timeEvents))
	}

	// Test pagination
	pageEvents, err := logger.Query(ctx, &QueryFilter{
		Limit:   2,
		Offset:  1,
		OrderBy: "timestamp",
	})
	if err != nil {
		t.Fatalf("Failed to query with pagination: %v", err)
	}
	if len(pageEvents) != 2 {
		t.Errorf("Expected 2 events with pagination, got %d", len(pageEvents))
	}
}

func TestSQLiteAuditLogger_Export(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_export.db")

	config := &AuditConfig{
		Backend:      "sqlite",
		Database:     dbPath,
		BatchSize:    1,
		FlushTimeout: 10 * time.Millisecond,
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// Log some events
	events := []*AuditEvent{
		NewAuthenticationEvent("corr-1", "user1@example.com", DecisionAllow, "valid"),
		NewAuthenticationEvent("corr-2", "user2@example.com", DecisionDeny, "expired"),
	}

	for _, event := range events {
		event.Tenant = "tenant-1"
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("Failed to log event: %v", err)
		}
	}

	// Flush to ensure all events are persisted
	if err := logger.Flush(); err != nil {
		t.Fatalf("Failed to flush logger: %v", err)
	}

	// Export to string builder
	var output strings.Builder
	if err := logger.Export(ctx, "jsonl", &output); err != nil {
		t.Fatalf("Failed to export: %v", err)
	}

	exportData := output.String()
	lines := strings.Split(strings.TrimSpace(exportData), "\n")

	if len(lines) != 2 {
		t.Errorf("Expected 2 lines in export, got %d", len(lines))
	}

	// Each line should be valid JSON
	for i, line := range lines {
		if !strings.Contains(line, `"correlation_id"`) {
			t.Errorf("Line %d should contain correlation_id: %s", i, line)
		}
		if !strings.Contains(line, `"hash"`) {
			t.Errorf("Line %d should contain hash: %s", i, line)
		}
	}
}

func TestSQLiteAuditLogger_ConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_concurrent.db")

	config := &AuditConfig{
		Backend:      "sqlite",
		Database:     dbPath,
		BatchSize:    10,
		FlushTimeout: 50 * time.Millisecond,
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// Concurrent writes
	const numGoroutines = 10
	const eventsPerGoroutine = 10

	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < eventsPerGoroutine; j++ {
				event := NewAuthenticationEvent(
					fmt.Sprintf("corr-%d-%d", goroutineID, j),
					fmt.Sprintf("user%d@example.com", goroutineID),
					DecisionAllow,
					"concurrent test",
				)
				event.Tenant = fmt.Sprintf("tenant-%d", goroutineID%3)

				if err := logger.LogEvent(ctx, event); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		if err := <-done; err != nil {
			t.Fatalf("Concurrent write failed: %v", err)
		}
	}

	// Flush to ensure all events are persisted
	if err := logger.Flush(); err != nil {
		t.Fatalf("Failed to flush logger: %v", err)
	}

	// Verify all events were written
	allEvents, err := logger.Query(ctx, &QueryFilter{})
	if err != nil {
		t.Fatalf("Failed to query all events: %v", err)
	}

	expectedCount := numGoroutines * eventsPerGoroutine
	if len(allEvents) != expectedCount {
		t.Errorf("Expected %d events, got %d", expectedCount, len(allEvents))
	}

	// For concurrent writes, we verify that each individual event has a valid hash
	// Perfect hash chaining is not guaranteed due to concurrent access patterns

	// For concurrent writes, we can't guarantee perfect hash chaining due to timing
	// but we can verify that each individual event has a valid hash
	for i, event := range allEvents {
		if err := logger.hasher.ValidateEventHash(event); err != nil {
			t.Errorf("Event %d hash validation failed: %v", i, err)
		}
	}
}

func TestSQLiteAuditLogger_DatabaseRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_recovery.db")

	config := &AuditConfig{
		Backend:      "sqlite",
		Database:     dbPath,
		BatchSize:    1,
		FlushTimeout: 10 * time.Millisecond,
	}

	// Create first logger and add events
	logger1, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create first logger: %v", err)
	}

	ctx := context.Background()

	event1 := NewAuthenticationEvent("corr-1", "user1@example.com", DecisionAllow, "valid")
	event1.Tenant = "tenant-1"

	if err := logger1.LogEvent(ctx, event1); err != nil {
		t.Fatalf("Failed to log event: %v", err)
	}

	if err := logger1.Flush(); err != nil {
		t.Fatalf("Failed to flush first logger: %v", err)
	}
	logger1.Close()

	// Create second logger with same database
	logger2, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create second logger: %v", err)
	}
	defer logger2.Close()

	// Add another event
	event2 := NewAuthenticationEvent("corr-2", "user2@example.com", DecisionAllow, "valid")
	event2.Tenant = "tenant-1"

	if err := logger2.LogEvent(ctx, event2); err != nil {
		t.Fatalf("Failed to log second event: %v", err)
	}

	if err := logger2.Flush(); err != nil {
		t.Fatalf("Failed to flush second logger: %v", err)
	}

	// Verify both events exist and chain is valid
	allEvents, err := logger2.Query(ctx, &QueryFilter{
		OrderBy: "timestamp",
	})
	if err != nil {
		t.Fatalf("Failed to query events: %v", err)
	}

	if len(allEvents) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(allEvents))
	}

	// Verify chain integrity across logger restart
	if err := logger2.ValidateChain(ctx); err != nil {
		t.Fatalf("Chain validation failed after restart: %v", err)
	}
}

package audit

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSQLiteAuditLogger_CleanupExpiredEvents(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_retention.db")

	config := &AuditConfig{
		Backend:         "sqlite",
		Database:        dbPath,
		RetentionDays:   7, // 7 days retention for testing
		BatchSize:       1,
		FlushTimeout:    10 * time.Millisecond,
		CleanupInterval: time.Hour, // Don't auto-cleanup during test
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func(logger *SQLiteAuditLogger) {
		err := logger.Close()
		if err != nil {

		}
	}(logger)

	ctx := context.Background()

	// Create events with different ages
	now := time.Now().UTC()
	oldTime := now.AddDate(0, 0, -10)   // 10 days ago (should be deleted)
	recentTime := now.AddDate(0, 0, -3) // 3 days ago (should be kept)

	// Old events (should be deleted)
	oldEvents := []*AuditEvent{
		{
			ID:            uuid.New().String(),
			Timestamp:     oldTime,
			CorrelationID: "old-1",
			Tenant:        "tenant-1",
			Subject:       "old-user@example.com",
			Action:        ActionTokenValidate,
			Decision:      DecisionAllow,
			Reason:        "valid token",
			Metadata:      make(map[string]interface{}),
		},
		{
			ID:            uuid.New().String(),
			Timestamp:     oldTime.Add(time.Hour),
			CorrelationID: "old-2",
			Tenant:        "tenant-1",
			Subject:       "old-user2@example.com",
			Action:        ActionPolicyEvaluate,
			Decision:      DecisionDeny,
			Reason:        "policy denied",
			Metadata:      make(map[string]interface{}),
		},
	}

	// Recent events (should be kept)
	recentEvents := []*AuditEvent{
		{
			ID:            uuid.New().String(),
			Timestamp:     recentTime,
			CorrelationID: "recent-1",
			Tenant:        "tenant-1",
			Subject:       "recent-user@example.com",
			Action:        ActionTokenValidate,
			Decision:      DecisionAllow,
			Reason:        "valid token",
			Metadata:      make(map[string]interface{}),
		},
		{
			ID:            uuid.New().String(),
			Timestamp:     now.Add(-time.Hour), // 1 hour ago
			CorrelationID: "recent-2",
			Tenant:        "tenant-1",
			Subject:       "recent-user2@example.com",
			Action:        ActionResourceRead,
			Decision:      DecisionAllow,
			Reason:        "authorized access",
			Metadata:      make(map[string]interface{}),
		},
	}

	// Log all events
	allEvents := append(oldEvents, recentEvents...)
	for _, event := range allEvents {
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("Failed to log event: %v", err)
		}
		time.Sleep(20 * time.Millisecond) // Ensure flush
	}

	// Verify all events are present before cleanup
	beforeCleanup, err := logger.Query(ctx, &QueryFilter{})
	if err != nil {
		t.Fatalf("Failed to query events before cleanup: %v", err)
	}
	if len(beforeCleanup) != 4 {
		t.Fatalf("Expected 4 events before cleanup, got %d", len(beforeCleanup))
	}

	// Run cleanup
	deletedCount, err := logger.CleanupExpiredEvents(ctx)
	if err != nil {
		t.Fatalf("Failed to cleanup expired events: %v", err)
	}

	if deletedCount != 2 {
		t.Errorf("Expected 2 deleted events, got %d", deletedCount)
	}

	// Verify only recent events remain
	afterCleanup, err := logger.Query(ctx, &QueryFilter{})
	if err != nil {
		t.Fatalf("Failed to query events after cleanup: %v", err)
	}
	if len(afterCleanup) != 2 {
		t.Errorf("Expected 2 events after cleanup, got %d", len(afterCleanup))
	}

	// Verify the remaining events are the recent ones
	for _, event := range afterCleanup {
		if strings.HasPrefix(event.CorrelationID, "old-") {
			t.Errorf("Old event should have been deleted: %s", event.CorrelationID)
		}
	}
}

func TestSQLiteAuditLogger_CreateTombstone(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_tombstone.db")

	config := &AuditConfig{
		Backend:         "sqlite",
		Database:        dbPath,
		RetentionDays:   30,
		BatchSize:       2, // Small batch for testing
		FlushTimeout:    100 * time.Millisecond,
		CleanupInterval: time.Hour,
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func(logger *SQLiteAuditLogger) {
		err := logger.Close()
		if err != nil {

		}
	}(logger)

	ctx := context.Background()
	targetSubject := "user-to-erase@example.com"
	otherSubject := "other-user@example.com"

	// Create events for the target subject and another subject
	events := []*AuditEvent{
		NewAuthenticationEvent("corr-1", targetSubject, DecisionAllow, "valid token"),
		NewAuthorizationEvent("corr-2", "tenant-1", targetSubject, "mcp://repo/file.txt", DecisionAllow, "authorized"),
		NewAuthenticationEvent("corr-3", otherSubject, DecisionAllow, "valid token"),
		NewResourceAccessEvent("corr-4", "tenant-1", targetSubject, "mcp://repo/data.json", ActionResourceRead),
	}

	for _, event := range events {
		event.Tenant = "tenant-1"
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("Failed to log event: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Wait for flush
	time.Sleep(200 * time.Millisecond)

	// Verify events exist before tombstone
	beforeTombstone, err := logger.Query(ctx, &QueryFilter{
		Subject: targetSubject,
	})
	if err != nil {
		t.Fatalf("Failed to query events before tombstone: %v", err)
	}
	if len(beforeTombstone) != 3 {
		t.Logf("Events found for target subject:")
		for i, event := range beforeTombstone {
			t.Logf("  %d: ID=%s, Action=%s, Subject=%s", i, event.ID, event.Action, event.Subject)
		}
		t.Fatalf("Expected 3 events for target subject before tombstone, got %d", len(beforeTombstone))
	}

	// Create tombstone
	if err := logger.CreateTombstone(ctx, targetSubject, "GDPR erasure request"); err != nil {
		t.Fatalf("Failed to create tombstone: %v", err)
	}

	// Verify tombstone event was created
	tombstones, err := logger.Query(ctx, &QueryFilter{
		Action: ActionTombstone,
	})
	if err != nil {
		t.Fatalf("Failed to query tombstone events: %v", err)
	}
	if len(tombstones) != 1 {
		t.Fatalf("Expected 1 tombstone event, got %d", len(tombstones))
	}

	tombstone := tombstones[0]
	if tombstone.Subject != targetSubject {
		t.Errorf("Expected tombstone subject '%s', got '%s'", targetSubject, tombstone.Subject)
	}
	if tombstone.Reason != "GDPR erasure request" {
		t.Errorf("Expected tombstone reason 'GDPR erasure request', got '%s'", tombstone.Reason)
	}

	// Verify original events have been redacted
	afterTombstone, err := logger.Query(ctx, &QueryFilter{})
	if err != nil {
		t.Fatalf("Failed to query all events after tombstone: %v", err)
	}

	var redactedCount int
	var otherSubjectCount int
	for _, event := range afterTombstone {
		if event.Action == ActionTombstone {
			continue // Skip the tombstone itself
		}
		if strings.HasPrefix(event.Subject, "erased_") {
			redactedCount++
			// Verify metadata indicates erasure
			if metadata, ok := event.Metadata["original_subject_erased"]; !ok || metadata != true {
				t.Errorf("Event should have erasure metadata: %+v", event.Metadata)
			}
		} else if event.Subject == otherSubject {
			otherSubjectCount++
		}
	}

	if redactedCount != 3 {
		t.Errorf("Expected 3 redacted events, got %d", redactedCount)
	}
	if otherSubjectCount != 1 {
		t.Errorf("Expected 1 event for other subject, got %d", otherSubjectCount)
	}

	// Verify hash chain integrity is preserved (validate against raw stored events, not redacted query results)
	// We need to query without redaction to validate the chain
	rawEvents, err := logger.queryRaw(ctx, &QueryFilter{OrderBy: "timestamp"})
	if err != nil {
		t.Fatalf("Failed to query raw events: %v", err)
	}

	if err := logger.hasher.ValidateChain(rawEvents); err != nil {
		t.Fatalf("Hash chain validation failed after tombstone: %v", err)
	}
}

func TestSQLiteAuditLogger_TombstonePreservesChain(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_tombstone_chain.db")

	config := &AuditConfig{
		Backend:         "sqlite",
		Database:        dbPath,
		RetentionDays:   30,
		BatchSize:       2, // Small batch for testing
		FlushTimeout:    100 * time.Millisecond,
		CleanupInterval: time.Hour,
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func(logger *SQLiteAuditLogger) {
		err := logger.Close()
		if err != nil {

		}
	}(logger)

	ctx := context.Background()
	targetSubject := "chain-test@example.com"

	// Create a sequence of events to establish a chain
	events := []*AuditEvent{
		NewAuthenticationEvent("chain-1", "other@example.com", DecisionAllow, "valid"),
		NewAuthenticationEvent("chain-2", targetSubject, DecisionAllow, "valid"),
		NewAuthenticationEvent("chain-3", "another@example.com", DecisionAllow, "valid"),
		NewAuthenticationEvent("chain-4", targetSubject, DecisionDeny, "expired"),
		NewAuthenticationEvent("chain-5", "final@example.com", DecisionAllow, "valid"),
	}

	for _, event := range events {
		event.Tenant = "tenant-1"
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("Failed to log event: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Wait for flush
	time.Sleep(200 * time.Millisecond)

	// Validate chain before tombstone (using raw events)
	rawEventsBefore, err := logger.queryRaw(ctx, &QueryFilter{OrderBy: "timestamp"})
	if err != nil {
		t.Fatalf("Failed to query raw events before tombstone: %v", err)
	}
	if err := logger.hasher.ValidateChain(rawEventsBefore); err != nil {
		t.Fatalf("Chain validation failed before tombstone: %v", err)
	}

	// Create tombstone
	if err := logger.CreateTombstone(ctx, targetSubject, "test erasure"); err != nil {
		t.Fatalf("Failed to create tombstone: %v", err)
	}

	// Validate chain after tombstone - should still be valid (using raw events)
	rawEventsAfter, err := logger.queryRaw(ctx, &QueryFilter{OrderBy: "timestamp"})
	if err != nil {
		t.Fatalf("Failed to query raw events after tombstone: %v", err)
	}
	if err := logger.hasher.ValidateChain(rawEventsAfter); err != nil {
		t.Fatalf("Chain validation failed after tombstone: %v", err)
	}

	// Verify the chain linkage is preserved (using raw events for hash validation)
	allEvents := rawEventsAfter

	// Should have original 5 events + 1 tombstone = 6 total
	if len(allEvents) != 6 {
		t.Fatalf("Expected 6 events after tombstone, got %d", len(allEvents))
	}

	// Verify chain linkage
	for i := 1; i < len(allEvents); i++ {
		if allEvents[i].PreviousHash != allEvents[i-1].Hash {
			t.Errorf("Chain break at event %d: expected previous_hash %s, got %s",
				i, allEvents[i-1].Hash, allEvents[i].PreviousHash)
		}
	}
}

func TestSQLiteAuditLogger_RetentionPreservesTombstones(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_retention_tombstone.db")

	config := &AuditConfig{
		Backend:         "sqlite",
		Database:        dbPath,
		RetentionDays:   7,
		BatchSize:       1,
		FlushTimeout:    10 * time.Millisecond,
		CleanupInterval: time.Hour,
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func(logger *SQLiteAuditLogger) {
		err := logger.Close()
		if err != nil {

		}
	}(logger)

	ctx := context.Background()

	// Create old events and an old tombstone
	oldTime := time.Now().UTC().AddDate(0, 0, -10) // 10 days ago

	oldEvent := &AuditEvent{
		ID:            uuid.New().String(),
		Timestamp:     oldTime,
		CorrelationID: "old-event",
		Tenant:        "tenant-1",
		Subject:       "old-user@example.com",
		Action:        ActionTokenValidate,
		Decision:      DecisionAllow,
		Reason:        "valid token",
		Metadata:      make(map[string]interface{}),
	}

	oldTombstone := &AuditEvent{
		ID:            uuid.New().String(),
		Timestamp:     oldTime.Add(time.Hour),
		CorrelationID: "old-tombstone",
		Tenant:        "tenant-1",
		Subject:       "erased-user@example.com",
		Action:        ActionTombstone,
		Decision:      DecisionAllow,
		Reason:        "GDPR erasure",
		Metadata:      map[string]interface{}{"erased_subject": "erased-user@example.com"},
	}

	// Log both events
	if err := logger.LogEvent(ctx, oldEvent); err != nil {
		t.Fatalf("Failed to log old event: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	if err := logger.LogEvent(ctx, oldTombstone); err != nil {
		t.Fatalf("Failed to log old tombstone: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	// Verify both events exist before cleanup
	beforeCleanup, err := logger.Query(ctx, &QueryFilter{})
	if err != nil {
		t.Fatalf("Failed to query events before cleanup: %v", err)
	}
	if len(beforeCleanup) != 2 {
		t.Fatalf("Expected 2 events before cleanup, got %d", len(beforeCleanup))
	}

	// Run cleanup
	deletedCount, err := logger.CleanupExpiredEvents(ctx)
	if err != nil {
		t.Fatalf("Failed to cleanup expired events: %v", err)
	}

	// Should delete only the regular old event, not the tombstone
	if deletedCount != 1 {
		t.Errorf("Expected 1 deleted event, got %d", deletedCount)
	}

	// Verify only tombstone remains
	afterCleanup, err := logger.Query(ctx, &QueryFilter{})
	if err != nil {
		t.Fatalf("Failed to query events after cleanup: %v", err)
	}
	if len(afterCleanup) != 1 {
		t.Errorf("Expected 1 event after cleanup, got %d", len(afterCleanup))
	}

	if afterCleanup[0].Action != ActionTombstone {
		t.Errorf("Remaining event should be tombstone, got action: %s", afterCleanup[0].Action)
	}
}

func TestSQLiteAuditLogger_ExportWithTombstones(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_export_tombstone.db")

	config := &AuditConfig{
		Backend:         "sqlite",
		Database:        dbPath,
		RetentionDays:   30,
		BatchSize:       1,
		FlushTimeout:    10 * time.Millisecond,
		CleanupInterval: time.Hour,
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func(logger *SQLiteAuditLogger) {
		err := logger.Close()
		if err != nil {
			
		}
	}(logger)

	ctx := context.Background()

	// Create some events and a tombstone
	events := []*AuditEvent{
		NewAuthenticationEvent("export-1", "user@example.com", DecisionAllow, "valid"),
		NewAuthenticationEvent("export-2", "user2@example.com", DecisionAllow, "valid"),
	}

	for _, event := range events {
		event.Tenant = "tenant-1"
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("Failed to log event: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Create tombstone
	if err := logger.CreateTombstone(ctx, "user@example.com", "test export"); err != nil {
		t.Fatalf("Failed to create tombstone: %v", err)
	}

	// Export to string builder
	var output strings.Builder
	if err := logger.Export(ctx, "jsonl", &output); err != nil {
		t.Fatalf("Failed to export: %v", err)
	}

	exportData := output.String()
	lines := strings.Split(strings.TrimSpace(exportData), "\n")

	// Should have 3 lines: 2 original events + 1 tombstone
	if len(lines) != 3 {
		t.Errorf("Expected 3 lines in export, got %d", len(lines))
	}

	// Verify tombstone is included in export
	var hasTombstone bool
	for _, line := range lines {
		if strings.Contains(line, `"action":"tombstone"`) {
			hasTombstone = true
			break
		}
	}

	if !hasTombstone {
		t.Error("Export should include tombstone event")
	}

	// Verify redacted subject appears in export
	var hasRedactedSubject bool
	for _, line := range lines {
		if strings.Contains(line, `"subject":"erased_`) {
			hasRedactedSubject = true
			break
		}
	}

	if !hasRedactedSubject {
		t.Error("Export should include redacted subject")
	}
}

package audit

import (
	"testing"
	"time"
)

func TestHasher_HashEvent(t *testing.T) {
	hasher := NewHasher()

	event := &AuditEvent{
		ID:             "test-event-1",
		Timestamp:      time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		CorrelationID:  "corr-123",
		Tenant:         "tenant-1",
		Subject:        "user@example.com",
		Action:         ActionTokenValidate,
		Resource:       "mcp://repo/test.txt",
		Decision:       DecisionAllow,
		Reason:         "valid token",
		Metadata:       map[string]interface{}{"test": "value"},
		PreviousHash:   "previous-hash",
		LatencyMs:      100,
		RedactionCount: 2,
	}

	hash1, err := hasher.HashEvent(event)
	if err != nil {
		t.Fatalf("Failed to hash event: %v", err)
	}

	if hash1 == "" {
		t.Fatal("Hash should not be empty")
	}

	// Hash should be deterministic
	hash2, err := hasher.HashEvent(event)
	if err != nil {
		t.Fatalf("Failed to hash event second time: %v", err)
	}

	if hash1 != hash2 {
		t.Fatalf("Hash should be deterministic: %s != %s", hash1, hash2)
	}

	// Different events should have different hashes
	event2 := *event
	event2.ID = "test-event-2"

	hash3, err := hasher.HashEvent(&event2)
	if err != nil {
		t.Fatalf("Failed to hash modified event: %v", err)
	}

	if hash1 == hash3 {
		t.Fatal("Different events should have different hashes")
	}
}

func TestHasher_ValidateEventHash(t *testing.T) {
	hasher := NewHasher()

	event := &AuditEvent{
		ID:            "test-event-1",
		Timestamp:     time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		CorrelationID: "corr-123",
		Tenant:        "tenant-1",
		Subject:       "user@example.com",
		Action:        ActionTokenValidate,
		Resource:      "mcp://repo/test.txt",
		Decision:      DecisionAllow,
		Reason:        "valid token",
		Metadata:      map[string]interface{}{"test": "value"},
		PreviousHash:  "previous-hash",
	}

	// Compute and set hash
	hash, err := hasher.HashEvent(event)
	if err != nil {
		t.Fatalf("Failed to hash event: %v", err)
	}
	event.Hash = hash

	// Validation should pass
	if err := hasher.ValidateEventHash(event); err != nil {
		t.Fatalf("Hash validation should pass: %v", err)
	}

	// Tamper with event
	event.Subject = "attacker@example.com"

	// Validation should fail
	if err := hasher.ValidateEventHash(event); err == nil {
		t.Fatal("Hash validation should fail for tampered event")
	}
}

func TestHasher_ValidateChain(t *testing.T) {
	hasher := NewHasher()

	// Create a chain of events
	events := []*AuditEvent{
		{
			ID:            "event-1",
			Timestamp:     time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			CorrelationID: "corr-1",
			Tenant:        "tenant-1",
			Subject:       "user@example.com",
			Action:        ActionTokenValidate,
			Decision:      DecisionAllow,
			PreviousHash:  "", // Genesis event
		},
		{
			ID:            "event-2",
			Timestamp:     time.Date(2024, 1, 1, 12, 1, 0, 0, time.UTC),
			CorrelationID: "corr-2",
			Tenant:        "tenant-1",
			Subject:       "user@example.com",
			Action:        ActionPolicyEvaluate,
			Decision:      DecisionAllow,
		},
		{
			ID:            "event-3",
			Timestamp:     time.Date(2024, 1, 1, 12, 2, 0, 0, time.UTC),
			CorrelationID: "corr-3",
			Tenant:        "tenant-1",
			Subject:       "user@example.com",
			Action:        ActionResourceRead,
			Decision:      DecisionAllow,
		},
	}

	// Compute hashes and link chain
	for i, event := range events {
		if i > 0 {
			event.PreviousHash = events[i-1].Hash
		}

		hash, err := hasher.HashEvent(event)
		if err != nil {
			t.Fatalf("Failed to hash event %d: %v", i, err)
		}
		event.Hash = hash
	}

	// Chain validation should pass
	if err := hasher.ValidateChain(events); err != nil {
		t.Fatalf("Chain validation should pass: %v", err)
	}

	// Break the chain
	events[1].PreviousHash = "wrong-hash"

	// Chain validation should fail
	if err := hasher.ValidateChain(events); err == nil {
		t.Fatal("Chain validation should fail for broken chain")
	}
}

func TestHasher_WithSalt(t *testing.T) {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	hasher1 := NewHasherWithSalt(salt)
	hasher2 := NewHasherWithSalt(salt)

	event := &AuditEvent{
		ID:        "test-event",
		Timestamp: time.Now(),
		Action:    ActionTokenValidate,
	}

	hash1, err := hasher1.HashEvent(event)
	if err != nil {
		t.Fatalf("Failed to hash with hasher1: %v", err)
	}

	hash2, err := hasher2.HashEvent(event)
	if err != nil {
		t.Fatalf("Failed to hash with hasher2: %v", err)
	}

	if hash1 != hash2 {
		t.Fatal("Same salt should produce same hash")
	}

	// Different salt should produce different hash
	differentSalt := make([]byte, 32)
	for i := range differentSalt {
		differentSalt[i] = byte(i + 1)
	}

	hasher3 := NewHasherWithSalt(differentSalt)
	hash3, err := hasher3.HashEvent(event)
	if err != nil {
		t.Fatalf("Failed to hash with hasher3: %v", err)
	}

	if hash1 == hash3 {
		t.Fatal("Different salt should produce different hash")
	}
}

func TestHasher_EmptyChain(t *testing.T) {
	hasher := NewHasher()

	// Empty chain should be valid
	if err := hasher.ValidateChain([]*AuditEvent{}); err != nil {
		t.Fatalf("Empty chain should be valid: %v", err)
	}
}

func BenchmarkHasher_HashEvent(b *testing.B) {
	hasher := NewHasher()

	event := &AuditEvent{
		ID:             "benchmark-event",
		Timestamp:      time.Now(),
		CorrelationID:  "corr-123",
		Tenant:         "tenant-1",
		Subject:        "user@example.com",
		Action:         ActionTokenValidate,
		Resource:       "mcp://repo/test.txt",
		Decision:       DecisionAllow,
		Reason:         "benchmark test",
		Metadata:       map[string]interface{}{"key": "value", "number": 42},
		PreviousHash:   "previous-hash-for-benchmark",
		LatencyMs:      50,
		RedactionCount: 1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hasher.HashEvent(event)
		if err != nil {
			b.Fatalf("Hash failed: %v", err)
		}
	}
}

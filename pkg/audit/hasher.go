package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/zeebo/blake3"
)

// Hasher provides Blake3-based hash chaining for audit events
type Hasher struct {
	salt []byte // Random salt for hash chain initialization
}

// NewHasher creates a new hasher with a random salt
func NewHasher() *Hasher {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		// Critical system issue - fail fast
		panic(fmt.Sprintf("failed to generate random salt: %v", err))
	}

	return &Hasher{
		salt: salt,
	}
}

// NewHasherWithSalt creates a hasher with a specific salt (for testing or recovery)
func NewHasherWithSalt(salt []byte) *Hasher {
	if len(salt) != 32 {
		panic("salt must be exactly 32 bytes")
	}
	return &Hasher{salt: salt}
}

// HashEvent computes the Blake3 hash of an audit event for chain integrity
func (h *Hasher) HashEvent(event *AuditEvent) (string, error) {
	// Create a hashable representation of the event
	hashData := struct {
		ID             string                 `json:"id"`
		Timestamp      int64                  `json:"timestamp"`
		CorrelationID  string                 `json:"correlation_id"`
		Tenant         string                 `json:"tenant"`
		Subject        string                 `json:"subject"`
		Action         string                 `json:"action"`
		Resource       string                 `json:"resource"`
		Decision       string                 `json:"decision"`
		Reason         string                 `json:"reason"`
		Metadata       map[string]interface{} `json:"metadata"`
		PreviousHash   string                 `json:"previous_hash"`
		LatencyMs      int64                  `json:"latency_ms"`
		RedactionCount int                    `json:"redaction_count"`
	}{
		ID:             event.ID,
		Timestamp:      event.Timestamp.UnixNano(),
		CorrelationID:  event.CorrelationID,
		Tenant:         event.Tenant,
		Subject:        event.Subject,
		Action:         event.Action,
		Resource:       event.Resource,
		Decision:       event.Decision,
		Reason:         event.Reason,
		Metadata:       event.Metadata,
		PreviousHash:   event.PreviousHash,
		LatencyMs:      event.LatencyMs,
		RedactionCount: event.RedactionCount,
	}

	// Serialize to JSON for consistent hashing
	jsonData, err := json.Marshal(hashData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event for hashing: %w", err)
	}

	// Create Blake3 hasher with salt
	hasher := blake3.New()
	hasher.Write(h.salt)
	hasher.Write(jsonData)

	// Return hex-encoded hash
	hash := hasher.Sum(nil)
	return hex.EncodeToString(hash), nil
}

// ValidateEventHash verifies that an event's hash is correct
func (h *Hasher) ValidateEventHash(event *AuditEvent) error {
	expectedHash, err := h.HashEvent(event)
	if err != nil {
		return fmt.Errorf("failed to compute expected hash: %w", err)
	}

	if event.Hash != expectedHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, event.Hash)
	}

	return nil
}

// ValidateChain verifies the integrity of a sequence of audit events
// Events MUST be pre-sorted by timestamp in ascending order by the caller
func (h *Hasher) ValidateChain(events []*AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	var previousHash string
	for i, event := range events {
		// Validate individual event hash
		if err := h.ValidateEventHash(event); err != nil {
			return fmt.Errorf("event %d hash validation failed: %w", i, err)
		}

		// Validate chain linkage (except for first event)
		if i > 0 {
			if event.PreviousHash != previousHash {
				return fmt.Errorf("chain break at event %d: expected previous_hash %s, got %s",
					i, previousHash, event.PreviousHash)
			}
		}

		previousHash = event.Hash
	}

	return nil
}

// GetSalt returns the hasher's salt (for persistence/recovery)
func (h *Hasher) GetSalt() []byte {
	salt := make([]byte, len(h.salt))
	copy(salt, h.salt)
	return salt
}

// GenesisHash returns the hash for the first event in a chain (empty previous hash)
func (h *Hasher) GenesisHash() string {
	return ""
}

// HashString computes a Blake3 hash of a string with the hasher's salt
func (h *Hasher) HashString(input string) []byte {
	hasher := blake3.New()
	hasher.Write(h.salt)
	hasher.Write([]byte(input))
	return hasher.Sum(nil)
}

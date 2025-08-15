package audit_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ik-labs/mcp-airlock/pkg/audit"
)

func ExampleNewAuditLogger() {
	// Create a temporary database for the example
	tmpDir, err := os.MkdirTemp("", "audit_example")
	if err != nil {
		log.Fatal(err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {

		}
	}(tmpDir)

	dbPath := filepath.Join(tmpDir, "audit.db")

	// Create audit logger with default configuration
	config := audit.DefaultConfig(dbPath)
	config.BatchSize = 1 // Flush immediately for example
	logger, err := audit.NewAuditLogger(config)
	if err != nil {
		log.Fatal(err)
	}
	defer func(logger audit.AuditLogger) {
		err := logger.Close()
		if err != nil {
			
		}
	}(logger)

	ctx := context.Background()

	// Log an authentication event
	authEvent := audit.NewAuthenticationEvent(
		"corr-123",
		"user@example.com",
		audit.DecisionAllow,
		"valid JWT token",
	)

	if err := logger.LogEvent(ctx, authEvent); err != nil {
		log.Fatal(err)
	}

	// Log an authorization event
	authzEvent := audit.NewAuthorizationEvent(
		"corr-124",
		"tenant-1",
		"user@example.com",
		"mcp://repo/sensitive.txt",
		audit.DecisionDeny,
		"insufficient permissions",
	)

	if err := logger.LogEvent(ctx, authzEvent); err != nil {
		log.Fatal(err)
	}

	// Wait a moment for events to be flushed to database
	// In production, this wouldn't be necessary as queries would happen later
	time.Sleep(100 * time.Millisecond)

	// Query events
	events, err := logger.Query(ctx, &audit.QueryFilter{
		Subject: "user@example.com",
		Limit:   10,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d events for user@example.com\n", len(events))

	// Validate hash chain integrity
	if err := logger.ValidateChain(ctx); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Hash chain validation passed")

	// Output:
	// Found 2 events for user@example.com
	// Hash chain validation passed
}

func ExampleEventBuilder() {
	// Build a custom audit event
	event := audit.NewEvent(audit.ActionToolCall).
		WithCorrelationID("corr-456").
		WithTenant("tenant-2").
		WithSubject("admin@example.com").
		WithResource("mcp://tools/search").
		WithDecision(audit.DecisionAllow).
		WithReason("admin access granted").
		WithLatency(25000000). // 25ms in nanoseconds
		WithRedactionCount(0).
		WithMetadata("tool_name", "search_documents").
		WithMetadata("query_terms", 3).
		Build()

	fmt.Printf("Event ID: %s\n", event.ID)
	fmt.Printf("Action: %s\n", event.Action)
	fmt.Printf("Subject: %s\n", event.Subject)
	fmt.Printf("Decision: %s\n", event.Decision)
	fmt.Printf("Metadata: %v\n", event.Metadata)

	// Output will vary due to random UUID, but structure will be:
	// Event ID: [some-uuid]
	// Action: tool_call
	// Subject: admin@example.com
	// Decision: allow
	// Metadata: map[query_terms:3 tool_name:search_documents]
}

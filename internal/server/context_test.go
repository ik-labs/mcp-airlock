package server

import (
	"context"
	"testing"
)

func TestGenerateCorrelationID(t *testing.T) {
	// Generate multiple IDs to test uniqueness
	ids := make(map[string]bool)
	
	for i := 0; i < 100; i++ {
		id := generateCorrelationID()
		
		if id == "" {
			t.Error("expected non-empty correlation ID")
		}
		
		if len(id) != 16 { // 8 bytes = 16 hex characters
			t.Errorf("expected correlation ID length 16, got %d", len(id))
		}
		
		if ids[id] {
			t.Errorf("duplicate correlation ID generated: %s", id)
		}
		
		ids[id] = true
	}
}

func TestCorrelationIDContext(t *testing.T) {
	ctx := context.Background()
	testID := "test-correlation-id"
	
	// Test setting and getting correlation ID
	ctx = withCorrelationID(ctx, testID)
	retrievedID := getCorrelationID(ctx)
	
	if retrievedID != testID {
		t.Errorf("expected correlation ID %s, got %s", testID, retrievedID)
	}
	
	// Test getting from context without correlation ID
	emptyCtx := context.Background()
	unknownID := getCorrelationID(emptyCtx)
	
	if unknownID != "unknown" {
		t.Errorf("expected 'unknown' for missing correlation ID, got %s", unknownID)
	}
}

func TestTenantContext(t *testing.T) {
	ctx := context.Background()
	testTenant := "test-tenant"
	
	// Test setting and getting tenant
	ctx = withTenant(ctx, testTenant)
	retrievedTenant := getTenant(ctx)
	
	if retrievedTenant != testTenant {
		t.Errorf("expected tenant %s, got %s", testTenant, retrievedTenant)
	}
	
	// Test getting from context without tenant
	emptyCtx := context.Background()
	unknownTenant := getTenant(emptyCtx)
	
	if unknownTenant != "unknown" {
		t.Errorf("expected 'unknown' for missing tenant, got %s", unknownTenant)
	}
}

func TestSubjectContext(t *testing.T) {
	ctx := context.Background()
	testSubject := "test-subject"
	
	// Test setting and getting subject
	ctx = withSubject(ctx, testSubject)
	retrievedSubject := getSubject(ctx)
	
	if retrievedSubject != testSubject {
		t.Errorf("expected subject %s, got %s", testSubject, retrievedSubject)
	}
	
	// Test getting from context without subject
	emptyCtx := context.Background()
	unknownSubject := getSubject(emptyCtx)
	
	if unknownSubject != "unknown" {
		t.Errorf("expected 'unknown' for missing subject, got %s", unknownSubject)
	}
}

func TestToolContext(t *testing.T) {
	ctx := context.Background()
	testTool := "test-tool"
	
	// Test setting and getting tool
	ctx = withTool(ctx, testTool)
	retrievedTool := getTool(ctx)
	
	if retrievedTool != testTool {
		t.Errorf("expected tool %s, got %s", testTool, retrievedTool)
	}
	
	// Test getting from context without tool
	emptyCtx := context.Background()
	unknownTool := getTool(emptyCtx)
	
	if unknownTool != "unknown" {
		t.Errorf("expected 'unknown' for missing tool, got %s", unknownTool)
	}
}

func TestContextChaining(t *testing.T) {
	ctx := context.Background()
	
	// Chain multiple context values
	ctx = withCorrelationID(ctx, "test-id")
	ctx = withTenant(ctx, "test-tenant")
	ctx = withSubject(ctx, "test-subject")
	ctx = withTool(ctx, "test-tool")
	
	// Verify all values are preserved
	if getCorrelationID(ctx) != "test-id" {
		t.Error("correlation ID not preserved in context chain")
	}
	
	if getTenant(ctx) != "test-tenant" {
		t.Error("tenant not preserved in context chain")
	}
	
	if getSubject(ctx) != "test-subject" {
		t.Error("subject not preserved in context chain")
	}
	
	if getTool(ctx) != "test-tool" {
		t.Error("tool not preserved in context chain")
	}
}

func TestContextImmutability(t *testing.T) {
	originalCtx := context.Background()
	originalCtx = withCorrelationID(originalCtx, "original-id")
	
	// Create new context with different value
	newCtx := withCorrelationID(originalCtx, "new-id")
	
	// Verify original context is unchanged
	if getCorrelationID(originalCtx) != "original-id" {
		t.Error("original context was modified")
	}
	
	// Verify new context has new value
	if getCorrelationID(newCtx) != "new-id" {
		t.Error("new context does not have expected value")
	}
}

func TestContextWithWrongType(t *testing.T) {
	ctx := context.Background()
	
	// Set a value with wrong type
	ctx = context.WithValue(ctx, correlationIDKey, 12345) // int instead of string
	
	// Should return "unknown" for wrong type
	id := getCorrelationID(ctx)
	if id != "unknown" {
		t.Errorf("expected 'unknown' for wrong type, got %s", id)
	}
}
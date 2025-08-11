package redact

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// MockAuditLogger implements AuditLogger for testing
type MockAuditLogger struct {
	events []*RedactionAuditEvent
}

func (m *MockAuditLogger) LogRedactionEvent(ctx context.Context, event *RedactionAuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *MockAuditLogger) GetEvents() []*RedactionAuditEvent {
	return m.events
}

func (m *MockAuditLogger) Reset() {
	m.events = nil
}

func TestNewRedactionMiddleware(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()

	middleware := NewRedactionMiddleware(redactor, logger, nil)

	if middleware == nil {
		t.Fatal("NewRedactionMiddleware returned nil")
	}

	if !middleware.enabled {
		t.Error("Expected middleware to be enabled by default")
	}

	if !middleware.redactRequests {
		t.Error("Expected request redaction to be enabled by default")
	}

	if !middleware.redactResponses {
		t.Error("Expected response redaction to be enabled by default")
	}
}

func TestProcessRequest(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	// Set up audit logger
	auditLogger := &MockAuditLogger{}
	middleware.SetAuditLogger(auditLogger)

	// Load test patterns
	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[redacted-email]",
		},
	}

	err := middleware.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	// Create context with metadata
	ctx := context.Background()
	ctx = withCorrelationID(ctx, "test-123")
	ctx = withTenant(ctx, "test-tenant")
	ctx = withSubject(ctx, "test-user")
	ctx = withTool(ctx, "test-tool")

	testData := []byte("Contact user@example.com for support")

	result, err := middleware.ProcessRequest(ctx, testData)
	if err != nil {
		t.Fatalf("ProcessRequest failed: %v", err)
	}

	expected := "Contact [redacted-email] for support"
	if string(result) != expected {
		t.Errorf("Expected %q, got %q", expected, string(result))
	}

	// Check audit event was logged
	events := auditLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 audit event, got %d", len(events))
	}

	event := events[0]
	if event.CorrelationID != "test-123" {
		t.Errorf("Expected correlation_id 'test-123', got %q", event.CorrelationID)
	}

	if event.Direction != "request" {
		t.Errorf("Expected direction 'request', got %q", event.Direction)
	}

	if event.RedactionCount != 1 {
		t.Errorf("Expected redaction_count 1, got %d", event.RedactionCount)
	}

	if event.Tenant != "test-tenant" {
		t.Errorf("Expected tenant 'test-tenant', got %q", event.Tenant)
	}
}

func TestProcessResponse(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	// Set up audit logger
	auditLogger := &MockAuditLogger{}
	middleware.SetAuditLogger(auditLogger)

	// Load test patterns
	patterns := []Pattern{
		{
			Name:    "phone",
			Regex:   `\b\d{3}-\d{3}-\d{4}\b`,
			Replace: "[redacted-phone]",
		},
	}

	err := middleware.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	ctx := context.Background()
	ctx = withCorrelationID(ctx, "test-456")

	testData := []byte("Call us at 555-123-4567")

	result, err := middleware.ProcessResponse(ctx, testData)
	if err != nil {
		t.Fatalf("ProcessResponse failed: %v", err)
	}

	expected := "Call us at [redacted-phone]"
	if string(result) != expected {
		t.Errorf("Expected %q, got %q", expected, string(result))
	}

	// Check audit event was logged
	events := auditLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 audit event, got %d", len(events))
	}

	event := events[0]
	if event.Direction != "response" {
		t.Errorf("Expected direction 'response', got %q", event.Direction)
	}
}

func TestProcessJSONMessage(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	// Load test patterns
	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[redacted-email]",
		},
	}

	err := middleware.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	ctx := context.Background()
	ctx = withCorrelationID(ctx, "test-789")

	// Test JSON-RPC message with sensitive data
	message := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "read_file",
		"params": map[string]interface{}{
			"uri":     "file:///path/to/file.txt",
			"content": "Contact admin@example.com for help",
		},
	}

	result, err := middleware.ProcessJSONMessage(ctx, message, "request")
	if err != nil {
		t.Fatalf("ProcessJSONMessage failed: %v", err)
	}

	// Check that the email was redacted
	params, ok := result["params"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected params to be a map")
	}

	content, ok := params["content"].(string)
	if !ok {
		t.Fatal("Expected content to be a string")
	}

	expected := "Contact [redacted-email] for help"
	if content != expected {
		t.Errorf("Expected content %q, got %q", expected, content)
	}

	// Verify other fields are unchanged
	if result["jsonrpc"] != "2.0" {
		t.Error("jsonrpc field should be unchanged")
	}

	if result["method"] != "read_file" {
		t.Error("method field should be unchanged")
	}
}

func TestRedactForLogging(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	// Load test patterns
	patterns := []Pattern{
		{
			Name:    "ssn",
			Regex:   `\b\d{3}-\d{2}-\d{4}\b`,
			Replace: "[redacted-ssn]",
		},
	}

	err := middleware.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	ctx := context.Background()
	testData := []byte("SSN: 123-45-6789")

	result, err := middleware.RedactForLogging(ctx, testData)
	if err != nil {
		t.Fatalf("RedactForLogging failed: %v", err)
	}

	expected := "SSN: [redacted-ssn]"
	if string(result) != expected {
		t.Errorf("Expected %q, got %q", expected, string(result))
	}
}

func TestRedactForProxy(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	// Load test patterns
	patterns := []Pattern{
		{
			Name:    "api_key",
			Regex:   `(?i)api[_-]?key[:\s]*[a-z0-9]{32}`,
			Replace: "[redacted-api-key]",
		},
	}

	err := middleware.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	ctx := context.Background()
	testData := []byte("API_KEY: abcd1234567890abcd1234567890abcd")

	result, err := middleware.RedactForProxy(ctx, testData)
	if err != nil {
		t.Fatalf("RedactForProxy failed: %v", err)
	}

	expected := "[redacted-api-key]"
	if string(result) != expected {
		t.Errorf("Expected %q, got %q", expected, string(result))
	}
}

func TestMiddlewareDisabled(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()

	config := &MiddlewareConfig{
		Enabled: false,
	}

	middleware := NewRedactionMiddleware(redactor, logger, config)

	ctx := context.Background()
	testData := []byte("sensitive@example.com")

	// Should return original data when disabled
	result, err := middleware.ProcessRequest(ctx, testData)
	if err != nil {
		t.Fatalf("ProcessRequest failed: %v", err)
	}

	if string(result) != string(testData) {
		t.Error("Expected original data when middleware is disabled")
	}
}

func TestUpdateConfig(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	// Initially enabled
	if !middleware.enabled {
		t.Error("Expected middleware to be enabled initially")
	}

	// Update config to disable
	newConfig := &MiddlewareConfig{
		Enabled:         false,
		RedactRequests:  false,
		RedactResponses: true,
	}

	middleware.UpdateConfig(newConfig)

	if middleware.enabled {
		t.Error("Expected middleware to be disabled after config update")
	}

	if middleware.redactRequests {
		t.Error("Expected request redaction to be disabled after config update")
	}

	if !middleware.redactResponses {
		t.Error("Expected response redaction to be enabled after config update")
	}
}

func TestGetStats(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	stats := middleware.GetStats()

	if stats["enabled"] != true {
		t.Error("Expected enabled to be true in stats")
	}

	if stats["redact_requests"] != true {
		t.Error("Expected redact_requests to be true in stats")
	}

	if stats["redactor"] == nil {
		t.Error("Expected redactor stats to be included")
	}
}

func TestAuditEventFields(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	auditLogger := &MockAuditLogger{}
	middleware.SetAuditLogger(auditLogger)

	// Load test patterns
	patterns := []Pattern{
		{
			Name:    "test",
			Regex:   `test`,
			Replace: "[redacted]",
		},
	}

	err := middleware.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	// Create context with all metadata
	ctx := context.Background()
	ctx = withCorrelationID(ctx, "test-correlation")
	ctx = withTenant(ctx, "test-tenant")
	ctx = withSubject(ctx, "test-subject")
	ctx = withTool(ctx, "test-tool")

	testData := []byte("This is a test message")

	_, err = middleware.ProcessRequest(ctx, testData)
	if err != nil {
		t.Fatalf("ProcessRequest failed: %v", err)
	}

	events := auditLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 audit event, got %d", len(events))
	}

	event := events[0]

	// Verify all fields are populated
	if event.CorrelationID != "test-correlation" {
		t.Errorf("Expected correlation_id 'test-correlation', got %q", event.CorrelationID)
	}

	if event.Tenant != "test-tenant" {
		t.Errorf("Expected tenant 'test-tenant', got %q", event.Tenant)
	}

	if event.Subject != "test-subject" {
		t.Errorf("Expected subject 'test-subject', got %q", event.Subject)
	}

	if event.Tool != "test-tool" {
		t.Errorf("Expected tool 'test-tool', got %q", event.Tool)
	}

	if event.Direction != "request" {
		t.Errorf("Expected direction 'request', got %q", event.Direction)
	}

	if event.RedactionCount != 1 { // "test" appears once in "This is a test message"
		t.Errorf("Expected redaction_count 1, got %d", event.RedactionCount)
	}

	if event.DataSize != len(testData) {
		t.Errorf("Expected data_size %d, got %d", len(testData), event.DataSize)
	}

	if event.ProcessingTime <= 0 {
		t.Error("Expected positive processing time")
	}

	if event.Timestamp.IsZero() {
		t.Error("Expected non-zero timestamp")
	}

	if len(event.PatternsHit) == 0 {
		t.Error("Expected patterns hit to be populated")
	}

	if event.PatternsHit["test"] != 1 {
		t.Errorf("Expected 'test' pattern to hit 1 time, got %d", event.PatternsHit["test"])
	}
}

func TestJSONMessageMarshalError(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	ctx := context.Background()

	// Create a message with unmarshalable content (circular reference)
	message := make(map[string]interface{})
	message["self"] = message // Circular reference

	_, err := middleware.ProcessJSONMessage(ctx, message, "request")
	if err == nil {
		t.Error("Expected error for unmarshalable message")
	}

	if err.Error() != "failed to marshal message for redaction: json: unsupported value: encountered a cycle via map[string]interface {}" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

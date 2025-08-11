package redact

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestRedactionIntegrationScenarios tests various integration scenarios
func TestRedactionIntegrationScenarios(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	// Set up audit logger
	auditLogger := &MockAuditLogger{}
	middleware.SetAuditLogger(auditLogger)

	// Load comprehensive patterns
	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[redacted-email]",
		},
		{
			Name:    "phone",
			Regex:   `\b\d{3}-\d{3}-\d{4}\b`,
			Replace: "[redacted-phone]",
		},
		{
			Name:    "ssn",
			Regex:   `\b\d{3}-\d{2}-\d{4}\b`,
			Replace: "[redacted-ssn]",
		},
		{
			Name:    "credit_card",
			Regex:   `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
			Replace: "[redacted-cc]",
		},
		{
			Name:    "api_key",
			Regex:   `(?i)api[_-]?key[:\s]*[a-z0-9]{32}`,
			Replace: "[redacted-api-key]",
		},
		{
			Name:    "bearer_token",
			Regex:   `(?i)bearer\s+[a-z0-9._-]+`,
			Replace: "[redacted-token]",
		},
	}

	err := middleware.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	t.Run("MCP_ReadFile_Request", func(t *testing.T) {
		auditLogger.Reset()

		ctx := context.Background()
		ctx = withCorrelationID(ctx, "read-file-001")
		ctx = withTenant(ctx, "acme-corp")
		ctx = withSubject(ctx, "user@acme.com")
		ctx = withTool(ctx, "read_file")

		// Simulate MCP read_file request with sensitive data
		message := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "read_file",
			"params": map[string]interface{}{
				"uri": "mcp://repo/config/secrets.yaml",
				"metadata": map[string]interface{}{
					"author":    "admin@acme.com",
					"api_key":   "api_key:abcd1234567890abcd1234567890abcd",
					"phone":     "Contact: 555-123-4567",
					"cc_number": "Card: 1234-5678-9012-3456",
				},
			},
		}

		result, err := middleware.ProcessJSONMessage(ctx, message, "request")
		if err != nil {
			t.Fatalf("ProcessJSONMessage failed: %v", err)
		}

		// Verify redaction occurred
		params := result["params"].(map[string]interface{})
		metadata := params["metadata"].(map[string]interface{})

		if metadata["author"] != "[redacted-email]" {
			t.Errorf("Expected author to be redacted, got %v", metadata["author"])
		}

		if metadata["api_key"] != "[redacted-api-key]" {
			t.Errorf("Expected api_key to be redacted, got %v", metadata["api_key"])
		}

		if metadata["phone"] != "Contact: [redacted-phone]" {
			t.Errorf("Expected phone to be redacted, got %v", metadata["phone"])
		}

		if metadata["cc_number"] != "Card: [redacted-cc]" {
			t.Errorf("Expected cc_number to be redacted, got %v", metadata["cc_number"])
		}

		// Verify audit event
		events := auditLogger.GetEvents()
		if len(events) != 1 {
			t.Fatalf("Expected 1 audit event, got %d", len(events))
		}

		event := events[0]
		if event.CorrelationID != "read-file-001" {
			t.Errorf("Expected correlation_id 'read-file-001', got %q", event.CorrelationID)
		}

		if event.Tool != "read_file" {
			t.Errorf("Expected tool 'read_file', got %q", event.Tool)
		}

		if event.RedactionCount != 4 {
			t.Errorf("Expected 4 redactions, got %d", event.RedactionCount)
		}
	})

	t.Run("MCP_ListTools_Response", func(t *testing.T) {
		auditLogger.Reset()

		ctx := context.Background()
		ctx = withCorrelationID(ctx, "list-tools-001")
		ctx = withTenant(ctx, "acme-corp")
		ctx = withTool(ctx, "list_tools")

		// Simulate MCP list_tools response with sensitive data
		message := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      2,
			"result": map[string]interface{}{
				"tools": []interface{}{
					map[string]interface{}{
						"name":        "email_sender",
						"description": "Send emails via admin@acme.com",
						"config": map[string]interface{}{
							"smtp_user": "service@acme.com",
							"api_key":   "api-key:1234567890abcdef1234567890abcdef",
						},
					},
					map[string]interface{}{
						"name":        "phone_dialer",
						"description": "Call support at 555-987-6543",
						"config": map[string]interface{}{
							"emergency": "911",
							"support":   "555-123-4567",
						},
					},
				},
			},
		}

		result, err := middleware.ProcessJSONMessage(ctx, message, "response")
		if err != nil {
			t.Fatalf("ProcessJSONMessage failed: %v", err)
		}

		// Verify redaction occurred in nested structures
		resultData := result["result"].(map[string]interface{})
		tools := resultData["tools"].([]interface{})

		emailTool := tools[0].(map[string]interface{})
		if emailTool["description"] != "Send emails via [redacted-email]" {
			t.Errorf("Expected email in description to be redacted, got %v", emailTool["description"])
		}

		emailConfig := emailTool["config"].(map[string]interface{})
		if emailConfig["smtp_user"] != "[redacted-email]" {
			t.Errorf("Expected smtp_user to be redacted, got %v", emailConfig["smtp_user"])
		}

		if emailConfig["api_key"] != "[redacted-api-key]" {
			t.Errorf("Expected api_key to be redacted, got %v", emailConfig["api_key"])
		}

		phoneTool := tools[1].(map[string]interface{})
		if phoneTool["description"] != "Call support at [redacted-phone]" {
			t.Errorf("Expected phone in description to be redacted, got %v", phoneTool["description"])
		}

		phoneConfig := phoneTool["config"].(map[string]interface{})
		if phoneConfig["support"] != "[redacted-phone]" {
			t.Errorf("Expected support phone to be redacted, got %v", phoneConfig["support"])
		}

		// Emergency number should not be redacted (different pattern)
		if phoneConfig["emergency"] != "911" {
			t.Errorf("Expected emergency number to remain unchanged, got %v", phoneConfig["emergency"])
		}

		// Verify audit event
		events := auditLogger.GetEvents()
		if len(events) != 1 {
			t.Fatalf("Expected 1 audit event, got %d", len(events))
		}

		event := events[0]
		if event.Direction != "response" {
			t.Errorf("Expected direction 'response', got %q", event.Direction)
		}

		if event.RedactionCount != 5 { // 2 emails + 1 api_key + 2 phones
			t.Errorf("Expected 5 redactions, got %d", event.RedactionCount)
		}
	})

	t.Run("Logging_Redaction", func(t *testing.T) {
		ctx := context.Background()
		ctx = withCorrelationID(ctx, "log-test-001")

		// Test data with multiple sensitive patterns
		logData := []byte(`{
			"timestamp": "2024-01-15T10:30:00Z",
			"level": "INFO",
			"message": "User john.doe@example.com accessed file with API key api_key:abcdef1234567890abcdef1234567890",
			"metadata": {
				"user_phone": "555-123-4567",
				"user_ssn": "123-45-6789",
				"payment_card": "4532-1234-5678-9012"
			}
		}`)

		redactedData, err := middleware.RedactForLogging(ctx, logData)
		if err != nil {
			t.Fatalf("RedactForLogging failed: %v", err)
		}

		// Parse the redacted JSON to verify redaction
		var logEntry map[string]interface{}
		if err := json.Unmarshal(redactedData, &logEntry); err != nil {
			t.Fatalf("Failed to parse redacted log data: %v", err)
		}

		message := logEntry["message"].(string)
		expectedMessage := "User [redacted-email] accessed file with API key [redacted-api-key]"
		if message != expectedMessage {
			t.Errorf("Expected message %q, got %q", expectedMessage, message)
		}

		metadata := logEntry["metadata"].(map[string]interface{})
		if metadata["user_phone"] != "[redacted-phone]" {
			t.Errorf("Expected user_phone to be redacted, got %v", metadata["user_phone"])
		}

		if metadata["user_ssn"] != "[redacted-ssn]" {
			t.Errorf("Expected user_ssn to be redacted, got %v", metadata["user_ssn"])
		}

		if metadata["payment_card"] != "[redacted-cc]" {
			t.Errorf("Expected payment_card to be redacted, got %v", metadata["payment_card"])
		}
	})

	t.Run("Proxy_Redaction", func(t *testing.T) {
		ctx := context.Background()
		ctx = withCorrelationID(ctx, "proxy-test-001")

		// Test data that would be sent to upstream server
		proxyData := []byte(`{
			"jsonrpc": "2.0",
			"id": 1,
			"method": "execute_command",
			"params": {
				"command": "send_email",
				"args": {
					"to": "recipient@example.com",
					"from": "sender@company.com",
					"subject": "Account Update",
					"body": "Your account linked to card 4111-1111-1111-1111 has been updated. Contact support at 555-999-8888 if you have questions.",
					"auth_token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
				}
			}
		}`)

		redactedData, err := middleware.RedactForProxy(ctx, proxyData)
		if err != nil {
			t.Fatalf("RedactForProxy failed: %v", err)
		}

		// Parse the redacted JSON to verify redaction
		var proxyMessage map[string]interface{}
		if err := json.Unmarshal(redactedData, &proxyMessage); err != nil {
			t.Fatalf("Failed to parse redacted proxy data: %v", err)
		}

		params := proxyMessage["params"].(map[string]interface{})
		args := params["args"].(map[string]interface{})

		if args["to"] != "[redacted-email]" {
			t.Errorf("Expected 'to' email to be redacted, got %v", args["to"])
		}

		if args["from"] != "[redacted-email]" {
			t.Errorf("Expected 'from' email to be redacted, got %v", args["from"])
		}

		expectedBody := "Your account linked to card [redacted-cc] has been updated. Contact support at [redacted-phone] if you have questions."
		if args["body"] != expectedBody {
			t.Errorf("Expected body to be redacted, got %v", args["body"])
		}

		if args["auth_token"] != "[redacted-token]" {
			t.Errorf("Expected auth_token to be redacted, got %v", args["auth_token"])
		}
	})

	t.Run("Performance_Under_Load", func(t *testing.T) {
		ctx := context.Background()

		// Create a large message with multiple sensitive data points
		largeMessage := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "bulk_process",
			"params": map[string]interface{}{
				"records": make([]interface{}, 100),
			},
		}

		records := largeMessage["params"].(map[string]interface{})["records"].([]interface{})
		for i := 0; i < 100; i++ {
			records[i] = map[string]interface{}{
				"id":    i,
				"email": "user" + string(rune('0'+i%10)) + "@example.com",
				"phone": "555-123-" + string(rune('0'+i%10)) + string(rune('0'+(i/10)%10)) + string(rune('0'+(i/100)%10)) + string(rune('0'+i%10)),
				"data":  "Some data for record " + string(rune('0'+i%10)),
			}
		}

		start := time.Now()

		result, err := middleware.ProcessJSONMessage(ctx, largeMessage, "request")
		if err != nil {
			t.Fatalf("ProcessJSONMessage failed: %v", err)
		}

		duration := time.Since(start)

		// Verify redaction occurred
		resultParams := result["params"].(map[string]interface{})
		resultRecords := resultParams["records"].([]interface{})

		if len(resultRecords) != 100 {
			t.Errorf("Expected 100 records, got %d", len(resultRecords))
		}

		// Check first record
		firstRecord := resultRecords[0].(map[string]interface{})
		if firstRecord["email"] != "[redacted-email]" {
			t.Errorf("Expected email to be redacted in first record, got %v", firstRecord["email"])
		}

		// Performance check - should complete within reasonable time
		if duration > 100*time.Millisecond {
			t.Errorf("Processing took too long: %v", duration)
		}

		t.Logf("Processed 100 records with redaction in %v", duration)
	})
}

// TestRedactionMiddlewareDisabledScenarios tests scenarios when redaction is disabled
func TestRedactionMiddlewareDisabledScenarios(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()

	// Create middleware with redaction disabled
	config := &MiddlewareConfig{
		Enabled:         false,
		RedactRequests:  false,
		RedactResponses: false,
	}

	middleware := NewRedactionMiddleware(redactor, logger, config)

	// Load patterns (should still work even when disabled)
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
	testData := []byte("Contact admin@example.com for support")

	t.Run("Request_Processing_Disabled", func(t *testing.T) {
		result, err := middleware.ProcessRequest(ctx, testData)
		if err != nil {
			t.Fatalf("ProcessRequest failed: %v", err)
		}

		// Should return original data unchanged
		if string(result) != string(testData) {
			t.Errorf("Expected original data when disabled, got %q", string(result))
		}
	})

	t.Run("Response_Processing_Disabled", func(t *testing.T) {
		result, err := middleware.ProcessResponse(ctx, testData)
		if err != nil {
			t.Fatalf("ProcessResponse failed: %v", err)
		}

		// Should return original data unchanged
		if string(result) != string(testData) {
			t.Errorf("Expected original data when disabled, got %q", string(result))
		}
	})

	t.Run("JSON_Message_Processing_Disabled", func(t *testing.T) {
		message := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "test",
			"params": map[string]interface{}{
				"email": "test@example.com",
			},
		}

		result, err := middleware.ProcessJSONMessage(ctx, message, "request")
		if err != nil {
			t.Fatalf("ProcessJSONMessage failed: %v", err)
		}

		// Should return original message unchanged
		params := result["params"].(map[string]interface{})
		if params["email"] != "test@example.com" {
			t.Errorf("Expected original email when disabled, got %v", params["email"])
		}
	})
}

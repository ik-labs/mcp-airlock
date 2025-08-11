package redact

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestNewRedactor(t *testing.T) {
	redactor := NewRedactor()

	if redactor == nil {
		t.Fatal("NewRedactor returned nil")
	}

	if redactor.bufPool == nil {
		t.Fatal("Buffer pool not initialized")
	}

	if len(redactor.patterns) != 0 {
		t.Fatal("Expected empty patterns on initialization")
	}
}

func TestLoadPatterns(t *testing.T) {
	redactor := NewRedactor()

	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[redacted-email]",
		},
		{
			Name:    "bearer_token",
			Regex:   `(?i)bearer\s+[a-z0-9._-]+`,
			Replace: "[redacted-token]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	loadedPatterns := redactor.GetPatterns()
	if len(loadedPatterns) != 2 {
		t.Fatalf("Expected 2 patterns, got %d", len(loadedPatterns))
	}

	// Verify pattern names
	expectedNames := map[string]bool{"email": true, "bearer_token": true}
	for _, pattern := range loadedPatterns {
		if !expectedNames[pattern.Name] {
			t.Errorf("Unexpected pattern name: %s", pattern.Name)
		}
	}
}

func TestLoadPatternsInvalidRegex(t *testing.T) {
	redactor := NewRedactor()

	patterns := []Pattern{
		{
			Name:    "invalid",
			Regex:   `[invalid regex`,
			Replace: "[redacted]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err == nil {
		t.Fatal("Expected error for invalid regex")
	}

	if !strings.Contains(err.Error(), "failed to compile pattern") {
		t.Errorf("Expected compilation error, got: %v", err)
	}
}

func TestRedactRequest(t *testing.T) {
	redactor := NewRedactor()

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
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	testData := []byte("Contact john.doe@example.com or call 555-123-4567")

	result, err := redactor.RedactRequest(context.Background(), testData)
	if err != nil {
		t.Fatalf("RedactRequest failed: %v", err)
	}

	expected := "Contact [redacted-email] or call [redacted-phone]"
	if string(result.Data) != expected {
		t.Errorf("Expected %q, got %q", expected, string(result.Data))
	}

	if result.RedactionCount != 2 {
		t.Errorf("Expected 2 redactions, got %d", result.RedactionCount)
	}

	if result.PatternsHit["email"] != 1 {
		t.Errorf("Expected 1 email hit, got %d", result.PatternsHit["email"])
	}

	if result.PatternsHit["phone"] != 1 {
		t.Errorf("Expected 1 phone hit, got %d", result.PatternsHit["phone"])
	}

	if result.ProcessingTime <= 0 {
		t.Error("Expected positive processing time")
	}
}

func TestRedactResponse(t *testing.T) {
	redactor := NewRedactor()

	patterns := []Pattern{
		{
			Name:    "ssn",
			Regex:   `\b\d{3}-\d{2}-\d{4}\b`,
			Replace: "[redacted-ssn]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	testData := []byte("SSN: 123-45-6789")

	result, err := redactor.RedactResponse(context.Background(), testData)
	if err != nil {
		t.Fatalf("RedactResponse failed: %v", err)
	}

	expected := "SSN: [redacted-ssn]"
	if string(result.Data) != expected {
		t.Errorf("Expected %q, got %q", expected, string(result.Data))
	}
}

func TestRedactStream(t *testing.T) {
	redactor := NewRedactor()

	patterns := []Pattern{
		{
			Name:    "credit_card",
			Regex:   `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
			Replace: "[redacted-cc]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	input := "Credit card: 1234-5678-9012-3456\nAnother line\nCard: 1111 2222 3333 4444"
	reader := strings.NewReader(input)
	var writer bytes.Buffer

	result, err := redactor.RedactStream(context.Background(), reader, &writer)
	if err != nil {
		t.Fatalf("RedactStream failed: %v", err)
	}

	output := writer.String()
	expectedLines := []string{
		"Credit card: [redacted-cc]",
		"Another line",
		"Card: [redacted-cc]",
		"", // Final newline creates empty string when split
	}

	actualLines := strings.Split(output, "\n")
	if len(actualLines) != len(expectedLines) {
		t.Errorf("Expected %d lines, got %d", len(expectedLines), len(actualLines))
	}

	for i, expected := range expectedLines {
		if i < len(actualLines) && actualLines[i] != expected {
			t.Errorf("Line %d: expected %q, got %q", i, expected, actualLines[i])
		}
	}

	if result.RedactionCount != 2 {
		t.Errorf("Expected 2 redactions, got %d", result.RedactionCount)
	}
}

func TestRedactWithNoPatterns(t *testing.T) {
	redactor := NewRedactor()

	testData := []byte("No redaction needed")

	result, err := redactor.RedactRequest(context.Background(), testData)
	if err != nil {
		t.Fatalf("RedactRequest failed: %v", err)
	}

	if !bytes.Equal(result.Data, testData) {
		t.Error("Data should be unchanged when no patterns are loaded")
	}

	if result.RedactionCount != 0 {
		t.Errorf("Expected 0 redactions, got %d", result.RedactionCount)
	}

	if len(result.PatternsHit) != 0 {
		t.Error("Expected empty patterns hit map")
	}
}

func TestRedactWithContextCancellation(t *testing.T) {
	redactor := NewRedactor()

	patterns := []Pattern{
		{
			Name:    "test",
			Regex:   `test`,
			Replace: "[redacted]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	testData := []byte("test data")

	_, err = redactor.RedactRequest(ctx, testData)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
}

func TestMultiplePatternMatches(t *testing.T) {
	redactor := NewRedactor()

	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[email]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	testData := []byte("Emails: user1@test.com, user2@test.com, admin@example.org")

	result, err := redactor.RedactRequest(context.Background(), testData)
	if err != nil {
		t.Fatalf("RedactRequest failed: %v", err)
	}

	expected := "Emails: [email], [email], [email]"
	if string(result.Data) != expected {
		t.Errorf("Expected %q, got %q", expected, string(result.Data))
	}

	if result.RedactionCount != 3 {
		t.Errorf("Expected 3 redactions, got %d", result.RedactionCount)
	}

	if result.PatternsHit["email"] != 3 {
		t.Errorf("Expected 3 email hits, got %d", result.PatternsHit["email"])
	}
}

func TestStats(t *testing.T) {
	redactor := NewRedactor()

	patterns := []Pattern{
		{Name: "test1", Regex: `test1`, Replace: "[redacted]"},
		{Name: "test2", Regex: `test2`, Replace: "[redacted]"},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	stats := redactor.Stats()

	if stats["pattern_count"] != 2 {
		t.Errorf("Expected pattern_count 2, got %v", stats["pattern_count"])
	}

	if stats["buffer_pool_size"] != "64KB" {
		t.Errorf("Expected buffer_pool_size '64KB', got %v", stats["buffer_pool_size"])
	}
}

// Benchmark tests for performance validation
func BenchmarkRedactRequest(b *testing.B) {
	redactor := NewRedactor()

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
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		b.Fatalf("LoadPatterns failed: %v", err)
	}

	testData := []byte("Contact john.doe@example.com or call 555-123-4567. SSN: 123-45-6789")
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := redactor.RedactRequest(ctx, testData)
		if err != nil {
			b.Fatalf("RedactRequest failed: %v", err)
		}
	}
}

func BenchmarkRedactStream(b *testing.B) {
	redactor := NewRedactor()

	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[redacted-email]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		b.Fatalf("LoadPatterns failed: %v", err)
	}

	// Create a larger test dataset
	var testData strings.Builder
	for i := 0; i < 100; i++ {
		testData.WriteString("Line ")
		testData.WriteString(string(rune('0' + i%10)))
		testData.WriteString(": user")
		testData.WriteString(string(rune('0' + i%10)))
		testData.WriteString("@example.com\n")
	}

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := strings.NewReader(testData.String())
		var writer bytes.Buffer

		_, err := redactor.RedactStream(ctx, reader, &writer)
		if err != nil {
			b.Fatalf("RedactStream failed: %v", err)
		}
	}
}

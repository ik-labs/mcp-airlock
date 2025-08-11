package redact

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestPIIProtectionEffectiveness validates that sensitive data is properly redacted
func TestPIIProtectionEffectiveness(t *testing.T) {
	redactor := NewRedactor()

	// Load comprehensive PII patterns
	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[redacted-email]",
		},
		{
			Name:    "phone_us",
			Regex:   `\b(?:\+1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b`,
			Replace: "[redacted-phone]",
		},
		{
			Name:    "ssn",
			Regex:   `\b\d{3}-\d{2}-\d{4}\b`,
			Replace: "[redacted-ssn]",
		},
		{
			Name:    "credit_card",
			Regex:   `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`,
			Replace: "[redacted-cc]",
		},
		{
			Name:    "ip_address",
			Regex:   `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
			Replace: "[redacted-ip]",
		},
		{
			Name:    "api_key",
			Regex:   `(?i)(?:api[_-]?key|token|secret)[:\s]*[a-z0-9]{32,}`,
			Replace: "[redacted-api-key]",
		},
		{
			Name:    "bearer_token",
			Regex:   `(?i)bearer\s+[a-z0-9._-]{20,}`,
			Replace: "[redacted-token]",
		},
		{
			Name:    "aws_access_key",
			Regex:   `\bAKIA[0-9A-Z]{16}\b`,
			Replace: "[redacted-aws-key]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	testCases := []struct {
		name           string
		input          string
		expectedRedact []string // Patterns that should be redacted
		shouldNotMatch []string // Text that should remain unchanged
	}{
		{
			name:  "Email_Addresses",
			input: "Contact john.doe@example.com, admin@company.org, or support@test-site.co.uk",
			expectedRedact: []string{
				"john.doe@example.com",
				"admin@company.org",
				"support@test-site.co.uk",
			},
		},
		{
			name:  "Phone_Numbers",
			input: "Call 555-123-4567, (555) 987-6543, or +1-555-111-2222",
			expectedRedact: []string{
				"555-123-4567",
				"(555) 987-6543",
				"+1-555-111-2222",
			},
		},
		{
			name:  "Social_Security_Numbers",
			input: "SSN: 123-45-6789, Tax ID: 987-65-4321",
			expectedRedact: []string{
				"123-45-6789",
				"987-65-4321",
			},
		},
		{
			name:  "Credit_Card_Numbers",
			input: "Visa: 4532123456789012, MasterCard: 5555555555554444, Amex: 378282246310005",
			expectedRedact: []string{
				"4532123456789012",
				"5555555555554444",
				"378282246310005",
			},
		},
		{
			name:  "IP_Addresses",
			input: "Server at 192.168.1.100, gateway 10.0.0.1, external 203.0.113.42",
			expectedRedact: []string{
				"192.168.1.100",
				"10.0.0.1",
				"203.0.113.42",
			},
		},
		{
			name:  "API_Keys_and_Tokens",
			input: "API_KEY: abcd1234567890abcd1234567890abcd, secret: xyz789xyz789xyz789xyz789xyz789xyz",
			expectedRedact: []string{
				"API_KEY: abcd1234567890abcd1234567890abcd",
				"secret: xyz789xyz789xyz789xyz789xyz789xyz",
			},
		},
		{
			name:  "Bearer_Tokens",
			input: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
			expectedRedact: []string{
				"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
			},
		},
		{
			name:  "AWS_Access_Keys",
			input: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE, AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			expectedRedact: []string{
				"AKIAIOSFODNN7EXAMPLE",
			},
		},
		{
			name:  "Mixed_Sensitive_Data",
			input: "User john@example.com (phone: 555-123-4567) has SSN 123-45-6789 and card 4532123456789012. Server: 192.168.1.1",
			expectedRedact: []string{
				"john@example.com",
				"555-123-4567",
				"123-45-6789",
				"4532123456789012",
				"192.168.1.1",
			},
		},
		{
			name:  "False_Positive_Prevention",
			input: "Version 1.2.3, Date 12-25-2023, @mention, file@version, price $12.34",
			shouldNotMatch: []string{
				"1.2.3",
				"12-25-2023",
				"@mention",
				"file@version",
				"$12.34",
			},
		},
	}

	ctx := context.Background()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := redactor.RedactRequest(ctx, []byte(tc.input))
			if err != nil {
				t.Fatalf("RedactRequest failed: %v", err)
			}

			redactedText := string(result.Data)

			// Verify expected patterns were redacted
			for _, expectedRedact := range tc.expectedRedact {
				if strings.Contains(redactedText, expectedRedact) {
					t.Errorf("Expected %q to be redacted, but found in output: %q", expectedRedact, redactedText)
				}
			}

			// Verify patterns that should not match remain unchanged
			for _, shouldNotMatch := range tc.shouldNotMatch {
				if !strings.Contains(redactedText, shouldNotMatch) {
					t.Errorf("Expected %q to remain unchanged, but not found in output: %q", shouldNotMatch, redactedText)
				}
			}

			// Verify redaction count is reasonable
			if len(tc.expectedRedact) > 0 && result.RedactionCount == 0 {
				t.Errorf("Expected redactions but got count 0 for input: %q", tc.input)
			}

			t.Logf("Input: %q", tc.input)
			t.Logf("Output: %q", redactedText)
			t.Logf("Redactions: %d", result.RedactionCount)
		})
	}
}

// TestRedactionBypass attempts to bypass redaction with various techniques
func TestRedactionBypass(t *testing.T) {
	redactor := NewRedactor()

	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[redacted-email]",
		},
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

	bypassAttempts := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "Unicode_Obfuscation",
			input:       "Contact john\u002Edoe\u0040example\u002Ecom",
			description: "Using unicode escape sequences",
		},
		{
			name:        "Case_Variation",
			input:       "Email: JOHN.DOE@EXAMPLE.COM",
			description: "Using uppercase to evade case-sensitive patterns",
		},
		{
			name:        "Space_Insertion",
			input:       "SSN: 123 - 45 - 6789",
			description: "Adding spaces to break pattern matching",
		},
		{
			name:        "Character_Substitution",
			input:       "Contact john[dot]doe[at]example[dot]com",
			description: "Using character substitution",
		},
		{
			name:        "HTML_Encoding",
			input:       "Email: john&#46;doe&#64;example&#46;com",
			description: "Using HTML entity encoding",
		},
		{
			name:        "Base64_Encoding",
			input:       "Data: am9obi5kb2VAZXhhbXBsZS5jb20=", // john.doe@example.com
			description: "Using base64 encoding",
		},
	}

	ctx := context.Background()

	for _, attempt := range bypassAttempts {
		t.Run(attempt.name, func(t *testing.T) {
			result, err := redactor.RedactRequest(ctx, []byte(attempt.input))
			if err != nil {
				t.Fatalf("RedactRequest failed: %v", err)
			}

			redactedText := string(result.Data)

			t.Logf("Bypass attempt: %s", attempt.description)
			t.Logf("Input: %q", attempt.input)
			t.Logf("Output: %q", redactedText)
			t.Logf("Redactions: %d", result.RedactionCount)

			// Note: Some bypass attempts may succeed, which is expected
			// This test documents current behavior and helps identify areas for improvement
		})
	}
}

// TestRedactionCompleteness ensures no sensitive data leaks through
func TestRedactionCompleteness(t *testing.T) {
	redactor := NewRedactor()

	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[REDACTED]",
		},
		{
			Name:    "phone",
			Regex:   `\b\d{3}-\d{3}-\d{4}\b`,
			Replace: "[REDACTED]",
		},
		{
			Name:    "ssn",
			Regex:   `\b\d{3}-\d{2}-\d{4}\b`,
			Replace: "[REDACTED]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	// Test data with known sensitive patterns
	testData := `
	Personal Information:
	- Email: john.doe@example.com
	- Phone: 555-123-4567
	- SSN: 123-45-6789
	- Backup email: admin@company.org
	- Emergency contact: 555-987-6543
	- Tax ID: 987-65-4321
	
	Additional contacts:
	- support@helpdesk.com
	- Call 555-111-2222 for assistance
	- Manager SSN: 456-78-9012
	`

	ctx := context.Background()
	result, err := redactor.RedactRequest(ctx, []byte(testData))
	if err != nil {
		t.Fatalf("RedactRequest failed: %v", err)
	}

	redactedText := string(result.Data)

	// Define patterns to check for leakage
	leakagePatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{
			name:    "email",
			pattern: regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
		},
		{
			name:    "phone",
			pattern: regexp.MustCompile(`\b\d{3}-\d{3}-\d{4}\b`),
		},
		{
			name:    "ssn",
			pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		},
	}

	// Check for any remaining sensitive data
	for _, leak := range leakagePatterns {
		matches := leak.pattern.FindAllString(redactedText, -1)
		if len(matches) > 0 {
			t.Errorf("Data leakage detected for %s pattern: %v", leak.name, matches)
		}
	}

	// Verify redaction occurred
	if result.RedactionCount == 0 {
		t.Error("Expected redactions but got count 0")
	}

	// Verify redaction markers are present
	if !strings.Contains(redactedText, "[REDACTED]") {
		t.Error("Expected redaction markers in output")
	}

	t.Logf("Original length: %d", len(testData))
	t.Logf("Redacted length: %d", len(redactedText))
	t.Logf("Total redactions: %d", result.RedactionCount)
	t.Logf("Patterns hit: %v", result.PatternsHit)
}

// TestRedactionConsistency ensures consistent redaction across multiple calls
func TestRedactionConsistency(t *testing.T) {
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
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	testInput := "Contact john.doe@example.com for support"
	ctx := context.Background()

	// Perform multiple redactions
	var results []string
	for i := 0; i < 10; i++ {
		result, err := redactor.RedactRequest(ctx, []byte(testInput))
		if err != nil {
			t.Fatalf("RedactRequest failed on iteration %d: %v", i, err)
		}
		results = append(results, string(result.Data))
	}

	// Verify all results are identical
	expectedResult := results[0]
	for i, result := range results {
		if result != expectedResult {
			t.Errorf("Inconsistent redaction on iteration %d: expected %q, got %q", i, expectedResult, result)
		}
	}

	// Verify the expected redaction occurred
	if !strings.Contains(expectedResult, "[redacted-email]") {
		t.Errorf("Expected redaction marker in result: %q", expectedResult)
	}

	if strings.Contains(expectedResult, "john.doe@example.com") {
		t.Errorf("Original email should be redacted: %q", expectedResult)
	}
}

// TestRedactionPerformanceUnderAttack simulates high-volume attacks
func TestRedactionPerformanceUnderAttack(t *testing.T) {
	redactor := NewRedactor()

	// Load multiple complex patterns
	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[redacted-email]",
		},
		{
			Name:    "phone",
			Regex:   `\b(?:\+1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b`,
			Replace: "[redacted-phone]",
		},
		{
			Name:    "complex_pattern",
			Regex:   `(?i)(?:[a-z0-9!#$%&'*+/=?^_` + "`" + `{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_` + "`" + `{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])`,
			Replace: "[redacted-complex]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	// Create attack payload with many potential matches
	attackPayload := strings.Repeat("user@example.com 555-123-4567 ", 1000)

	ctx := context.Background()

	// Measure performance under attack
	start := time.Now()
	result, err := redactor.RedactRequest(ctx, []byte(attackPayload))
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("RedactRequest failed under attack: %v", err)
	}

	// Verify redaction still works correctly
	if result.RedactionCount == 0 {
		t.Error("Expected redactions even under attack")
	}

	// Performance should still be reasonable (adjust threshold as needed)
	if testing.Short() {
		t.Skip("Skipping strict performance check in short mode")
	}
	if duration > 500*time.Millisecond {
		t.Errorf("Redaction took too long under attack: %v", duration)
	}
	t.Logf("Attack payload size: %d bytes", len(attackPayload))
	t.Logf("Processing time: %v", duration)
	t.Logf("Redactions: %d", result.RedactionCount)
	t.Logf("Throughput: %.2f MB/s", float64(len(attackPayload))/duration.Seconds()/1024/1024)
}

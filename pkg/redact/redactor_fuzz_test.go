package redact

import (
	"context"
	"testing"
	"unicode/utf8"
)

// FuzzRedactRequest tests redaction with random input data
func FuzzRedactRequest(f *testing.F) {
	// Define common patterns for fuzzing (moved outside to avoid recompilation)
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
	}

	// Seed with some test cases
	f.Add([]byte("test@example.com"))
	f.Add([]byte("555-123-4567"))
	f.Add([]byte("123-45-6789"))
	f.Add([]byte("1234-5678-9012-3456"))
	f.Add([]byte(""))
	f.Add([]byte("no sensitive data here"))
	f.Add([]byte("mixed: test@example.com and 555-123-4567"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Skip invalid UTF-8 sequences that might cause issues
		if !utf8.Valid(data) {
			t.Skip("Invalid UTF-8 sequence")
		}

		// Create fresh redactor for each iteration to avoid shared state
		redactor := NewRedactor()
		err := redactor.LoadPatterns(patterns)
		if err != nil {
			t.Fatalf("LoadPatterns failed: %v", err)
		}

		// Test redaction doesn't panic or error on arbitrary input
		result, err := redactor.RedactRequest(context.Background(), data)
		if err != nil {
			t.Errorf("RedactRequest failed on input %q: %v", data, err)
			return
		}

		// Verify result is not nil
		if result == nil {
			t.Error("RedactRequest returned nil result")
			return
		}

		// Verify redacted data is valid UTF-8
		if !utf8.Valid(result.Data) {
			t.Error("Redacted data contains invalid UTF-8")
			return
		}

		// Verify redaction count is non-negative
		if result.RedactionCount < 0 {
			t.Errorf("Negative redaction count: %d", result.RedactionCount)
			return
		}

		// Verify patterns hit map is not nil
		if result.PatternsHit == nil {
			t.Error("PatternsHit map is nil")
			return
		}

		// Verify processing time is non-negative
		if result.ProcessingTime < 0 {
			t.Errorf("Negative processing time: %v", result.ProcessingTime)
			return
		}

		// Verify sum of pattern hits equals total redaction count
		totalHits := 0
		for _, count := range result.PatternsHit {
			if count < 0 {
				t.Errorf("Negative pattern hit count: %d", count)
				return
			}
			totalHits += count
		}

		if totalHits != result.RedactionCount {
			t.Errorf("Pattern hits sum (%d) doesn't match redaction count (%d)", totalHits, result.RedactionCount)
		}
	})
}

// FuzzLoadPatterns tests pattern loading with random regex patterns
func FuzzLoadPatterns(f *testing.F) {
	// Seed with valid and invalid regex patterns
	f.Add("test", "[redacted]")
	f.Add(`\d+`, "[number]")
	f.Add(`[a-zA-Z]+`, "[word]")
	f.Add(`(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`, "[email]")
	f.Add("[invalid", "[redacted]") // Invalid regex
	f.Add("", "[empty]")
	f.Add(".*", "[all]")

	f.Fuzz(func(t *testing.T, regex, replace string) {
		redactor := NewRedactor()

		patterns := []Pattern{
			{
				Name:    "fuzz_pattern",
				Regex:   regex,
				Replace: replace,
			},
		}

		err := redactor.LoadPatterns(patterns)

		// We expect some patterns to fail compilation
		// This is normal behavior, not a bug
		if err != nil {
			// Verify error message is reasonable
			if len(err.Error()) == 0 {
				t.Error("Error message is empty")
			}
			return
		}

		// If pattern loaded successfully, verify it's accessible
		loadedPatterns := redactor.GetPatterns()
		if len(loadedPatterns) != 1 {
			t.Errorf("Expected 1 pattern, got %d", len(loadedPatterns))
			return
		}

		if loadedPatterns[0].Name != "fuzz_pattern" {
			t.Errorf("Expected pattern name 'fuzz_pattern', got %q", loadedPatterns[0].Name)
		}

		if loadedPatterns[0].Replace != replace {
			t.Errorf("Expected replace %q, got %q", replace, loadedPatterns[0].Replace)
		}
	})
}

// FuzzRedactLargeInput tests redaction with large input sizes
func FuzzRedactLargeInput(f *testing.F) {
	// Define pattern outside to avoid recompilation
	patterns := []Pattern{
		{
			Name:    "simple",
			Regex:   `test`,
			Replace: "[redacted]",
		},
	}

	// Seed with various sizes
	f.Add(100)
	f.Add(1000)
	f.Add(10000)
	f.Add(100000)
	f.Add(0)
	f.Add(1)

	f.Fuzz(func(t *testing.T, size int) {
		// Limit size to prevent excessive memory usage
		if size < 0 || size > 1000000 {
			t.Skip("Size out of reasonable range")
		}

		// Create fresh redactor for each iteration to avoid shared state
		redactor := NewRedactor()
		err := redactor.LoadPatterns(patterns)
		if err != nil {
			t.Fatalf("LoadPatterns failed: %v", err)
		}

		// Create input data of specified size
		data := make([]byte, size)
		for i := range data {
			// Fill with printable ASCII characters
			data[i] = byte(32 + (i % 95)) // ASCII 32-126
		}

		// Ensure it's valid UTF-8
		if !utf8.Valid(data) {
			t.Skip("Generated data is not valid UTF-8")
		}

		result, err := redactor.RedactRequest(context.Background(), data)
		if err != nil {
			t.Errorf("RedactRequest failed on size %d: %v", size, err)
			return
		}

		if result == nil {
			t.Error("RedactRequest returned nil result")
			return
		}

		// Verify output is reasonable size (shouldn't grow excessively)
		if len(result.Data) > size*2 {
			t.Errorf("Output size (%d) is more than double input size (%d)", len(result.Data), size)
		}
	})
}

// FuzzRedactSpecialCharacters tests redaction with special characters
func FuzzRedactSpecialCharacters(f *testing.F) {
	// Define patterns outside to avoid recompilation
	patterns := []Pattern{
		{
			Name:    "word",
			Regex:   `\w+`,
			Replace: "[word]",
		},
		{
			Name:    "digit",
			Regex:   `\d+`,
			Replace: "[digit]",
		},
	}

	// Seed with various special character combinations
	f.Add("\x00\x01\x02")
	f.Add("🚀🌟💻")
	f.Add("café naïve résumé")
	f.Add("\n\r\t")
	f.Add("\\n\\r\\t")
	f.Add("\"'`")
	f.Add("<>&")
	f.Add("{}[]()")
	f.Add("!@#$%^&*()")

	f.Fuzz(func(t *testing.T, input string) {
		data := []byte(input)

		// Skip invalid UTF-8
		if !utf8.Valid(data) {
			t.Skip("Invalid UTF-8 sequence")
		}

		// Create fresh redactor for each iteration to avoid shared state
		redactor := NewRedactor()
		err := redactor.LoadPatterns(patterns)
		if err != nil {
			t.Fatalf("LoadPatterns failed: %v", err)
		}

		result, err := redactor.RedactRequest(context.Background(), data)
		if err != nil {
			t.Errorf("RedactRequest failed on input %q: %v", input, err)
			return
		}

		if result == nil {
			t.Error("RedactRequest returned nil result")
			return
		}

		// Verify output is valid UTF-8
		if !utf8.Valid(result.Data) {
			t.Error("Redacted data contains invalid UTF-8")
		}
	})
}

package redact

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// BenchmarkRedactorMemoryEfficiency tests memory allocation patterns
func BenchmarkRedactorMemoryEfficiency(b *testing.B) {
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
		{
			Name:    "credit_card",
			Regex:   `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
			Replace: "[redacted-cc]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		b.Fatalf("LoadPatterns failed: %v", err)
	}

	testData := []byte("Contact john.doe@example.com or call 555-123-4567. SSN: 123-45-6789. CC: 1234-5678-9012-3456")
	ctx := context.Background()

	b.Run("SmallPayload", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := redactor.RedactRequest(ctx, testData)
			if err != nil {
				b.Fatalf("RedactRequest failed: %v", err)
			}
		}
	})

	// Test with larger payload
	largeData := bytes.Repeat(testData, 100) // ~10KB
	b.Run("LargePayload", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := redactor.RedactRequest(ctx, largeData)
			if err != nil {
				b.Fatalf("RedactRequest failed: %v", err)
			}
		}
	})

	// Test with very large payload
	veryLargeData := bytes.Repeat(testData, 1000) // ~100KB
	b.Run("VeryLargePayload", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := redactor.RedactRequest(ctx, veryLargeData)
			if err != nil {
				b.Fatalf("RedactRequest failed: %v", err)
			}
		}
	})
}

// BenchmarkStreamingRedaction tests streaming performance
func BenchmarkStreamingRedaction(b *testing.B) {
	redactor := NewRedactor()

	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[redacted-email]",
		},
		{
			Name:    "sensitive_id",
			Regex:   `ID:\s*\d{6,}`,
			Replace: "ID: [redacted]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		b.Fatalf("LoadPatterns failed: %v", err)
	}

	// Create test data with multiple lines
	var testDataBuilder strings.Builder
	for i := 0; i < 1000; i++ {
		testDataBuilder.WriteString("Line ")
		testDataBuilder.WriteString(string(rune('0' + i%10)))
		testDataBuilder.WriteString(": user")
		testDataBuilder.WriteString(string(rune('0' + i%10)))
		testDataBuilder.WriteString("@example.com ID: ")
		testDataBuilder.WriteString(string(rune('0' + (i*123456)%10)))
		testDataBuilder.WriteString("123456\n")
	}
	testData := testDataBuilder.String()

	ctx := context.Background()

	b.Run("StreamingVsBuffer", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			reader := strings.NewReader(testData)
			var writer bytes.Buffer

			_, err := redactor.RedactStream(ctx, reader, &writer)
			if err != nil {
				b.Fatalf("RedactStream failed: %v", err)
			}
		}
	})

	// Compare with buffered approach
	b.Run("BufferedApproach", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			data := []byte(testData)
			_, err := redactor.RedactRequest(ctx, data)
			if err != nil {
				b.Fatalf("RedactRequest failed: %v", err)
			}
		}
	})
}

// BenchmarkPatternComplexity tests performance with different pattern complexities
func BenchmarkPatternComplexity(b *testing.B) {
	testData := []byte("This is a test string with various patterns: email@example.com, phone 555-123-4567, and some numbers 123456789")
	ctx := context.Background()

	b.Run("SimplePatterns", func(b *testing.B) {
		redactor := NewRedactor()
		patterns := []Pattern{
			{Name: "simple", Regex: `test`, Replace: "[redacted]"},
		}

		err := redactor.LoadPatterns(patterns)
		if err != nil {
			b.Fatalf("LoadPatterns failed: %v", err)
		}

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := redactor.RedactRequest(ctx, testData)
			if err != nil {
				b.Fatalf("RedactRequest failed: %v", err)
			}
		}
	})

	b.Run("ComplexPatterns", func(b *testing.B) {
		redactor := NewRedactor()
		patterns := []Pattern{
			{
				Name:    "email",
				Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
				Replace: "[email]",
			},
			{
				Name:    "phone",
				Regex:   `\b\d{3}-\d{3}-\d{4}\b`,
				Replace: "[phone]",
			},
			{
				Name:    "numbers",
				Regex:   `\b\d{6,}\b`,
				Replace: "[number]",
			},
		}

		err := redactor.LoadPatterns(patterns)
		if err != nil {
			b.Fatalf("LoadPatterns failed: %v", err)
		}

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := redactor.RedactRequest(ctx, testData)
			if err != nil {
				b.Fatalf("RedactRequest failed: %v", err)
			}
		}
	})

	b.Run("VeryComplexPatterns", func(b *testing.B) {
		redactor := NewRedactor()
		patterns := []Pattern{
			{
				Name:    "email_complex",
				Regex:   `(?i)(?:[a-z0-9!#$%&'*+/=?^_` + "`" + `{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_` + "`" + `{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])`,
				Replace: "[email]",
			},
			{
				Name:    "phone_international",
				Regex:   `(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})`,
				Replace: "[phone]",
			},
		}

		err := redactor.LoadPatterns(patterns)
		if err != nil {
			b.Fatalf("LoadPatterns failed: %v", err)
		}

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := redactor.RedactRequest(ctx, testData)
			if err != nil {
				b.Fatalf("RedactRequest failed: %v", err)
			}
		}
	})
}

// BenchmarkBufferPoolEfficiency tests buffer pool reuse
func BenchmarkBufferPoolEfficiency(b *testing.B) {
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
		b.Fatalf("LoadPatterns failed: %v", err)
	}

	// Create large streaming data
	var testDataBuilder strings.Builder
	for i := 0; i < 10000; i++ {
		testDataBuilder.WriteString("This is a test line number ")
		testDataBuilder.WriteString(string(rune('0' + i%10)))
		testDataBuilder.WriteString("\n")
	}
	testData := testDataBuilder.String()

	ctx := context.Background()

	b.Run("BufferPoolReuse", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			reader := strings.NewReader(testData)
			var writer bytes.Buffer

			_, err := redactor.RedactStream(ctx, reader, &writer)
			if err != nil {
				b.Fatalf("RedactStream failed: %v", err)
			}
		}
	})
}

// BenchmarkConcurrentRedaction tests concurrent redaction performance
func BenchmarkConcurrentRedaction(b *testing.B) {
	redactor := NewRedactor()

	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[email]",
		},
		{
			Name:    "phone",
			Regex:   `\b\d{3}-\d{3}-\d{4}\b`,
			Replace: "[phone]",
		},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		b.Fatalf("LoadPatterns failed: %v", err)
	}

	testData := []byte("Contact john.doe@example.com or call 555-123-4567")
	ctx := context.Background()

	b.Run("Sequential", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := redactor.RedactRequest(ctx, testData)
			if err != nil {
				b.Fatalf("RedactRequest failed: %v", err)
			}
		}
	})

	b.Run("Parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := redactor.RedactRequest(ctx, testData)
				if err != nil {
					b.Fatalf("RedactRequest failed: %v", err)
				}
			}
		})
	})
}

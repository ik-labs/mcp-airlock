package redact

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

// BenchmarkRedaction benchmarks redaction performance
func BenchmarkRedaction(b *testing.B) {
	redactor := setupBenchmarkRedactor(b)

	testData := []byte(`{
		"user": "john.doe@example.com",
		"token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"phone": "+1-555-123-4567",
		"ssn": "123-45-6789",
		"credit_card": "4111-1111-1111-1111",
		"message": "Please contact me at john.doe@example.com or call +1-555-987-6543"
	}`)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := redactor.RedactRequest(ctx, testData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkRedactionLargeData benchmarks redaction with large data
func BenchmarkRedactionLargeData(b *testing.B) {
	redactor := setupBenchmarkRedactor(b)

	// Create large test data (1MB)
	baseData := `{
		"user": "john.doe@example.com",
		"token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"phone": "+1-555-123-4567",
		"data": "This is some sample data that contains emails like test@example.com and tokens like Bearer abc123def456"
	}`

	var largeData strings.Builder
	largeData.WriteString("[")
	for i := 0; i < 1000; i++ {
		if i > 0 {
			largeData.WriteString(",")
		}
		largeData.WriteString(baseData)
	}
	largeData.WriteString("]")

	testData := []byte(largeData.String())
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := redactor.RedactRequest(ctx, testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRedactionStream benchmarks streaming redaction
func BenchmarkRedactionStream(b *testing.B) {
	redactor := setupBenchmarkRedactor(b)

	testData := `line with email john.doe@example.com
line with token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
line with phone +1-555-123-4567
line with ssn 123-45-6789
normal line without sensitive data
another line with email test@example.com
line with multiple emails: first@example.com, second@example.com
`

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reader := strings.NewReader(testData)
			writer := &bytes.Buffer{}

			_, err := redactor.RedactStream(ctx, reader, writer)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkPatternMatching benchmarks individual pattern matching
func BenchmarkPatternMatching(b *testing.B) {
	redactor := setupBenchmarkRedactor(b)
	patterns := redactor.GetPatterns()

	testData := []byte("Contact me at john.doe@example.com or use token Bearer abc123def456 or call +1-555-123-4567")

	b.ResetTimer()
	b.ReportAllocs()

	for _, pattern := range patterns {
		b.Run(pattern.Name, func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					matches := pattern.Regex.FindAll(testData, -1)
					_ = matches // Use matches to prevent optimization
				}
			})
		})
	}
}

// BenchmarkConcurrentRedaction benchmarks concurrent redaction
func BenchmarkConcurrentRedaction(b *testing.B) {
	redactor := setupBenchmarkRedactor(b)

	testData := []byte(`{
		"user": "john.doe@example.com",
		"token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"phone": "+1-555-123-4567",
		"message": "Contact me at john.doe@example.com"
	}`)

	ctx := context.Background()

	// Test different concurrency levels
	concurrencyLevels := []int{1, 2, 4, 8, 16, 32}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Concurrency-%d", concurrency), func(b *testing.B) {
			b.SetParallelism(concurrency)
			b.ResetTimer()
			b.ReportAllocs()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_, err := redactor.RedactRequest(ctx, testData)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// BenchmarkDifferentDataSizes benchmarks redaction with different data sizes
func BenchmarkDifferentDataSizes(b *testing.B) {
	redactor := setupBenchmarkRedactor(b)
	ctx := context.Background()

	baseLine := "This line contains email john.doe@example.com and token Bearer abc123def456\n"

	sizes := []struct {
		name  string
		lines int
	}{
		{"Small-10lines", 10},
		{"Medium-100lines", 100},
		{"Large-1000lines", 1000},
		{"XLarge-10000lines", 10000},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			// Create test data of specified size
			var data strings.Builder
			for i := 0; i < size.lines; i++ {
				data.WriteString(baseLine)
			}
			testData := []byte(data.String())

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := redactor.RedactRequest(ctx, testData)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkBufferPoolUsage benchmarks buffer pool efficiency
func BenchmarkBufferPoolUsage(b *testing.B) {
	redactor := setupBenchmarkRedactor(b)

	testData := "Contact me at john.doe@example.com or call +1-555-123-4567"
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("WithBufferPool", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				reader := strings.NewReader(testData)
				writer := &bytes.Buffer{}

				_, err := redactor.RedactStream(ctx, reader, writer)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	b.Run("WithoutBufferPool", func(b *testing.B) {
		// Create redactor without buffer pool for comparison
		redactorNoBuf := NewRedactor()
		redactorNoBuf.bufPool = nil // Disable buffer pool

		patterns := []Pattern{
			{Name: "email", Regex: `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`, Replace: "[redacted-email]"},
			{Name: "phone", Regex: `\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`, Replace: "[redacted-phone]"},
		}
		redactorNoBuf.LoadPatterns(patterns)

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := redactorNoBuf.RedactRequest(ctx, []byte(testData))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	redactor := setupBenchmarkRedactor(b)

	testData := []byte(`{
		"user": "john.doe@example.com",
		"token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"phone": "+1-555-123-4567"
	}`)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	// Measure memory allocations per operation
	for i := 0; i < b.N; i++ {
		_, err := redactor.RedactRequest(ctx, testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPatternCompilation benchmarks pattern compilation
func BenchmarkPatternCompilation(b *testing.B) {
	patterns := []Pattern{
		{Name: "email", Regex: `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`, Replace: "[redacted-email]"},
		{Name: "phone", Regex: `\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`, Replace: "[redacted-phone]"},
		{Name: "ssn", Regex: `\b\d{3}-\d{2}-\d{4}\b`, Replace: "[redacted-ssn]"},
		{Name: "credit_card", Regex: `\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`, Replace: "[redacted-cc]"},
		{Name: "bearer_token", Regex: `(?i)bearer\s+[a-z0-9._-]+`, Replace: "[redacted-token]"},
		{Name: "api_key", Regex: `(?i)(api[_-]?key|apikey)\s*[:=]\s*['""]?[a-z0-9]{20,}['""]?`, Replace: "[redacted-api-key]"},
		{Name: "jwt", Regex: `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`, Replace: "[redacted-jwt]"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		redactor := NewRedactor()
		err := redactor.LoadPatterns(patterns)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// setupBenchmarkRedactor creates a test redactor for benchmarking
func setupBenchmarkRedactor(b *testing.B) *Redactor {
	b.Helper()

	redactor := NewRedactor()

	patterns := []Pattern{
		{Name: "email", Regex: `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`, Replace: "[redacted-email]"},
		{Name: "phone", Regex: `\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`, Replace: "[redacted-phone]"},
		{Name: "ssn", Regex: `\b\d{3}-\d{2}-\d{4}\b`, Replace: "[redacted-ssn]"},
		{Name: "credit_card", Regex: `\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`, Replace: "[redacted-cc]"},
		{Name: "bearer_token", Regex: `(?i)bearer\s+[a-z0-9._-]+`, Replace: "[redacted-token]"},
		{Name: "api_key", Regex: `(?i)(api[_-]?key|apikey)\s*[:=]\s*['""]?[a-z0-9]{20,}['""]?`, Replace: "[redacted-api-key]"},
		{Name: "jwt", Regex: `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`, Replace: "[redacted-jwt]"},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		b.Fatal(err)
	}

	return redactor
}

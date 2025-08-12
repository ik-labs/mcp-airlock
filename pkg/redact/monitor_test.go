package redact

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestNewRedactionMonitor(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05) // 5% false positive budget

	if monitor == nil {
		t.Fatal("NewRedactionMonitor returned nil")
	}

	if monitor.falsePositiveBudget != 0.05 {
		t.Errorf("Expected false positive budget 0.05, got %f", monitor.falsePositiveBudget)
	}

	if !monitor.monitoringEnabled {
		t.Error("Expected monitoring to be enabled by default")
	}
}

func TestRecordRedactionEvent(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	ctx := context.Background()
	originalData := []byte("Contact user@example.com for support")

	result := &RedactionResult{
		Data:           []byte("Contact [redacted-email] for support"),
		RedactionCount: 1,
		PatternsHit:    map[string]int{"email": 1},
		ProcessingTime: 5 * time.Millisecond,
	}

	monitor.RecordRedactionEvent(ctx, result, originalData)

	stats := monitor.GetCurrentStats()

	if stats["total_requests"] != int64(1) {
		t.Errorf("Expected total_requests 1, got %v", stats["total_requests"])
	}

	if stats["total_redactions"] != int64(1) {
		t.Errorf("Expected total_redactions 1, got %v", stats["total_redactions"])
	}

	if stats["avg_processing_time"] != 5*time.Millisecond {
		t.Errorf("Expected avg_processing_time 5ms, got %v", stats["avg_processing_time"])
	}

	// Check pattern stats
	patternStats, exists := monitor.GetPatternStats("email")
	if !exists {
		t.Fatal("Expected email pattern stats to exist")
	}

	if patternStats.TotalMatches != 1 {
		t.Errorf("Expected email pattern total matches 1, got %d", patternStats.TotalMatches)
	}

	if patternStats.Name != "email" {
		t.Errorf("Expected pattern name 'email', got %q", patternStats.Name)
	}
}

func TestLoadValidationPatterns(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	validationPatterns := []ValidationPattern{
		{
			Name:            "email",
			OriginalPattern: `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			ExpectedRedactions: []string{
				`user@example\.com`,
				`admin@test\.org`,
			},
			UnexpectedMatches: []string{
				`@mention`,
				`file@version`,
			},
		},
		{
			Name:            "phone",
			OriginalPattern: `\b\d{3}-\d{3}-\d{4}\b`,
			ExpectedRedactions: []string{
				`\d{3}-\d{3}-\d{4}`,
			},
			UnexpectedMatches: []string{
				`\d{1,2}-\d{1,2}-\d{4}`, // dates
			},
		},
	}

	err := monitor.LoadValidationPatterns(validationPatterns)
	if err != nil {
		t.Fatalf("LoadValidationPatterns failed: %v", err)
	}

	// Verify patterns were loaded
	if len(monitor.validationPatterns) != 2 {
		t.Errorf("Expected 2 validation patterns, got %d", len(monitor.validationPatterns))
	}

	emailPattern, exists := monitor.validationPatterns["email"]
	if !exists {
		t.Fatal("Expected email validation pattern to exist")
	}

	if emailPattern.FalsePositiveRegex == nil {
		t.Error("Expected false positive regex to be compiled")
	}

	if emailPattern.FalseNegativeRegex == nil {
		t.Error("Expected false negative regex to be compiled")
	}
}

func TestFalsePositiveDetection(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	// Load validation patterns
	validationPatterns := []ValidationPattern{
		{
			Name:            "email",
			OriginalPattern: `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			UnexpectedMatches: []string{
				`@mention`,
				`file@version`,
			},
		},
	}

	err := monitor.LoadValidationPatterns(validationPatterns)
	if err != nil {
		t.Fatalf("LoadValidationPatterns failed: %v", err)
	}

	ctx := context.Background()
	originalData := []byte("Check @mention and file@version")
	redactedData := []byte("Check [redacted-email] and [redacted-email]") // False positives

	result := &RedactionResult{
		Data:           redactedData,
		RedactionCount: 2,
		PatternsHit:    map[string]int{"email": 2},
		ProcessingTime: 3 * time.Millisecond,
	}

	monitor.RecordRedactionEvent(ctx, result, originalData)

	stats := monitor.GetCurrentStats()

	if stats["false_positives"] != int64(2) {
		t.Errorf("Expected 2 false positives, got %v", stats["false_positives"])
	}

	if stats["false_positive_rate"].(float64) != 1.0 { // 2/2 = 100%
		t.Errorf("Expected false positive rate 1.0, got %f", stats["false_positive_rate"])
	}

	if stats["within_budget"].(bool) {
		t.Error("Expected to be outside budget with 100% false positive rate")
	}

	// Check pattern effectiveness
	patternStats, exists := monitor.GetPatternStats("email")
	if !exists {
		t.Fatal("Expected email pattern stats to exist")
	}

	if patternStats.FalsePositives != 2 {
		t.Errorf("Expected 2 false positives for email pattern, got %d", patternStats.FalsePositives)
	}

	if patternStats.Effectiveness != 0.0 { // (2-2)/2 = 0%
		t.Errorf("Expected 0%% effectiveness, got %f", patternStats.Effectiveness)
	}
}

func TestFalseNegativeDetection(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	// Load validation patterns
	validationPatterns := []ValidationPattern{
		{
			Name:            "email",
			OriginalPattern: `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			ExpectedRedactions: []string{
				`user@example\.com`,
				`admin@test\.org`,
			},
		},
	}

	err := monitor.LoadValidationPatterns(validationPatterns)
	if err != nil {
		t.Fatalf("LoadValidationPatterns failed: %v", err)
	}

	ctx := context.Background()
	originalData := []byte("Contact user@example.com and admin@test.org")
	redactedData := []byte("Contact [redacted-email] and admin@test.org") // One missed

	result := &RedactionResult{
		Data:           redactedData,
		RedactionCount: 1,
		PatternsHit:    map[string]int{"email": 1},
		ProcessingTime: 3 * time.Millisecond,
	}

	monitor.RecordRedactionEvent(ctx, result, originalData)

	stats := monitor.GetCurrentStats()

	if stats["false_negatives"] != int64(1) {
		t.Errorf("Expected 1 false negative, got %v", stats["false_negatives"])
	}

	if stats["false_negative_rate"].(float64) != 1.0 { // 1/1 = 100%
		t.Errorf("Expected false negative rate 1.0, got %f", stats["false_negative_rate"])
	}

	// Check pattern stats
	patternStats, exists := monitor.GetPatternStats("email")
	if !exists {
		t.Fatal("Expected email pattern stats to exist")
	}

	if patternStats.FalseNegatives != 1 {
		t.Errorf("Expected 1 false negative for email pattern, got %d", patternStats.FalseNegatives)
	}
}

func TestGenerateReport(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	// Record some events
	ctx := context.Background()

	// Good redaction
	result1 := &RedactionResult{
		Data:           []byte("Contact [redacted-email] for support"),
		RedactionCount: 1,
		PatternsHit:    map[string]int{"email": 1},
		ProcessingTime: 5 * time.Millisecond,
	}
	monitor.RecordRedactionEvent(ctx, result1, []byte("Contact user@example.com for support"))

	// Another good redaction
	result2 := &RedactionResult{
		Data:           []byte("Call [redacted-phone]"),
		RedactionCount: 1,
		PatternsHit:    map[string]int{"phone": 1},
		ProcessingTime: 3 * time.Millisecond,
	}
	monitor.RecordRedactionEvent(ctx, result2, []byte("Call 555-123-4567"))

	report := monitor.GenerateReport()

	if report == nil {
		t.Fatal("GenerateReport returned nil")
	}

	if report.TotalRequests != 2 {
		t.Errorf("Expected total requests 2, got %d", report.TotalRequests)
	}

	if report.TotalRedactions != 2 {
		t.Errorf("Expected total redactions 2, got %d", report.TotalRedactions)
	}

	if report.AvgProcessingTime != 4*time.Millisecond { // (5+3)/2 = 4ms
		t.Errorf("Expected avg processing time 4ms, got %v", report.AvgProcessingTime)
	}

	if len(report.PatternStats) != 2 {
		t.Errorf("Expected 2 pattern stats, got %d", len(report.PatternStats))
	}

	if !report.WithinBudget {
		t.Error("Expected to be within budget with no false positives")
	}

	if report.Timestamp.IsZero() {
		t.Error("Expected non-zero timestamp")
	}
}

func TestRecommendations(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.01) // Very strict 1% budget

	// Load validation patterns to trigger false positives
	validationPatterns := []ValidationPattern{
		{
			Name:            "email",
			OriginalPattern: `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			UnexpectedMatches: []string{
				`@mention`,
			},
		},
	}

	err := monitor.LoadValidationPatterns(validationPatterns)
	if err != nil {
		t.Fatalf("LoadValidationPatterns failed: %v", err)
	}

	ctx := context.Background()

	// Record event with false positive
	result := &RedactionResult{
		Data:           []byte("Check [redacted-email]"), // False positive
		RedactionCount: 1,
		PatternsHit:    map[string]int{"email": 1},
		ProcessingTime: 15 * time.Millisecond, // High processing time
	}
	monitor.RecordRedactionEvent(ctx, result, []byte("Check @mention"))

	report := monitor.GenerateReport()

	if len(report.Recommendations) == 0 {
		t.Error("Expected recommendations to be generated")
	}

	// Should have recommendations for false positive rate and processing time
	foundFalsePositiveRec := false
	foundProcessingTimeRec := false

	for _, rec := range report.Recommendations {
		if strings.Contains(rec, "False positive rate") {
			foundFalsePositiveRec = true
		}
		if strings.Contains(rec, "processing time") {
			foundProcessingTimeRec = true
		}
	}

	if !foundFalsePositiveRec {
		t.Error("Expected false positive rate recommendation")
	}

	if !foundProcessingTimeRec {
		t.Error("Expected processing time recommendation")
	}
}

func TestSetFalsePositiveBudget(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	monitor.SetFalsePositiveBudget(0.10)

	if monitor.falsePositiveBudget != 0.10 {
		t.Errorf("Expected false positive budget 0.10, got %f", monitor.falsePositiveBudget)
	}
}

func TestEnableMonitoring(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	// Initially enabled
	if !monitor.monitoringEnabled {
		t.Error("Expected monitoring to be enabled initially")
	}

	// Disable monitoring
	monitor.EnableMonitoring(false)

	if monitor.monitoringEnabled {
		t.Error("Expected monitoring to be disabled")
	}

	// Record event while disabled - should not affect stats
	ctx := context.Background()
	result := &RedactionResult{
		Data:           []byte("test"),
		RedactionCount: 1,
		PatternsHit:    map[string]int{"test": 1},
		ProcessingTime: 1 * time.Millisecond,
	}

	monitor.RecordRedactionEvent(ctx, result, []byte("test"))

	stats := monitor.GetCurrentStats()
	if stats["total_requests"] != int64(0) {
		t.Error("Expected no stats recorded when monitoring is disabled")
	}
}

func TestResetStats(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	// Record some events
	ctx := context.Background()
	result := &RedactionResult{
		Data:           []byte("test"),
		RedactionCount: 1,
		PatternsHit:    map[string]int{"test": 1},
		ProcessingTime: 1 * time.Millisecond,
	}

	monitor.RecordRedactionEvent(ctx, result, []byte("test"))

	// Verify stats exist
	stats := monitor.GetCurrentStats()
	if stats["total_requests"] == int64(0) {
		t.Error("Expected stats to be recorded before reset")
	}

	// Reset stats
	monitor.ResetStats()

	// Verify stats are reset
	stats = monitor.GetCurrentStats()
	if stats["total_requests"] != int64(0) {
		t.Error("Expected stats to be reset")
	}

	if stats["total_redactions"] != int64(0) {
		t.Error("Expected redaction count to be reset")
	}

	if len(monitor.patternEffectiveness) != 0 {
		t.Error("Expected pattern effectiveness to be reset")
	}
}

func TestIsWithinBudget(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05) // 5% budget

	// Initially within budget (no data)
	if !monitor.IsWithinBudget() {
		t.Error("Expected to be within budget initially")
	}

	// Add some good redactions
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		result := &RedactionResult{
			Data:           []byte("redacted"),
			RedactionCount: 1,
			PatternsHit:    map[string]int{"test": 1},
			ProcessingTime: 1 * time.Millisecond,
		}
		monitor.RecordRedactionEvent(ctx, result, []byte("original"))
	}

	// Should still be within budget
	if !monitor.IsWithinBudget() {
		t.Error("Expected to be within budget with no false positives")
	}

	// Manually add false positives to exceed budget
	monitor.mu.Lock()
	monitor.falsePositives = 1 // 1/10 = 10% > 5% budget
	monitor.mu.Unlock()

	if monitor.IsWithinBudget() {
		t.Error("Expected to be outside budget with 10% false positive rate")
	}
}

func TestPatternStatsNotFound(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	stats, exists := monitor.GetPatternStats("nonexistent")
	if exists {
		t.Error("Expected pattern stats to not exist")
	}

	if stats != nil {
		t.Error("Expected nil stats for nonexistent pattern")
	}
}

func TestValidationPatternCompilationError(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	// Invalid regex pattern
	validationPatterns := []ValidationPattern{
		{
			Name:            "invalid",
			OriginalPattern: `valid`,
			UnexpectedMatches: []string{
				`[invalid regex`,
			},
		},
	}

	err := monitor.LoadValidationPatterns(validationPatterns)
	if err == nil {
		t.Error("Expected error for invalid regex pattern")
	}

	if !strings.Contains(err.Error(), "failed to compile false positive regex") {
		t.Errorf("Expected compilation error, got: %v", err)
	}
}

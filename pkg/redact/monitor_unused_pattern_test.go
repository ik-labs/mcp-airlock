package redact

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestUnusedPatternDetection tests that newly added patterns are not incorrectly flagged as unused
func TestUnusedPatternDetection(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	// Create a pattern stats entry that simulates a newly added pattern
	// (zero LastUsed time, zero TotalMatches)
	monitor.mu.Lock()
	monitor.patternEffectiveness["new_pattern"] = &PatternStats{
		Name:         "new_pattern",
		TotalMatches: 0,
		LastUsed:     time.Time{}, // Zero time (newly added pattern)
	}

	// Create a pattern stats entry that simulates an old unused pattern
	oldTime := time.Now().Add(-48 * time.Hour) // 48 hours ago
	monitor.patternEffectiveness["old_unused_pattern"] = &PatternStats{
		Name:         "old_unused_pattern",
		TotalMatches: 0,
		LastUsed:     oldTime,
	}

	// Create a pattern stats entry that simulates a recently used pattern
	recentTime := time.Now().Add(-1 * time.Hour) // 1 hour ago
	monitor.patternEffectiveness["recent_pattern"] = &PatternStats{
		Name:         "recent_pattern",
		TotalMatches: 0,
		LastUsed:     recentTime,
	}
	monitor.mu.Unlock()

	// Generate report and check recommendations
	report := monitor.GenerateReport()

	// Check that recommendations don't include the newly added pattern
	newPatternFlagged := false
	oldPatternFlagged := false
	recentPatternFlagged := false

	for _, recommendation := range report.Recommendations {
		if contains(recommendation, "new_pattern") && contains(recommendation, "not been used recently") {
			newPatternFlagged = true
		}
		if contains(recommendation, "old_unused_pattern") && contains(recommendation, "not been used recently") {
			oldPatternFlagged = true
		}
		if contains(recommendation, "recent_pattern") && contains(recommendation, "not been used recently") {
			recentPatternFlagged = true
		}
	}

	// Verify results
	if newPatternFlagged {
		t.Error("Newly added pattern with zero LastUsed should not be flagged as unused")
	}

	if !oldPatternFlagged {
		t.Error("Old unused pattern should be flagged as unused")
	}

	if recentPatternFlagged {
		t.Error("Recently used pattern should not be flagged as unused")
	}

	t.Logf("Generated %d recommendations", len(report.Recommendations))
	for i, rec := range report.Recommendations {
		t.Logf("Recommendation %d: %s", i+1, rec)
	}
}

// TestPatternUsageTracking tests that LastUsed is properly updated when patterns are used
func TestPatternUsageTracking(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	// Create a pattern stats entry with zero LastUsed
	monitor.mu.Lock()
	monitor.patternEffectiveness["test_pattern"] = &PatternStats{
		Name:         "test_pattern",
		TotalMatches: 0,
		LastUsed:     time.Time{}, // Zero time
	}
	monitor.mu.Unlock()

	// Simulate pattern usage by recording a redaction event
	result := &RedactionResult{
		Data:           []byte("redacted"),
		RedactionCount: 1,
		PatternsHit:    map[string]int{"test_pattern": 1},
		ProcessingTime: 1 * time.Millisecond,
	}

	beforeTime := time.Now()
	monitor.RecordRedactionEvent(context.Background(), result, []byte("original"))
	afterTime := time.Now()

	// Check that LastUsed was updated
	stats, exists := monitor.GetPatternStats("test_pattern")
	if !exists {
		t.Fatal("Pattern stats should exist")
	}

	if stats.LastUsed.IsZero() {
		t.Error("LastUsed should be updated after pattern usage")
	}

	if stats.LastUsed.Before(beforeTime) || stats.LastUsed.After(afterTime) {
		t.Errorf("LastUsed time (%v) should be between %v and %v", stats.LastUsed, beforeTime, afterTime)
	}

	if stats.TotalMatches != 1 {
		t.Errorf("Expected TotalMatches to be 1, got %d", stats.TotalMatches)
	}

	// Generate report and verify the pattern is not flagged as unused
	report := monitor.GenerateReport()

	patternFlagged := false
	for _, recommendation := range report.Recommendations {
		if contains(recommendation, "test_pattern") && contains(recommendation, "not been used recently") {
			patternFlagged = true
		}
	}

	if patternFlagged {
		t.Error("Recently used pattern should not be flagged as unused")
	}
}

// TestZeroTimeHandling tests edge cases with zero time values
func TestZeroTimeHandling(t *testing.T) {
	logger := zap.NewNop()
	monitor := NewRedactionMonitor(logger, 0.05)

	testCases := []struct {
		name         string
		totalMatches int64
		lastUsed     time.Time
		shouldFlag   bool
		description  string
	}{
		{
			name:         "new_unused_pattern",
			totalMatches: 0,
			lastUsed:     time.Time{}, // Zero time
			shouldFlag:   false,
			description:  "Newly added pattern with zero LastUsed should not be flagged",
		},
		{
			name:         "old_unused_pattern",
			totalMatches: 0,
			lastUsed:     time.Now().Add(-48 * time.Hour),
			shouldFlag:   true,
			description:  "Old unused pattern should be flagged",
		},
		{
			name:         "recent_unused_pattern",
			totalMatches: 0,
			lastUsed:     time.Now().Add(-1 * time.Hour),
			shouldFlag:   false,
			description:  "Recently touched but unused pattern should not be flagged",
		},
		{
			name:         "used_pattern_old_timestamp",
			totalMatches: 5,
			lastUsed:     time.Now().Add(-48 * time.Hour),
			shouldFlag:   false,
			description:  "Used pattern should not be flagged regardless of LastUsed time",
		},
		{
			name:         "used_pattern_zero_timestamp",
			totalMatches: 3,
			lastUsed:     time.Time{}, // Zero time
			shouldFlag:   false,
			description:  "Used pattern with zero LastUsed should not be flagged",
		},
	}

	// Set up pattern stats
	monitor.mu.Lock()
	for _, tc := range testCases {
		monitor.patternEffectiveness[tc.name] = &PatternStats{
			Name:         tc.name,
			TotalMatches: tc.totalMatches,
			LastUsed:     tc.lastUsed,
		}
	}
	monitor.mu.Unlock()

	// Generate report
	report := monitor.GenerateReport()

	// Check each test case
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			patternFlagged := false
			for _, recommendation := range report.Recommendations {
				if contains(recommendation, tc.name) && contains(recommendation, "not been used recently") {
					patternFlagged = true
					break
				}
			}

			if patternFlagged != tc.shouldFlag {
				if tc.shouldFlag {
					t.Errorf("%s: Expected pattern to be flagged but it wasn't", tc.description)
				} else {
					t.Errorf("%s: Expected pattern not to be flagged but it was", tc.description)
				}
			}
		})
	}
}

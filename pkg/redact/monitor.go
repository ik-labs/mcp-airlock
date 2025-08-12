package redact

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RedactionMonitor provides monitoring and validation for redaction effectiveness
type RedactionMonitor struct {
	logger *zap.Logger

	// Metrics tracking
	mu                   sync.RWMutex
	totalRequests        int64
	totalRedactions      int64
	falsePositives       int64
	falseNegatives       int64
	processingTimeTotal  time.Duration
	patternEffectiveness map[string]*PatternStats

	// Validation patterns for false positive detection
	validationPatterns map[string]*ValidationPattern

	// Configuration
	falsePositiveBudget float64 // Maximum acceptable false positive rate (0.0-1.0)
	monitoringEnabled   bool
}

// PatternStats tracks statistics for individual patterns
type PatternStats struct {
	Name           string        `json:"name"`
	TotalMatches   int64         `json:"total_matches"`
	FalsePositives int64         `json:"false_positives"`
	FalseNegatives int64         `json:"false_negatives"`
	AvgProcessTime time.Duration `json:"avg_process_time"`
	LastUsed       time.Time     `json:"last_used"`
	Effectiveness  float64       `json:"effectiveness"` // (TotalMatches - FalsePositives) / TotalMatches
}

// ValidationPattern defines patterns to detect false positives/negatives
type ValidationPattern struct {
	Name               string         `yaml:"name" json:"name"`
	OriginalPattern    string         `yaml:"original_pattern" json:"original_pattern"`
	FalsePositiveRegex *regexp.Regexp `yaml:"-" json:"-"`
	FalseNegativeRegex *regexp.Regexp `yaml:"-" json:"-"`
	ExpectedRedactions []string       `yaml:"expected_redactions" json:"expected_redactions"`
	UnexpectedMatches  []string       `yaml:"unexpected_matches" json:"unexpected_matches"`
}

// MonitoringReport provides a comprehensive view of redaction effectiveness
type MonitoringReport struct {
	Timestamp         time.Time                `json:"timestamp"`
	TotalRequests     int64                    `json:"total_requests"`
	TotalRedactions   int64                    `json:"total_redactions"`
	FalsePositiveRate float64                  `json:"false_positive_rate"`
	FalseNegativeRate float64                  `json:"false_negative_rate"`
	AvgProcessingTime time.Duration            `json:"avg_processing_time"`
	PatternStats      map[string]*PatternStats `json:"pattern_stats"`
	WithinBudget      bool                     `json:"within_budget"`
	Recommendations   []string                 `json:"recommendations"`
}

// NewRedactionMonitor creates a new redaction monitor
func NewRedactionMonitor(logger *zap.Logger, falsePositiveBudget float64) *RedactionMonitor {
	return &RedactionMonitor{
		logger:               logger,
		patternEffectiveness: make(map[string]*PatternStats),
		validationPatterns:   make(map[string]*ValidationPattern),
		falsePositiveBudget:  falsePositiveBudget,
		monitoringEnabled:    true,
	}
}

// RecordRedactionEvent records a redaction event for monitoring
func (rm *RedactionMonitor) RecordRedactionEvent(ctx context.Context, result *RedactionResult, originalData []byte) {
	if !rm.monitoringEnabled {
		return
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.totalRequests++
	rm.totalRedactions += int64(result.RedactionCount)
	rm.processingTimeTotal += result.ProcessingTime

	// Update pattern statistics
	for patternName, count := range result.PatternsHit {
		stats, exists := rm.patternEffectiveness[patternName]
		if !exists {
			stats = &PatternStats{
				Name: patternName,
			}
			rm.patternEffectiveness[patternName] = stats
		}

		stats.TotalMatches += int64(count)
		stats.LastUsed = time.Now()

		// Update average processing time
		if stats.TotalMatches > 0 {
			stats.AvgProcessTime = time.Duration(int64(stats.AvgProcessTime)*stats.TotalMatches+int64(result.ProcessingTime)) / time.Duration(stats.TotalMatches+1)
		} else {
			stats.AvgProcessTime = result.ProcessingTime
		}
	}

	// Validate redaction effectiveness
	rm.validateRedactionEffectiveness(originalData, result.Data, result.PatternsHit)
}

// validateRedactionEffectiveness checks for false positives and negatives
func (rm *RedactionMonitor) validateRedactionEffectiveness(_, redactedData []byte, _ map[string]int) {
	for patternName, validationPattern := range rm.validationPatterns {
		stats := rm.patternEffectiveness[patternName]
		if stats == nil {
			continue
		}

		// Check for false positives (things that shouldn't have been redacted)
		if validationPattern.FalsePositiveRegex != nil {
			falsePositives := validationPattern.FalsePositiveRegex.FindAll(redactedData, -1)
			if len(falsePositives) > 0 {
				stats.FalsePositives += int64(len(falsePositives))
				rm.falsePositives += int64(len(falsePositives))

				rm.logger.Warn("False positive detected",
					zap.String("pattern", patternName),
					zap.Int("count", len(falsePositives)),
					zap.ByteStrings("matches", falsePositives),
				)
			}
		}

		// Check for false negatives (things that should have been redacted but weren't)
		if validationPattern.FalseNegativeRegex != nil {
			falseNegatives := validationPattern.FalseNegativeRegex.FindAll(redactedData, -1)
			if len(falseNegatives) > 0 {
				stats.FalseNegatives += int64(len(falseNegatives))
				rm.falseNegatives += int64(len(falseNegatives))

				rm.logger.Warn("False negative detected",
					zap.String("pattern", patternName),
					zap.Int("count", len(falseNegatives)),
					zap.ByteStrings("missed", falseNegatives),
				)
			}
		}

		// Update effectiveness score
		if stats.TotalMatches > 0 {
			stats.Effectiveness = float64(stats.TotalMatches-stats.FalsePositives) / float64(stats.TotalMatches)
		}
	}
}

// LoadValidationPatterns loads validation patterns for false positive/negative detection
func (rm *RedactionMonitor) LoadValidationPatterns(patterns []ValidationPattern) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for _, pattern := range patterns {
		validationPattern := &ValidationPattern{
			Name:               pattern.Name,
			OriginalPattern:    pattern.OriginalPattern,
			ExpectedRedactions: pattern.ExpectedRedactions,
			UnexpectedMatches:  pattern.UnexpectedMatches,
		}

		// Compile false positive regex if provided
		if len(pattern.UnexpectedMatches) > 0 {
			// Create regex that matches any of the unexpected patterns
			regexStr := "(?:" + pattern.UnexpectedMatches[0]
			for _, match := range pattern.UnexpectedMatches[1:] {
				regexStr += "|" + match
			}
			regexStr += ")"

			regex, err := regexp.Compile(regexStr)
			if err != nil {
				return fmt.Errorf("failed to compile false positive regex for pattern %s: %w", pattern.Name, err)
			}
			validationPattern.FalsePositiveRegex = regex
		}

		// Compile false negative regex if provided
		if len(pattern.ExpectedRedactions) > 0 {
			// Create regex that matches any of the expected patterns that should be redacted
			regexStr := "(?:" + pattern.ExpectedRedactions[0]
			for _, match := range pattern.ExpectedRedactions[1:] {
				regexStr += "|" + match
			}
			regexStr += ")"

			regex, err := regexp.Compile(regexStr)
			if err != nil {
				return fmt.Errorf("failed to compile false negative regex for pattern %s: %w", pattern.Name, err)
			}
			validationPattern.FalseNegativeRegex = regex
		}

		rm.validationPatterns[pattern.Name] = validationPattern
	}

	rm.logger.Info("Validation patterns loaded",
		zap.Int("pattern_count", len(patterns)),
	)

	return nil
}

// GenerateReport generates a comprehensive monitoring report
func (rm *RedactionMonitor) GenerateReport() *MonitoringReport {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	report := &MonitoringReport{
		Timestamp:       time.Now(),
		TotalRequests:   rm.totalRequests,
		TotalRedactions: rm.totalRedactions,
		PatternStats:    make(map[string]*PatternStats),
		Recommendations: make([]string, 0),
	}

	// Calculate rates
	if rm.totalRedactions > 0 {
		report.FalsePositiveRate = float64(rm.falsePositives) / float64(rm.totalRedactions)
		report.FalseNegativeRate = float64(rm.falseNegatives) / float64(rm.totalRedactions)
	}

	// Calculate average processing time
	if rm.totalRequests > 0 {
		report.AvgProcessingTime = rm.processingTimeTotal / time.Duration(rm.totalRequests)
	}

	// Check if within budget
	report.WithinBudget = report.FalsePositiveRate <= rm.falsePositiveBudget

	// Copy pattern stats
	for name, stats := range rm.patternEffectiveness {
		statsCopy := *stats
		report.PatternStats[name] = &statsCopy
	}

	// Generate recommendations
	report.Recommendations = rm.generateRecommendations(report)

	return report
}

// generateRecommendations generates actionable recommendations based on monitoring data
func (rm *RedactionMonitor) generateRecommendations(report *MonitoringReport) []string {
	recommendations := make([]string, 0)

	// Check false positive rate
	if report.FalsePositiveRate > rm.falsePositiveBudget {
		recommendations = append(recommendations,
			fmt.Sprintf("False positive rate (%.2f%%) exceeds budget (%.2f%%). Consider refining patterns.",
				report.FalsePositiveRate*100, rm.falsePositiveBudget*100))
	}

	// Check false negative rate
	if report.FalseNegativeRate > 0.01 { // 1% threshold
		recommendations = append(recommendations,
			fmt.Sprintf("False negative rate (%.2f%%) detected. Review patterns for completeness.",
				report.FalseNegativeRate*100))
	}

	// Check processing time
	if report.AvgProcessingTime > 10*time.Millisecond {
		recommendations = append(recommendations,
			fmt.Sprintf("Average processing time (%.2fms) is high. Consider optimizing patterns.",
				float64(report.AvgProcessingTime.Nanoseconds())/1e6))
	}

	// Check individual pattern effectiveness
	for name, stats := range report.PatternStats {
		if stats.Effectiveness < 0.95 { // 95% effectiveness threshold
			recommendations = append(recommendations,
				fmt.Sprintf("Pattern '%s' has low effectiveness (%.1f%%). Consider refinement.",
					name, stats.Effectiveness*100))
		}

		if stats.TotalMatches == 0 && !stats.LastUsed.IsZero() && time.Since(stats.LastUsed) > 24*time.Hour {
			recommendations = append(recommendations,
				fmt.Sprintf("Pattern '%s' has not been used recently. Consider removal if no longer needed.",
					name))
		}
	}

	return recommendations
}

// GetPatternStats returns statistics for a specific pattern
func (rm *RedactionMonitor) GetPatternStats(patternName string) (*PatternStats, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	stats, exists := rm.patternEffectiveness[patternName]
	if !exists {
		return nil, false
	}

	// Return a copy to prevent external modification
	statsCopy := *stats
	return &statsCopy, true
}

// ResetStats resets all monitoring statistics
func (rm *RedactionMonitor) ResetStats() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.totalRequests = 0
	rm.totalRedactions = 0
	rm.falsePositives = 0
	rm.falseNegatives = 0
	rm.processingTimeTotal = 0
	rm.patternEffectiveness = make(map[string]*PatternStats)

	rm.logger.Info("Monitoring statistics reset")
}

// SetFalsePositiveBudget updates the false positive budget
func (rm *RedactionMonitor) SetFalsePositiveBudget(budget float64) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.falsePositiveBudget = budget

	rm.logger.Info("False positive budget updated",
		zap.Float64("budget", budget),
	)
}

// EnableMonitoring enables or disables monitoring
func (rm *RedactionMonitor) EnableMonitoring(enabled bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.monitoringEnabled = enabled

	rm.logger.Info("Monitoring status updated",
		zap.Bool("enabled", enabled),
	)
}

// IsWithinBudget checks if current false positive rate is within budget
func (rm *RedactionMonitor) IsWithinBudget() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if rm.totalRedactions == 0 {
		return true
	}

	falsePositiveRate := float64(rm.falsePositives) / float64(rm.totalRedactions)
	return falsePositiveRate <= rm.falsePositiveBudget
}

// GetCurrentStats returns current monitoring statistics
func (rm *RedactionMonitor) GetCurrentStats() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	stats := map[string]interface{}{
		"total_requests":      rm.totalRequests,
		"total_redactions":    rm.totalRedactions,
		"false_positives":     rm.falsePositives,
		"false_negatives":     rm.falseNegatives,
		"false_positive_rate": 0.0,
		"false_negative_rate": 0.0,
		"avg_processing_time": time.Duration(0),
		"within_budget":       true,
		"monitoring_enabled":  rm.monitoringEnabled,
		"pattern_count":       len(rm.patternEffectiveness),
	}

	if rm.totalRedactions > 0 {
		stats["false_positive_rate"] = float64(rm.falsePositives) / float64(rm.totalRedactions)
		stats["false_negative_rate"] = float64(rm.falseNegatives) / float64(rm.totalRedactions)
		stats["within_budget"] = stats["false_positive_rate"].(float64) <= rm.falsePositiveBudget
	}

	if rm.totalRequests > 0 {
		stats["avg_processing_time"] = rm.processingTimeTotal / time.Duration(rm.totalRequests)
	}

	return stats
}

package compliance

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// MockAuditLogger implements AuditLogger for testing
type MockAuditLogger struct {
	events           []*AuditEvent
	validationResult *AuditTrailValidation
	validationError  error
}

func (m *MockAuditLogger) ValidateAuditTrail(ctx context.Context, period CompliancePeriod) (*AuditTrailValidation, error) {
	if m.validationError != nil {
		return nil, m.validationError
	}

	if m.validationResult != nil {
		return m.validationResult, nil
	}

	// Default validation result
	return &AuditTrailValidation{
		Period:          period,
		TotalEvents:     len(m.events),
		ValidEvents:     len(m.events),
		InvalidEvents:   0,
		MissingEvents:   0,
		HashChainValid:  true,
		CompletionScore: 100.0,
		IntegrityScore:  100.0,
		Issues:          []string{},
	}, nil
}

func (m *MockAuditLogger) GetAuditEvents(ctx context.Context, period CompliancePeriod) ([]*AuditEvent, error) {
	var filteredEvents []*AuditEvent
	for _, event := range m.events {
		if event.Timestamp.After(period.StartDate) && event.Timestamp.Before(period.EndDate) {
			filteredEvents = append(filteredEvents, event)
		}
	}
	return filteredEvents, nil
}

func (m *MockAuditLogger) ValidateHashChain(ctx context.Context, events []*AuditEvent) error {
	return nil
}

func TestNewComplianceValidator(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := &MockAuditLogger{}

	validator := NewComplianceValidator(logger, mockAuditLogger)

	if validator == nil {
		t.Fatal("Expected validator to be created")
	}

	if len(validator.requirements) == 0 {
		t.Error("Expected requirements to be initialized")
	}

	if len(validator.checks) == 0 {
		t.Error("Expected checks to be initialized")
	}
}

func TestValidateCompliance(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := &MockAuditLogger{
		events: []*AuditEvent{
			{
				ID:        "event1",
				Timestamp: time.Now().Add(-1 * time.Hour),
				EventType: "authentication",
				Subject:   "user@example.com",
				Action:    "login",
				Resource:  "system",
				Result:    "success",
			},
			{
				ID:        "event2",
				Timestamp: time.Now().Add(-30 * time.Minute),
				EventType: "authorization",
				Subject:   "user@example.com",
				Action:    "access",
				Resource:  "resource1",
				Result:    "allowed",
			},
		},
	}

	validator := NewComplianceValidator(logger, mockAuditLogger)

	period := CompliancePeriod{
		StartDate: time.Now().Add(-24 * time.Hour),
		EndDate:   time.Now(),
	}

	report, err := validator.ValidateCompliance(context.Background(), FrameworkSOC2, period)
	if err != nil {
		t.Fatalf("Failed to validate compliance: %v", err)
	}

	if report == nil {
		t.Fatal("Expected compliance report to be generated")
	}

	if report.Framework != FrameworkSOC2 {
		t.Errorf("Expected framework %s, got %s", FrameworkSOC2, report.Framework)
	}

	if len(report.Results) == 0 {
		t.Error("Expected compliance results to be generated")
	}

	if report.Summary == nil {
		t.Error("Expected compliance summary to be generated")
	}

	if report.OverallScore < 0 || report.OverallScore > 100 {
		t.Errorf("Expected overall score between 0-100, got %f", report.OverallScore)
	}
}

func TestValidateAuditTrailCompliance(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := &MockAuditLogger{
		validationResult: &AuditTrailValidation{
			TotalEvents:     100,
			ValidEvents:     98,
			InvalidEvents:   2,
			MissingEvents:   0,
			HashChainValid:  true,
			CompletionScore: 98.0,
			IntegrityScore:  99.0,
			Issues:          []string{"Minor timestamp inconsistency"},
		},
	}

	validator := NewComplianceValidator(logger, mockAuditLogger)

	period := CompliancePeriod{
		StartDate: time.Now().Add(-24 * time.Hour),
		EndDate:   time.Now(),
	}

	validation, err := validator.ValidateAuditTrailCompliance(context.Background(), period)
	if err != nil {
		t.Fatalf("Failed to validate audit trail compliance: %v", err)
	}

	if validation.TotalEvents != 100 {
		t.Errorf("Expected 100 total events, got %d", validation.TotalEvents)
	}

	if validation.ValidEvents != 98 {
		t.Errorf("Expected 98 valid events, got %d", validation.ValidEvents)
	}

	if !validation.HashChainValid {
		t.Error("Expected hash chain to be valid")
	}
}

func TestValidateDataRetention(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Test case 1: No old events (compliant)
	mockAuditLogger := &MockAuditLogger{
		events: []*AuditEvent{}, // No old events
	}

	validator := NewComplianceValidator(logger, mockAuditLogger)

	result, err := validator.ValidateDataRetention(context.Background(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to validate data retention: %v", err)
	}

	if result.Status != StatusCompliant {
		t.Errorf("Expected compliant status, got %s", result.Status)
	}

	if result.Score != 100.0 {
		t.Errorf("Expected score 100.0, got %f", result.Score)
	}

	// Test case 2: Old events exist (non-compliant)
	oldEvent := &AuditEvent{
		ID:        "old-event",
		Timestamp: time.Now().Add(-60 * 24 * time.Hour), // 60 days old
		EventType: "authentication",
		Subject:   "user@example.com",
		Action:    "login",
		Resource:  "system",
	}

	mockAuditLogger.events = []*AuditEvent{oldEvent}

	result, err = validator.ValidateDataRetention(context.Background(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to validate data retention: %v", err)
	}

	if result.Status != StatusNonCompliant {
		t.Errorf("Expected non-compliant status, got %s", result.Status)
	}

	if result.Score != 0.0 {
		t.Errorf("Expected score 0.0, got %f", result.Score)
	}
}

func TestExportReport(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := &MockAuditLogger{}
	validator := NewComplianceValidator(logger, mockAuditLogger)

	// Create a sample report
	report := &ComplianceReport{
		ID:           "test-report",
		Framework:    FrameworkSOC2,
		GeneratedAt:  time.Now(),
		OverallScore: 85.5,
		Status:       StatusCompliant,
		Results: []*ComplianceResult{
			{
				CheckID:   "test-check",
				Status:    StatusCompliant,
				Score:     85.5,
				Message:   "Test check passed",
				Timestamp: time.Now(),
			},
		},
	}

	// Test JSON export
	jsonData, err := validator.ExportReport(report, "json")
	if err != nil {
		t.Fatalf("Failed to export report as JSON: %v", err)
	}

	if len(jsonData) == 0 {
		t.Error("Expected JSON data to be generated")
	}

	// Test CSV export
	csvData, err := validator.ExportReport(report, "csv")
	if err != nil {
		t.Fatalf("Failed to export report as CSV: %v", err)
	}

	if len(csvData) == 0 {
		t.Error("Expected CSV data to be generated")
	}

	// Test unsupported format
	_, err = validator.ExportReport(report, "xml")
	if err == nil {
		t.Error("Expected error for unsupported format")
	}
}

func TestComplianceFrameworks(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := &MockAuditLogger{}
	validator := NewComplianceValidator(logger, mockAuditLogger)

	frameworks := []ComplianceFramework{
		FrameworkSOC2,
		FrameworkGDPR,
		FrameworkISO27001,
		FrameworkHIPAA,
		FrameworkPCIDSS,
		FrameworkNIST,
	}

	period := CompliancePeriod{
		StartDate: time.Now().Add(-24 * time.Hour),
		EndDate:   time.Now(),
	}

	for _, framework := range frameworks {
		t.Run(string(framework), func(t *testing.T) {
			// Check if we have requirements for this framework
			hasRequirements := false
			for _, req := range validator.requirements {
				if req.Framework == framework {
					hasRequirements = true
					break
				}
			}

			if !hasRequirements && (framework == FrameworkSOC2 || framework == FrameworkGDPR || framework == FrameworkISO27001) {
				t.Errorf("Expected requirements for framework %s", framework)
			}

			// Try to validate compliance (should not error even if no requirements)
			report, err := validator.ValidateCompliance(context.Background(), framework, period)
			if err != nil {
				t.Errorf("Failed to validate compliance for %s: %v", framework, err)
			}

			if report != nil && report.Framework != framework {
				t.Errorf("Expected framework %s in report, got %s", framework, report.Framework)
			}
		})
	}
}

func TestComplianceStatus(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := &MockAuditLogger{}
	validator := NewComplianceValidator(logger, mockAuditLogger)

	testCases := []struct {
		name     string
		results  []*ComplianceResult
		expected ComplianceStatus
	}{
		{
			name: "All Compliant",
			results: []*ComplianceResult{
				{Status: StatusCompliant},
				{Status: StatusCompliant},
			},
			expected: StatusCompliant,
		},
		{
			name: "One Non-Compliant",
			results: []*ComplianceResult{
				{Status: StatusCompliant},
				{Status: StatusNonCompliant},
			},
			expected: StatusNonCompliant,
		},
		{
			name: "Partial Compliance",
			results: []*ComplianceResult{
				{Status: StatusCompliant},
				{Status: StatusPartial},
			},
			expected: StatusPartial,
		},
		{
			name: "Only Errors",
			results: []*ComplianceResult{
				{Status: StatusError},
				{Status: StatusError},
			},
			expected: StatusError,
		},
		{
			name: "Mixed with Errors",
			results: []*ComplianceResult{
				{Status: StatusCompliant},
				{Status: StatusError},
			},
			expected: StatusCompliant,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status := validator.determineOverallStatus(tc.results)
			if status != tc.expected {
				t.Errorf("Expected status %s, got %s", tc.expected, status)
			}
		})
	}
}

func TestGenerateSummary(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := &MockAuditLogger{}
	validator := NewComplianceValidator(logger, mockAuditLogger)

	results := []*ComplianceResult{
		{CheckID: "check1", Status: StatusCompliant},
		{CheckID: "check2", Status: StatusNonCompliant},
		{CheckID: "check3", Status: StatusPartial},
		{CheckID: "check4", Status: StatusError},
	}

	summary := validator.generateSummary(results)

	if summary.TotalChecks != 4 {
		t.Errorf("Expected 4 total checks, got %d", summary.TotalChecks)
	}

	if summary.CompliantChecks != 1 {
		t.Errorf("Expected 1 compliant check, got %d", summary.CompliantChecks)
	}

	if summary.NonCompliantChecks != 1 {
		t.Errorf("Expected 1 non-compliant check, got %d", summary.NonCompliantChecks)
	}

	if summary.PartialChecks != 1 {
		t.Errorf("Expected 1 partial check, got %d", summary.PartialChecks)
	}

	if summary.ErrorChecks != 1 {
		t.Errorf("Expected 1 error check, got %d", summary.ErrorChecks)
	}
}

func TestGenerateRecommendations(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := &MockAuditLogger{}
	validator := NewComplianceValidator(logger, mockAuditLogger)

	results := []*ComplianceResult{
		{
			CheckID:     "check1",
			Status:      StatusCompliant,
			Remediation: "", // No remediation for compliant
		},
		{
			CheckID:     "check2",
			Status:      StatusNonCompliant,
			Remediation: "Fix authentication issues",
		},
		{
			CheckID:     "check3",
			Status:      StatusPartial,
			Remediation: "Improve logging configuration",
		},
		{
			CheckID:     "check4",
			Status:      StatusNonCompliant,
			Remediation: "Fix authentication issues", // Duplicate
		},
	}

	recommendations := validator.generateRecommendations(results)

	expectedRecommendations := []string{
		"Fix authentication issues",
		"Improve logging configuration",
	}

	if len(recommendations) != len(expectedRecommendations) {
		t.Errorf("Expected %d recommendations, got %d", len(expectedRecommendations), len(recommendations))
	}

	for i, expected := range expectedRecommendations {
		if i >= len(recommendations) || recommendations[i] != expected {
			t.Errorf("Expected recommendation %d to be '%s', got '%s'", i, expected, recommendations[i])
		}
	}
}

// Benchmark compliance validation performance
func BenchmarkValidateCompliance(b *testing.B) {
	logger := zaptest.NewLogger(b)
	mockAuditLogger := &MockAuditLogger{
		events: make([]*AuditEvent, 1000), // 1000 events
	}

	// Generate mock events
	for i := 0; i < 1000; i++ {
		mockAuditLogger.events[i] = &AuditEvent{
			ID:        fmt.Sprintf("event-%d", i),
			Timestamp: time.Now().Add(-time.Duration(i) * time.Minute),
			EventType: "authentication",
			Subject:   "user@example.com",
			Action:    "login",
			Resource:  "system",
		}
	}

	validator := NewComplianceValidator(logger, mockAuditLogger)

	period := CompliancePeriod{
		StartDate: time.Now().Add(-24 * time.Hour),
		EndDate:   time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := validator.ValidateCompliance(context.Background(), FrameworkSOC2, period)
		if err != nil {
			b.Fatalf("Compliance validation failed: %v", err)
		}
	}
}

func TestComplianceValidatorConcurrency(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := &MockAuditLogger{}
	validator := NewComplianceValidator(logger, mockAuditLogger)

	period := CompliancePeriod{
		StartDate: time.Now().Add(-24 * time.Hour),
		EndDate:   time.Now(),
	}

	// Run multiple compliance validations concurrently
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			framework := FrameworkSOC2
			if id%2 == 0 {
				framework = FrameworkGDPR
			}

			_, err := validator.ValidateCompliance(context.Background(), framework, period)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent compliance validation failed: %v", err)
	}
}

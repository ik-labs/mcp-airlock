// Package compliance provides compliance validation and reporting capabilities
package compliance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ComplianceFramework represents different compliance frameworks
type ComplianceFramework string

const (
	FrameworkSOC2     ComplianceFramework = "SOC2"
	FrameworkISO27001 ComplianceFramework = "ISO27001"
	FrameworkGDPR     ComplianceFramework = "GDPR"
	FrameworkHIPAA    ComplianceFramework = "HIPAA"
	FrameworkPCIDSS   ComplianceFramework = "PCI-DSS"
	FrameworkNIST     ComplianceFramework = "NIST"
)

// ComplianceRequirement represents a specific compliance requirement
type ComplianceRequirement struct {
	ID          string              `json:"id"`
	Framework   ComplianceFramework `json:"framework"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Category    string              `json:"category"`
	Severity    string              `json:"severity"`
	Required    bool                `json:"required"`
	Automated   bool                `json:"automated"`
}

// ComplianceCheck represents a compliance validation check
type ComplianceCheck struct {
	RequirementID string                                                                 `json:"requirement_id"`
	CheckID       string                                                                 `json:"check_id"`
	Name          string                                                                 `json:"name"`
	Description   string                                                                 `json:"description"`
	CheckFunc     func(ctx context.Context, data interface{}) (*ComplianceResult, error) `json:"-"`
	Metadata      map[string]interface{}                                                 `json:"metadata"`
}

// ComplianceResult represents the result of a compliance check
type ComplianceResult struct {
	CheckID     string                 `json:"check_id"`
	Status      ComplianceStatus       `json:"status"`
	Score       float64                `json:"score"`
	Message     string                 `json:"message"`
	Evidence    []string               `json:"evidence"`
	Remediation string                 `json:"remediation"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ComplianceStatus represents the status of a compliance check
type ComplianceStatus string

const (
	StatusCompliant     ComplianceStatus = "compliant"
	StatusNonCompliant  ComplianceStatus = "non_compliant"
	StatusPartial       ComplianceStatus = "partial"
	StatusNotApplicable ComplianceStatus = "not_applicable"
	StatusError         ComplianceStatus = "error"
)

// ComplianceReport represents a comprehensive compliance report
type ComplianceReport struct {
	ID              string                 `json:"id"`
	Framework       ComplianceFramework    `json:"framework"`
	GeneratedAt     time.Time              `json:"generated_at"`
	Period          CompliancePeriod       `json:"period"`
	OverallScore    float64                `json:"overall_score"`
	Status          ComplianceStatus       `json:"status"`
	Results         []*ComplianceResult    `json:"results"`
	Summary         *ComplianceSummary     `json:"summary"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// CompliancePeriod represents the time period for compliance reporting
type CompliancePeriod struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
}

// ComplianceSummary provides a summary of compliance status
type ComplianceSummary struct {
	TotalChecks        int                         `json:"total_checks"`
	CompliantChecks    int                         `json:"compliant_checks"`
	NonCompliantChecks int                         `json:"non_compliant_checks"`
	PartialChecks      int                         `json:"partial_checks"`
	ErrorChecks        int                         `json:"error_checks"`
	ByCategory         map[string]*CategorySummary `json:"by_category"`
	BySeverity         map[string]*SeveritySummary `json:"by_severity"`
}

// CategorySummary provides compliance summary by category
type CategorySummary struct {
	Total     int     `json:"total"`
	Compliant int     `json:"compliant"`
	Score     float64 `json:"score"`
}

// SeveritySummary provides compliance summary by severity
type SeveritySummary struct {
	Total     int     `json:"total"`
	Compliant int     `json:"compliant"`
	Score     float64 `json:"score"`
}

// ComplianceValidator manages compliance validation
type ComplianceValidator struct {
	logger       *zap.Logger
	requirements map[string]*ComplianceRequirement
	checks       map[string]*ComplianceCheck
	auditLogger  AuditLogger
}

// AuditLogger interface for audit trail validation
type AuditLogger interface {
	ValidateAuditTrail(ctx context.Context, period CompliancePeriod) (*AuditTrailValidation, error)
	GetAuditEvents(ctx context.Context, period CompliancePeriod) ([]*AuditEvent, error)
	ValidateHashChain(ctx context.Context, events []*AuditEvent) error
}

// AuditEvent represents an audit event for compliance validation
type AuditEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"`
	Subject      string                 `json:"subject"`
	Action       string                 `json:"action"`
	Resource     string                 `json:"resource"`
	Result       string                 `json:"result"`
	Hash         string                 `json:"hash"`
	PreviousHash string                 `json:"previous_hash"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// AuditTrailValidation represents audit trail validation results
type AuditTrailValidation struct {
	Period          CompliancePeriod `json:"period"`
	TotalEvents     int              `json:"total_events"`
	ValidEvents     int              `json:"valid_events"`
	InvalidEvents   int              `json:"invalid_events"`
	MissingEvents   int              `json:"missing_events"`
	HashChainValid  bool             `json:"hash_chain_valid"`
	CompletionScore float64          `json:"completion_score"`
	IntegrityScore  float64          `json:"integrity_score"`
	Issues          []string         `json:"issues"`
}

// NewComplianceValidator creates a new compliance validator
func NewComplianceValidator(logger *zap.Logger, auditLogger AuditLogger) *ComplianceValidator {
	validator := &ComplianceValidator{
		logger:       logger,
		requirements: make(map[string]*ComplianceRequirement),
		checks:       make(map[string]*ComplianceCheck),
		auditLogger:  auditLogger,
	}

	// Initialize with default requirements and checks
	validator.initializeDefaultRequirements()
	validator.initializeDefaultChecks()

	return validator
}

// initializeDefaultRequirements sets up default compliance requirements
func (cv *ComplianceValidator) initializeDefaultRequirements() {
	requirements := []*ComplianceRequirement{
		{
			ID:          "SOC2-CC6.1",
			Framework:   FrameworkSOC2,
			Title:       "Logical and Physical Access Controls",
			Description: "The entity implements logical and physical access controls to protect against threats from sources outside its system boundaries.",
			Category:    "Access Control",
			Severity:    "High",
			Required:    true,
			Automated:   true,
		},
		{
			ID:          "SOC2-CC6.7",
			Framework:   FrameworkSOC2,
			Title:       "Data Transmission and Disposal",
			Description: "The entity restricts the transmission, movement, and disposal of information to authorized internal and external users and processes.",
			Category:    "Data Protection",
			Severity:    "High",
			Required:    true,
			Automated:   true,
		},
		{
			ID:          "SOC2-CC7.1",
			Framework:   FrameworkSOC2,
			Title:       "System Monitoring",
			Description: "The entity monitors system components and the operation of controls to detect anomalies that are indicative of malicious acts, natural disasters, and errors.",
			Category:    "Monitoring",
			Severity:    "Medium",
			Required:    true,
			Automated:   true,
		},
		{
			ID:          "GDPR-Art32",
			Framework:   FrameworkGDPR,
			Title:       "Security of Processing",
			Description: "Taking into account the state of the art, the costs of implementation and the nature, scope, context and purposes of processing as well as the risk of varying likelihood and severity for the rights and freedoms of natural persons, the controller and the processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk.",
			Category:    "Data Security",
			Severity:    "High",
			Required:    true,
			Automated:   true,
		},
		{
			ID:          "GDPR-Art30",
			Framework:   FrameworkGDPR,
			Title:       "Records of Processing Activities",
			Description: "Each controller and, where applicable, the controller's representative, shall maintain a record of processing activities under its responsibility.",
			Category:    "Documentation",
			Severity:    "Medium",
			Required:    true,
			Automated:   true,
		},
		{
			ID:          "ISO27001-A.12.4.1",
			Framework:   FrameworkISO27001,
			Title:       "Event Logging",
			Description: "Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.",
			Category:    "Logging",
			Severity:    "High",
			Required:    true,
			Automated:   true,
		},
		{
			ID:          "ISO27001-A.18.1.4",
			Framework:   FrameworkISO27001,
			Title:       "Privacy and Protection of Personally Identifiable Information",
			Description: "Privacy and protection of personally identifiable information shall be ensured as required in relevant legislation and regulation where applicable.",
			Category:    "Privacy",
			Severity:    "High",
			Required:    true,
			Automated:   true,
		},
	}

	for _, req := range requirements {
		cv.requirements[req.ID] = req
	}
}

// initializeDefaultChecks sets up default compliance checks
func (cv *ComplianceValidator) initializeDefaultChecks() {
	checks := []*ComplianceCheck{
		{
			RequirementID: "SOC2-CC6.1",
			CheckID:       "access-control-authentication",
			Name:          "Authentication Controls",
			Description:   "Verify that authentication controls are properly implemented",
			CheckFunc:     cv.checkAuthenticationControls,
		},
		{
			RequirementID: "SOC2-CC6.7",
			CheckID:       "data-encryption-transit",
			Name:          "Data Encryption in Transit",
			Description:   "Verify that data is encrypted during transmission",
			CheckFunc:     cv.checkDataEncryptionInTransit,
		},
		{
			RequirementID: "SOC2-CC7.1",
			CheckID:       "audit-logging-enabled",
			Name:          "Audit Logging",
			Description:   "Verify that comprehensive audit logging is enabled",
			CheckFunc:     cv.checkAuditLogging,
		},
		{
			RequirementID: "GDPR-Art32",
			CheckID:       "data-protection-measures",
			Name:          "Data Protection Measures",
			Description:   "Verify that appropriate data protection measures are implemented",
			CheckFunc:     cv.checkDataProtectionMeasures,
		},
		{
			RequirementID: "GDPR-Art30",
			CheckID:       "processing-records",
			Name:          "Processing Records",
			Description:   "Verify that records of processing activities are maintained",
			CheckFunc:     cv.checkProcessingRecords,
		},
		{
			RequirementID: "ISO27001-A.12.4.1",
			CheckID:       "event-logging-comprehensive",
			Name:          "Comprehensive Event Logging",
			Description:   "Verify that comprehensive event logging is implemented",
			CheckFunc:     cv.checkComprehensiveEventLogging,
		},
		{
			RequirementID: "ISO27001-A.18.1.4",
			CheckID:       "pii-protection",
			Name:          "PII Protection",
			Description:   "Verify that personally identifiable information is properly protected",
			CheckFunc:     cv.checkPIIProtection,
		},
	}

	for _, check := range checks {
		cv.checks[check.CheckID] = check
	}
}

// ValidateCompliance performs compliance validation for a specific framework
func (cv *ComplianceValidator) ValidateCompliance(ctx context.Context, framework ComplianceFramework, period CompliancePeriod) (*ComplianceReport, error) {
	cv.logger.Info("Starting compliance validation",
		zap.String("framework", string(framework)),
		zap.Time("start_date", period.StartDate),
		zap.Time("end_date", period.EndDate),
	)

	report := &ComplianceReport{
		ID:          cv.generateReportID(framework, period),
		Framework:   framework,
		GeneratedAt: time.Now(),
		Period:      period,
		Results:     make([]*ComplianceResult, 0),
		Metadata:    make(map[string]interface{}),
	}

	// Get relevant checks for the framework
	relevantChecks := cv.getChecksForFramework(framework)

	var totalScore float64
	var validChecks int

	// Execute each compliance check
	for _, check := range relevantChecks {
		result, err := cv.executeCheck(ctx, check, period)
		if err != nil {
			cv.logger.Error("Compliance check failed",
				zap.String("check_id", check.CheckID),
				zap.Error(err),
			)
			result = &ComplianceResult{
				CheckID:   check.CheckID,
				Status:    StatusError,
				Score:     0.0,
				Message:   fmt.Sprintf("Check execution failed: %v", err),
				Timestamp: time.Now(),
			}
		}

		report.Results = append(report.Results, result)

		if result.Status != StatusError && result.Status != StatusNotApplicable {
			totalScore += result.Score
			validChecks++
		}
	}

	// Calculate overall score
	if validChecks > 0 {
		report.OverallScore = totalScore / float64(validChecks)
	}

	// Determine overall status
	report.Status = cv.determineOverallStatus(report.Results)

	// Generate summary
	report.Summary = cv.generateSummary(report.Results)

	// Generate recommendations
	report.Recommendations = cv.generateRecommendations(report.Results)

	cv.logger.Info("Compliance validation completed",
		zap.String("framework", string(framework)),
		zap.Float64("overall_score", report.OverallScore),
		zap.String("status", string(report.Status)),
		zap.Int("total_checks", len(report.Results)),
	)

	return report, nil
}

// ValidateAuditTrailCompliance validates audit trail compliance
func (cv *ComplianceValidator) ValidateAuditTrailCompliance(ctx context.Context, period CompliancePeriod) (*AuditTrailValidation, error) {
	cv.logger.Info("Validating audit trail compliance",
		zap.Time("start_date", period.StartDate),
		zap.Time("end_date", period.EndDate),
	)

	return cv.auditLogger.ValidateAuditTrail(ctx, period)
}

// ValidateDataRetention validates data retention compliance
func (cv *ComplianceValidator) ValidateDataRetention(ctx context.Context, retentionPeriod time.Duration) (*ComplianceResult, error) {
	cv.logger.Info("Validating data retention compliance",
		zap.Duration("retention_period", retentionPeriod),
	)

	// Get audit events older than retention period
	cutoffDate := time.Now().Add(-retentionPeriod)
	period := CompliancePeriod{
		StartDate: time.Now().Add(-365 * 24 * time.Hour), // Look back 1 year
		EndDate:   cutoffDate,
	}

	events, err := cv.auditLogger.GetAuditEvents(ctx, period)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit events: %w", err)
	}

	result := &ComplianceResult{
		CheckID:   "data-retention-validation",
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Check if old events still exist (they should be cleaned up)
	if len(events) > 0 {
		result.Status = StatusNonCompliant
		result.Score = 0.0
		result.Message = fmt.Sprintf("Found %d audit events older than retention period", len(events))
		result.Evidence = []string{
			fmt.Sprintf("Retention period: %v", retentionPeriod),
			fmt.Sprintf("Cutoff date: %v", cutoffDate),
			fmt.Sprintf("Old events found: %d", len(events)),
		}
		result.Remediation = "Implement automated cleanup of audit events older than retention period"
	} else {
		result.Status = StatusCompliant
		result.Score = 100.0
		result.Message = "Data retention policy is properly enforced"
		result.Evidence = []string{
			fmt.Sprintf("Retention period: %v", retentionPeriod),
			fmt.Sprintf("No events found older than cutoff date: %v", cutoffDate),
		}
	}

	result.Metadata["retention_period_days"] = retentionPeriod.Hours() / 24
	result.Metadata["cutoff_date"] = cutoffDate
	result.Metadata["old_events_count"] = len(events)

	return result, nil
}

// executeCheck executes a specific compliance check
func (cv *ComplianceValidator) executeCheck(ctx context.Context, check *ComplianceCheck, period CompliancePeriod) (*ComplianceResult, error) {
	cv.logger.Debug("Executing compliance check",
		zap.String("check_id", check.CheckID),
		zap.String("name", check.Name),
	)

	// Prepare check data
	checkData := map[string]interface{}{
		"period":    period,
		"timestamp": time.Now(),
	}

	// Execute the check function
	result, err := check.CheckFunc(ctx, checkData)
	if err != nil {
		return nil, fmt.Errorf("check execution failed: %w", err)
	}

	// Ensure result has required fields
	if result.CheckID == "" {
		result.CheckID = check.CheckID
	}
	if result.Timestamp.IsZero() {
		result.Timestamp = time.Now()
	}

	return result, nil
}

// getChecksForFramework returns checks relevant to a specific framework
func (cv *ComplianceValidator) getChecksForFramework(framework ComplianceFramework) []*ComplianceCheck {
	var relevantChecks []*ComplianceCheck

	for _, check := range cv.checks {
		if req, exists := cv.requirements[check.RequirementID]; exists {
			if req.Framework == framework {
				relevantChecks = append(relevantChecks, check)
			}
		}
	}

	return relevantChecks
}

// determineOverallStatus determines the overall compliance status
func (cv *ComplianceValidator) determineOverallStatus(results []*ComplianceResult) ComplianceStatus {
	var compliant, nonCompliant, partial, errors int

	for _, result := range results {
		switch result.Status {
		case StatusCompliant:
			compliant++
		case StatusNonCompliant:
			nonCompliant++
		case StatusPartial:
			partial++
		case StatusError:
			errors++
		}
	}

	// If there are any non-compliant checks, overall status is non-compliant
	if nonCompliant > 0 {
		return StatusNonCompliant
	}

	// If there are partial compliance issues, overall status is partial
	if partial > 0 {
		return StatusPartial
	}

	// If there are only errors, overall status is error
	if errors > 0 && compliant == 0 {
		return StatusError
	}

	// Otherwise, compliant
	return StatusCompliant
}

// generateSummary generates a compliance summary
func (cv *ComplianceValidator) generateSummary(results []*ComplianceResult) *ComplianceSummary {
	summary := &ComplianceSummary{
		TotalChecks: len(results),
		ByCategory:  make(map[string]*CategorySummary),
		BySeverity:  make(map[string]*SeveritySummary),
	}

	for _, result := range results {
		switch result.Status {
		case StatusCompliant:
			summary.CompliantChecks++
		case StatusNonCompliant:
			summary.NonCompliantChecks++
		case StatusPartial:
			summary.PartialChecks++
		case StatusError:
			summary.ErrorChecks++
		}

		// Get requirement for categorization
		if check, exists := cv.checks[result.CheckID]; exists {
			if req, exists := cv.requirements[check.RequirementID]; exists {
				// Update category summary
				if summary.ByCategory[req.Category] == nil {
					summary.ByCategory[req.Category] = &CategorySummary{}
				}
				catSummary := summary.ByCategory[req.Category]
				catSummary.Total++
				if result.Status == StatusCompliant {
					catSummary.Compliant++
				}
				if catSummary.Total > 0 {
					catSummary.Score = float64(catSummary.Compliant) / float64(catSummary.Total) * 100
				}

				// Update severity summary
				if summary.BySeverity[req.Severity] == nil {
					summary.BySeverity[req.Severity] = &SeveritySummary{}
				}
				sevSummary := summary.BySeverity[req.Severity]
				sevSummary.Total++
				if result.Status == StatusCompliant {
					sevSummary.Compliant++
				}
				if sevSummary.Total > 0 {
					sevSummary.Score = float64(sevSummary.Compliant) / float64(sevSummary.Total) * 100
				}
			}
		}
	}

	return summary
}

// generateRecommendations generates compliance recommendations
func (cv *ComplianceValidator) generateRecommendations(results []*ComplianceResult) []string {
	var recommendations []string
	recommendationSet := make(map[string]bool)

	for _, result := range results {
		if result.Status == StatusNonCompliant || result.Status == StatusPartial {
			if result.Remediation != "" && !recommendationSet[result.Remediation] {
				recommendations = append(recommendations, result.Remediation)
				recommendationSet[result.Remediation] = true
			}
		}
	}

	// Sort recommendations for consistency
	sort.Strings(recommendations)

	return recommendations
}

// generateReportID generates a unique report ID
func (cv *ComplianceValidator) generateReportID(framework ComplianceFramework, period CompliancePeriod) string {
	data := fmt.Sprintf("%s-%s-%s", framework, period.StartDate.Format("2006-01-02"), period.EndDate.Format("2006-01-02"))
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("compliance-%x", hash[:8])
}

// ExportReport exports a compliance report in the specified format
func (cv *ComplianceValidator) ExportReport(report *ComplianceReport, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(report, "", "  ")
	case "csv":
		return cv.exportReportCSV(report)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// exportReportCSV exports a compliance report in CSV format
func (cv *ComplianceValidator) exportReportCSV(report *ComplianceReport) ([]byte, error) {
	var buffer bytes.Buffer

	// CSV header
	buffer.WriteString("Check ID,Requirement ID,Status,Score,Message,Timestamp\n")

	// CSV data
	for _, result := range report.Results {
		requirementID := ""
		if check, exists := cv.checks[result.CheckID]; exists {
			requirementID = check.RequirementID
		}

		buffer.WriteString(fmt.Sprintf("%s,%s,%s,%.2f,\"%s\",%s\n",
			result.CheckID,
			requirementID,
			result.Status,
			result.Score,
			strings.ReplaceAll(result.Message, "\"", "\"\""), // Escape quotes
			result.Timestamp.Format(time.RFC3339),
		))
	}

	return buffer.Bytes(), nil
}

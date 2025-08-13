package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"time"

	"go.uber.org/zap"
)

// ComplianceDashboard provides a web interface for compliance reporting
type ComplianceDashboard struct {
	validator *ComplianceValidator
	logger    *zap.Logger
	templates map[string]*template.Template
}

// DashboardData represents data for the compliance dashboard
type DashboardData struct {
	Title       string                `json:"title"`
	GeneratedAt time.Time             `json:"generated_at"`
	Frameworks  []ComplianceFramework `json:"frameworks"`
	Reports     []*ComplianceReport   `json:"reports"`
	Summary     *DashboardSummary     `json:"summary"`
	Trends      *ComplianceTrends     `json:"trends"`
	Alerts      []*ComplianceAlert    `json:"alerts"`
}

// DashboardSummary provides overall compliance summary
type DashboardSummary struct {
	OverallScore        float64                    `json:"overall_score"`
	TotalFrameworks     int                        `json:"total_frameworks"`
	CompliantFrameworks int                        `json:"compliant_frameworks"`
	TotalChecks         int                        `json:"total_checks"`
	PassingChecks       int                        `json:"passing_checks"`
	FailingChecks       int                        `json:"failing_checks"`
	ByFramework         map[string]*FrameworkScore `json:"by_framework"`
}

// FrameworkScore represents compliance score for a framework
type FrameworkScore struct {
	Framework ComplianceFramework `json:"framework"`
	Score     float64             `json:"score"`
	Status    ComplianceStatus    `json:"status"`
	LastCheck time.Time           `json:"last_check"`
}

// ComplianceTrends represents compliance trends over time
type ComplianceTrends struct {
	Period     string                  `json:"period"`
	DataPoints []*ComplianceTrendPoint `json:"data_points"`
}

// ComplianceTrendPoint represents a single trend data point
type ComplianceTrendPoint struct {
	Date      time.Time           `json:"date"`
	Framework ComplianceFramework `json:"framework"`
	Score     float64             `json:"score"`
	Status    ComplianceStatus    `json:"status"`
}

// ComplianceAlert represents a compliance alert
type ComplianceAlert struct {
	ID          string              `json:"id"`
	Framework   ComplianceFramework `json:"framework"`
	Severity    string              `json:"severity"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	CreatedAt   time.Time           `json:"created_at"`
	Status      string              `json:"status"`
}

// NewComplianceDashboard creates a new compliance dashboard
func NewComplianceDashboard(validator *ComplianceValidator, logger *zap.Logger) *ComplianceDashboard {
	dashboard := &ComplianceDashboard{
		validator: validator,
		logger:    logger,
		templates: make(map[string]*template.Template),
	}

	dashboard.initializeTemplates()
	return dashboard
}

// initializeTemplates initializes HTML templates for the dashboard
func (cd *ComplianceDashboard) initializeTemplates() {
	// Main dashboard template
	dashboardHTML := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .summary-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary-card h3 { margin: 0 0 10px 0; color: #333; }
        .summary-card .value { font-size: 2em; font-weight: bold; color: #007bff; }
        .frameworks { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .framework-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .framework-card h3 { margin: 0 0 15px 0; color: #333; }
        .score-bar { background: #e9ecef; height: 20px; border-radius: 10px; overflow: hidden; margin: 10px 0; }
        .score-fill { height: 100%; transition: width 0.3s ease; }
        .score-compliant { background: #28a745; }
        .score-partial { background: #ffc107; }
        .score-non-compliant { background: #dc3545; }
        .status { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }
        .status-compliant { background: #d4edda; color: #155724; }
        .status-partial { background: #fff3cd; color: #856404; }
        .status-non-compliant { background: #f8d7da; color: #721c24; }
        .alerts { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .alert { padding: 15px; margin: 10px 0; border-radius: 4px; border-left: 4px solid; }
        .alert-high { background: #f8d7da; border-color: #dc3545; }
        .alert-medium { background: #fff3cd; border-color: #ffc107; }
        .alert-low { background: #d1ecf1; border-color: #17a2b8; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
            <p class="timestamp">Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Overall Score</h3>
                <div class="value">{{printf "%.1f%%" .Summary.OverallScore}}</div>
            </div>
            <div class="summary-card">
                <h3>Frameworks</h3>
                <div class="value">{{.Summary.CompliantFrameworks}}/{{.Summary.TotalFrameworks}}</div>
            </div>
            <div class="summary-card">
                <h3>Passing Checks</h3>
                <div class="value">{{.Summary.PassingChecks}}/{{.Summary.TotalChecks}}</div>
            </div>
            <div class="summary-card">
                <h3>Failing Checks</h3>
                <div class="value">{{.Summary.FailingChecks}}</div>
            </div>
        </div>

        <div class="frameworks">
            {{range $framework, $score := .Summary.ByFramework}}
            <div class="framework-card">
                <h3>{{$framework}}</h3>
                <div class="score-bar">
                    <div class="score-fill {{if ge $score.Score 90.0}}score-compliant{{else if ge $score.Score 70.0}}score-partial{{else}}score-non-compliant{{end}}" 
                         style="width: {{$score.Score}}%"></div>
                </div>
                <p>Score: {{printf "%.1f%%" $score.Score}}</p>
                <span class="status {{if eq $score.Status "compliant"}}status-compliant{{else if eq $score.Status "partial"}}status-partial{{else}}status-non-compliant{{end}}">
                    {{$score.Status}}
                </span>
                <p class="timestamp">Last Check: {{$score.LastCheck.Format "2006-01-02 15:04"}}</p>
            </div>
            {{end}}
        </div>

        {{if .Alerts}}
        <div class="alerts">
            <h2>Compliance Alerts</h2>
            {{range .Alerts}}
            <div class="alert {{if eq .Severity "high"}}alert-high{{else if eq .Severity "medium"}}alert-medium{{else}}alert-low{{end}}">
                <h4>{{.Title}} ({{.Framework}})</h4>
                <p>{{.Description}}</p>
                <p class="timestamp">{{.CreatedAt.Format "2006-01-02 15:04:05"}}</p>
            </div>
            {{end}}
        </div>
        {{end}}
    </div>
</body>
</html>
`

	tmpl, err := template.New("dashboard").Parse(dashboardHTML)
	if err != nil {
		cd.logger.Error("Failed to parse dashboard template", zap.Error(err))
	} else {
		cd.templates["dashboard"] = tmpl
	}
}

// ServeHTTP implements http.Handler for the compliance dashboard
func (cd *ComplianceDashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/compliance":
		cd.handleDashboard(w, r)
	case "/compliance/api/reports":
		cd.handleAPIReports(w, r)
	case "/compliance/api/summary":
		cd.handleAPISummary(w, r)
	case "/compliance/api/validate":
		cd.handleAPIValidate(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleDashboard serves the main compliance dashboard
func (cd *ComplianceDashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Generate dashboard data
	data, err := cd.generateDashboardData(ctx)
	if err != nil {
		cd.logger.Error("Failed to generate dashboard data", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Render template
	tmpl, exists := cd.templates["dashboard"]
	if !exists {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		cd.logger.Error("Failed to render dashboard template", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleAPIReports serves compliance reports via API
func (cd *ComplianceDashboard) handleAPIReports(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	framework := r.URL.Query().Get("framework")
	daysStr := r.URL.Query().Get("days")

	days := 30 // Default to 30 days
	if daysStr != "" {
		if parsed, err := strconv.Atoi(daysStr); err == nil && parsed > 0 {
			days = parsed
		}
	}

	period := CompliancePeriod{
		StartDate: time.Now().Add(-time.Duration(days) * 24 * time.Hour),
		EndDate:   time.Now(),
	}

	var reports []*ComplianceReport

	if framework != "" {
		// Generate report for specific framework
		report, err := cd.validator.ValidateCompliance(ctx, ComplianceFramework(framework), period)
		if err != nil {
			cd.logger.Error("Failed to validate compliance", zap.Error(err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		reports = append(reports, report)
	} else {
		// Generate reports for all frameworks
		frameworks := []ComplianceFramework{FrameworkSOC2, FrameworkGDPR, FrameworkISO27001}
		for _, fw := range frameworks {
			report, err := cd.validator.ValidateCompliance(ctx, fw, period)
			if err != nil {
				cd.logger.Error("Failed to validate compliance",
					zap.String("framework", string(fw)),
					zap.Error(err))
				continue
			}
			reports = append(reports, report)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reports)
}

// handleAPISummary serves compliance summary via API
func (cd *ComplianceDashboard) handleAPISummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	summary, err := cd.generateComplianceSummary(ctx)
	if err != nil {
		cd.logger.Error("Failed to generate compliance summary", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

// handleAPIValidate triggers compliance validation via API
func (cd *ComplianceDashboard) handleAPIValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	framework := r.URL.Query().Get("framework")

	if framework == "" {
		http.Error(w, "Framework parameter required", http.StatusBadRequest)
		return
	}

	period := CompliancePeriod{
		StartDate: time.Now().Add(-30 * 24 * time.Hour),
		EndDate:   time.Now(),
	}

	report, err := cd.validator.ValidateCompliance(ctx, ComplianceFramework(framework), period)
	if err != nil {
		cd.logger.Error("Failed to validate compliance", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// generateDashboardData generates data for the compliance dashboard
func (cd *ComplianceDashboard) generateDashboardData(ctx context.Context) (*DashboardData, error) {
	data := &DashboardData{
		Title:       "MCP Airlock Compliance Dashboard",
		GeneratedAt: time.Now(),
		Frameworks:  []ComplianceFramework{FrameworkSOC2, FrameworkGDPR, FrameworkISO27001},
		Reports:     make([]*ComplianceReport, 0),
	}

	// Generate summary
	summary, err := cd.generateComplianceSummary(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate summary: %w", err)
	}
	data.Summary = summary

	// Generate alerts
	alerts, err := cd.generateComplianceAlerts(ctx)
	if err != nil {
		cd.logger.Warn("Failed to generate compliance alerts", zap.Error(err))
	} else {
		data.Alerts = alerts
	}

	return data, nil
}

// generateComplianceSummary generates overall compliance summary
func (cd *ComplianceDashboard) generateComplianceSummary(ctx context.Context) (*DashboardSummary, error) {
	summary := &DashboardSummary{
		ByFramework: make(map[string]*FrameworkScore),
	}

	period := CompliancePeriod{
		StartDate: time.Now().Add(-30 * 24 * time.Hour),
		EndDate:   time.Now(),
	}

	frameworks := []ComplianceFramework{FrameworkSOC2, FrameworkGDPR, FrameworkISO27001}
	var totalScore float64
	var validFrameworks int

	for _, framework := range frameworks {
		report, err := cd.validator.ValidateCompliance(ctx, framework, period)
		if err != nil {
			cd.logger.Error("Failed to validate compliance for summary",
				zap.String("framework", string(framework)),
				zap.Error(err))
			continue
		}

		frameworkScore := &FrameworkScore{
			Framework: framework,
			Score:     report.OverallScore,
			Status:    report.Status,
			LastCheck: report.GeneratedAt,
		}

		summary.ByFramework[string(framework)] = frameworkScore
		summary.TotalFrameworks++

		if report.Status == StatusCompliant {
			summary.CompliantFrameworks++
		}

		totalScore += report.OverallScore
		validFrameworks++

		// Count checks
		for _, result := range report.Results {
			summary.TotalChecks++
			if result.Status == StatusCompliant {
				summary.PassingChecks++
			} else if result.Status == StatusNonCompliant {
				summary.FailingChecks++
			}
		}
	}

	if validFrameworks > 0 {
		summary.OverallScore = totalScore / float64(validFrameworks)
	}

	return summary, nil
}

// generateComplianceAlerts generates compliance alerts
func (cd *ComplianceDashboard) generateComplianceAlerts(ctx context.Context) ([]*ComplianceAlert, error) {
	var alerts []*ComplianceAlert

	period := CompliancePeriod{
		StartDate: time.Now().Add(-7 * 24 * time.Hour), // Last 7 days
		EndDate:   time.Now(),
	}

	frameworks := []ComplianceFramework{FrameworkSOC2, FrameworkGDPR, FrameworkISO27001}

	for _, framework := range frameworks {
		report, err := cd.validator.ValidateCompliance(ctx, framework, period)
		if err != nil {
			continue
		}

		// Generate alerts for non-compliant checks
		for _, result := range report.Results {
			if result.Status == StatusNonCompliant {
				alert := &ComplianceAlert{
					ID:          fmt.Sprintf("alert-%s-%s", framework, result.CheckID),
					Framework:   framework,
					Severity:    cd.determineSeverity(result),
					Title:       fmt.Sprintf("Non-compliant check: %s", result.CheckID),
					Description: result.Message,
					CreatedAt:   result.Timestamp,
					Status:      "active",
				}
				alerts = append(alerts, alert)
			}
		}

		// Generate alert for low overall score
		if report.OverallScore < 70.0 {
			alert := &ComplianceAlert{
				ID:          fmt.Sprintf("alert-%s-overall", framework),
				Framework:   framework,
				Severity:    "high",
				Title:       fmt.Sprintf("Low compliance score for %s", framework),
				Description: fmt.Sprintf("Overall compliance score is %.1f%%, below acceptable threshold", report.OverallScore),
				CreatedAt:   report.GeneratedAt,
				Status:      "active",
			}
			alerts = append(alerts, alert)
		}
	}

	// Sort alerts by severity and creation time
	sort.Slice(alerts, func(i, j int) bool {
		severityOrder := map[string]int{"high": 3, "medium": 2, "low": 1}
		if severityOrder[alerts[i].Severity] != severityOrder[alerts[j].Severity] {
			return severityOrder[alerts[i].Severity] > severityOrder[alerts[j].Severity]
		}
		return alerts[i].CreatedAt.After(alerts[j].CreatedAt)
	})

	return alerts, nil
}

// determineSeverity determines alert severity based on compliance result
func (cd *ComplianceDashboard) determineSeverity(result *ComplianceResult) string {
	// Check if this is related to a high-severity requirement
	if check, exists := cd.validator.checks[result.CheckID]; exists {
		if req, exists := cd.validator.requirements[check.RequirementID]; exists {
			switch req.Severity {
			case "High":
				return "high"
			case "Medium":
				return "medium"
			default:
				return "low"
			}
		}
	}

	// Default based on score
	if result.Score < 50.0 {
		return "high"
	} else if result.Score < 80.0 {
		return "medium"
	}
	return "low"
}

// GenerateComplianceReport generates a comprehensive compliance report
func (cd *ComplianceDashboard) GenerateComplianceReport(ctx context.Context, framework ComplianceFramework, format string) ([]byte, error) {
	period := CompliancePeriod{
		StartDate: time.Now().Add(-30 * 24 * time.Hour),
		EndDate:   time.Now(),
	}

	report, err := cd.validator.ValidateCompliance(ctx, framework, period)
	if err != nil {
		return nil, fmt.Errorf("failed to validate compliance: %w", err)
	}

	return cd.validator.ExportReport(report, format)
}

// ScheduleComplianceChecks schedules regular compliance checks
func (cd *ComplianceDashboard) ScheduleComplianceChecks(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	cd.logger.Info("Starting scheduled compliance checks", zap.Duration("interval", interval))

	for {
		select {
		case <-ticker.C:
			cd.runScheduledChecks(ctx)
		case <-ctx.Done():
			cd.logger.Info("Stopping scheduled compliance checks")
			return
		}
	}
}

// runScheduledChecks runs compliance checks for all frameworks
func (cd *ComplianceDashboard) runScheduledChecks(ctx context.Context) {
	cd.logger.Info("Running scheduled compliance checks")

	period := CompliancePeriod{
		StartDate: time.Now().Add(-24 * time.Hour),
		EndDate:   time.Now(),
	}

	frameworks := []ComplianceFramework{FrameworkSOC2, FrameworkGDPR, FrameworkISO27001}

	for _, framework := range frameworks {
		_, err := cd.validator.ValidateCompliance(ctx, framework, period)
		if err != nil {
			cd.logger.Error("Scheduled compliance check failed",
				zap.String("framework", string(framework)),
				zap.Error(err))
		} else {
			cd.logger.Info("Scheduled compliance check completed",
				zap.String("framework", string(framework)))
		}
	}
}

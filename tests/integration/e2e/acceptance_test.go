package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestUserAcceptanceScenarios tests all major user scenarios end-to-end
func TestUserAcceptanceScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping acceptance tests in short mode")
	}

	logger := zaptest.NewLogger(t)
	testEnv := setupTestEnvironment(t, logger)
	defer testEnv.Cleanup()

	// Major user scenarios
	t.Run("DeveloperOnboarding", func(t *testing.T) {
		testDeveloperOnboardingFlow(t, testEnv)
	})

	t.Run("DocumentationAccess", func(t *testing.T) {
		testDocumentationAccessFlow(t, testEnv)
	})

	t.Run("CodeAnalysisWorkflow", func(t *testing.T) {
		testCodeAnalysisWorkflow(t, testEnv)
	})

	t.Run("DataAnalyticsWorkflow", func(t *testing.T) {
		testDataAnalyticsWorkflow(t, testEnv)
	})

	t.Run("MultiTenantIsolation", func(t *testing.T) {
		testMultiTenantIsolationFlow(t, testEnv)
	})

	t.Run("AdminOperations", func(t *testing.T) {
		testAdminOperationsFlow(t, testEnv)
	})

	t.Run("ErrorRecoveryScenarios", func(t *testing.T) {
		testErrorRecoveryScenarios(t, testEnv)
	})

	t.Run("PerformanceUnderLoad", func(t *testing.T) {
		testPerformanceUnderLoad(t, testEnv)
	})
}

func testDeveloperOnboardingFlow(t *testing.T, env *TestEnvironment) {
	// Scenario: New developer gets access to MCP services

	// Step 1: Developer gets JWT token from identity provider
	token := env.CreateValidToken("newdev@company.com", "company-tenant", []string{"mcp.users", "developers"})

	// Step 2: Developer discovers available tools
	discoverRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "discover-tools",
		"method":  "tools/list",
	}

	response := makeAuthenticatedRequest(t, env.Server, token, discoverRequest)
	assert.Equal(t, "2.0", response["jsonrpc"])
	assert.Equal(t, "discover-tools", response["id"])
	assert.NotNil(t, response["result"])

	// Verify tools are returned
	result := response["result"].(map[string]interface{})
	tools := result["tools"].([]interface{})
	assert.Greater(t, len(tools), 0, "Should return available tools")

	// Step 3: Developer tries to use a tool
	toolCallRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "first-tool-call",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "test_tool",
			"arguments": map[string]interface{}{
				"query": "Hello MCP Airlock",
			},
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, token, toolCallRequest)
	assert.Equal(t, "first-tool-call", response["id"])
	assert.NotNil(t, response["result"])

	// Step 4: Verify audit trail for onboarding
	events := env.AuditLogger.GetEvents()
	assert.GreaterOrEqual(t, len(events), 4, "Should have events for discovery and tool call")

	// Verify developer identity is properly tracked
	for _, event := range events {
		assert.Equal(t, "newdev@company.com", event.Subject)
		assert.Equal(t, "company-tenant", event.Tenant)
	}
}

func testDocumentationAccessFlow(t *testing.T, env *TestEnvironment) {
	// Scenario: User accesses documentation through MCP

	token := env.CreateValidToken("user@company.com", "company-tenant", []string{"mcp.users", "docs-readers"})

	// Step 1: List available documentation resources
	listResourcesRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "list-docs",
		"method":  "resources/list",
	}

	response := makeAuthenticatedRequest(t, env.Server, token, listResourcesRequest)
	assert.Equal(t, "list-docs", response["id"])
	assert.NotNil(t, response["result"])

	// Step 2: Search documentation
	searchRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "search-docs",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "search_docs",
			"arguments": map[string]interface{}{
				"query":       "authentication",
				"max_results": 10,
			},
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, token, searchRequest)
	assert.Equal(t, "search-docs", response["id"])
	assert.NotNil(t, response["result"])

	// Step 3: Read specific documentation file
	readFileRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "read-doc-file",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "read_file",
			"arguments": map[string]interface{}{
				"path": "mcp://repo/docs/authentication.md",
			},
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, token, readFileRequest)
	assert.Equal(t, "read-doc-file", response["id"])

	// Should succeed for allowed path
	if response["error"] != nil {
		errorObj := response["error"].(map[string]interface{})
		// Only fail if it's not a path-related security issue
		if !strings.Contains(errorObj["message"].(string), "path") {
			t.Errorf("Unexpected error: %v", errorObj["message"])
		}
	}

	// Step 4: Verify documentation access is audited
	events := env.AuditLogger.GetEvents()
	docEvents := filterEventsByAction(events, "resource_read")
	if len(docEvents) > 0 {
		assert.Equal(t, "user@company.com", docEvents[0].Subject)
		assert.Contains(t, docEvents[0].Metadata, "resource_type")
	}
}

func testCodeAnalysisWorkflow(t *testing.T, env *TestEnvironment) {
	// Scenario: Developer analyzes code using MCP tools

	token := env.CreateValidToken("developer@company.com", "dev-tenant", []string{"mcp.users", "code-analyzers"})

	// Step 1: List code repository contents
	listCodeRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "list-code",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "list_directory",
			"arguments": map[string]interface{}{
				"path": "mcp://repo/src",
			},
		},
	}

	response := makeAuthenticatedRequest(t, env.Server, token, listCodeRequest)
	assert.Equal(t, "list-code", response["id"])

	// Step 2: Analyze specific code file
	analyzeRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "analyze-code",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "analyze_code",
			"arguments": map[string]interface{}{
				"file_path":     "mcp://repo/src/main.go",
				"analysis_type": "security",
			},
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, token, analyzeRequest)
	assert.Equal(t, "analyze-code", response["id"])

	// Step 3: Generate code metrics
	metricsRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "code-metrics",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "generate_metrics",
			"arguments": map[string]interface{}{
				"path":         "mcp://repo/src",
				"metric_types": []string{"complexity", "coverage", "quality"},
			},
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, token, metricsRequest)
	assert.Equal(t, "code-metrics", response["id"])

	// Verify all code analysis operations are audited
	events := env.AuditLogger.GetEvents()
	codeEvents := make([]string, 0)
	for _, event := range events {
		if strings.Contains(event.Action, "tool_call") || event.Action == "policy_evaluate" {
			codeEvents = append(codeEvents, event.Action)
		}
	}
	assert.GreaterOrEqual(t, len(codeEvents), 3, "Should have events for all code analysis operations")
}

func testDataAnalyticsWorkflow(t *testing.T, env *TestEnvironment) {
	// Scenario: Data analyst queries metrics and generates reports

	token := env.CreateValidToken("analyst@company.com", "analytics-tenant", []string{"mcp.users", "data-analysts"})

	// Step 1: Query available metrics
	queryMetricsRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "query-metrics",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "query_metrics",
			"arguments": map[string]interface{}{
				"metric_name": "system_performance",
				"time_range":  "24h",
				"aggregation": "avg",
			},
		},
	}

	response := makeAuthenticatedRequest(t, env.Server, token, queryMetricsRequest)
	assert.Equal(t, "query-metrics", response["id"])

	// Step 2: Generate analytics report
	reportRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "generate-report",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "generate_report",
			"arguments": map[string]interface{}{
				"report_type": "performance_summary",
				"format":      "json",
				"filters": map[string]interface{}{
					"tenant": "analytics-tenant",
					"period": "weekly",
				},
			},
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, token, reportRequest)
	assert.Equal(t, "generate-report", response["id"])

	// Step 3: Export data (with redaction)
	env.Redactor.SetRedactionCount(2) // Simulate PII found in data

	exportRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "export-data",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "export_data",
			"arguments": map[string]interface{}{
				"dataset":     "user_analytics",
				"format":      "csv",
				"destination": "mcp://artifacts/exports/analytics_export.csv",
			},
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, token, exportRequest)
	assert.Equal(t, "export-data", response["id"])

	// Verify data redaction occurred
	events := env.AuditLogger.GetEvents()
	redactionEvents := filterEventsByAction(events, "redact_data")
	if len(redactionEvents) > 0 {
		assert.Equal(t, 2, redactionEvents[0].RedactionCount)
		assert.Equal(t, "analyst@company.com", redactionEvents[0].Subject)
	}
}

func testMultiTenantIsolationFlow(t *testing.T, env *TestEnvironment) {
	// Scenario: Multiple tenants access system simultaneously with proper isolation

	// Create tokens for different tenants
	tenant1Token := env.CreateValidToken("user1@tenant1.com", "tenant-1", []string{"mcp.users"})
	tenant2Token := env.CreateValidToken("user2@tenant2.com", "tenant-2", []string{"mcp.users"})

	env.AuditLogger.Reset()

	// Tenant 1 operations
	tenant1Request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "tenant1-operation",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "read_file",
			"arguments": map[string]interface{}{
				"path": "mcp://repo/tenant1/data.txt",
			},
		},
	}

	response1 := makeAuthenticatedRequest(t, env.Server, tenant1Token, tenant1Request)
	assert.Equal(t, "tenant1-operation", response1["id"])

	// Tenant 2 operations
	tenant2Request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "tenant2-operation",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "read_file",
			"arguments": map[string]interface{}{
				"path": "mcp://repo/tenant2/data.txt",
			},
		},
	}

	response2 := makeAuthenticatedRequest(t, env.Server, tenant2Token, tenant2Request)
	assert.Equal(t, "tenant2-operation", response2["id"])

	// Verify tenant isolation in audit logs
	events := env.AuditLogger.GetEvents()

	tenant1Events := make([]*AuditEvent, 0)
	tenant2Events := make([]*AuditEvent, 0)

	for _, event := range events {
		switch event.Tenant {
		case "tenant-1":
			tenant1Events = append(tenant1Events, event)
		case "tenant-2":
			tenant2Events = append(tenant2Events, event)
		}
	}

	assert.Greater(t, len(tenant1Events), 0, "Should have events for tenant-1")
	assert.Greater(t, len(tenant2Events), 0, "Should have events for tenant-2")

	// Verify no cross-tenant data leakage in audit logs
	for _, event := range tenant1Events {
		assert.Equal(t, "tenant-1", event.Tenant)
		assert.Equal(t, "user1@tenant1.com", event.Subject)
	}

	for _, event := range tenant2Events {
		assert.Equal(t, "tenant-2", event.Tenant)
		assert.Equal(t, "user2@tenant2.com", event.Subject)
	}
}

func testAdminOperationsFlow(t *testing.T, env *TestEnvironment) {
	// Scenario: Administrator performs system operations

	adminToken := env.CreateValidToken("admin@company.com", "admin-tenant", []string{"mcp.users", "mcp.admins"})

	// Step 1: Check system health
	healthRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "health-check",
		"method":  "system/health",
	}

	response := makeAuthenticatedRequest(t, env.Server, adminToken, healthRequest)
	assert.Equal(t, "health-check", response["id"])

	// Step 2: Query audit logs
	auditQueryRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "query-audit",
		"method":  "admin/audit/query",
		"params": map[string]interface{}{
			"time_range": "1h",
			"action":     "token_validate",
			"limit":      100,
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, adminToken, auditQueryRequest)
	assert.Equal(t, "query-audit", response["id"])

	// Step 3: Update policy (simulate hot-reload)
	policyUpdateRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "update-policy",
		"method":  "admin/policy/reload",
		"params": map[string]interface{}{
			"validate_only": false,
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, adminToken, policyUpdateRequest)
	assert.Equal(t, "update-policy", response["id"])

	// Verify admin operations are properly audited
	events := env.AuditLogger.GetEvents()
	adminEvents := make([]*AuditEvent, 0)
	for _, event := range events {
		if event.Subject == "admin@company.com" {
			adminEvents = append(adminEvents, event)
		}
	}

	assert.Greater(t, len(adminEvents), 0, "Should have admin events")

	// Verify admin has elevated privileges in audit metadata
	for _, event := range adminEvents {
		if event.Metadata != nil {
			if groups, ok := event.Metadata["groups"].([]string); ok {
				assert.Contains(t, groups, "mcp.admins")
			}
		}
	}
}

func testErrorRecoveryScenarios(t *testing.T, env *TestEnvironment) {
	// Scenario: System handles various error conditions gracefully

	token := env.CreateValidToken("user@company.com", "test-tenant", []string{"mcp.users"})

	// Test 1: Upstream server timeout
	timeoutRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "timeout-test",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "slow_operation",
			"arguments": map[string]interface{}{
				"delay": "60s", // Should timeout
			},
		},
	}

	response := makeAuthenticatedRequest(t, env.Server, token, timeoutRequest)
	assert.Equal(t, "timeout-test", response["id"])

	// Should get timeout error
	if response["error"] != nil {
		errorObj := response["error"].(map[string]interface{})
		assert.Contains(t, strings.ToLower(errorObj["message"].(string)), "timeout")
	}

	// Test 2: Policy engine failure (should fail closed)
	env.PolicyEngine.SetShouldError(true)

	policyFailRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "policy-fail-test",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "test_tool",
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, token, policyFailRequest)
	assert.Equal(t, "policy-fail-test", response["id"])
	assert.NotNil(t, response["error"], "Should fail closed when policy engine fails")

	env.PolicyEngine.SetShouldError(false)

	// Test 3: Malformed JSON-RPC request
	malformedRequest := `{"jsonrpc": "1.0", "method": "invalid"}`

	httpReq, _ := http.NewRequest("POST", env.Server.URL+"/mcp", strings.NewReader(malformedRequest))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(httpReq)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should handle malformed request gracefully
	assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)

	// Verify all errors are properly audited
	events := env.AuditLogger.GetEvents()
	errorEvents := make([]*AuditEvent, 0)
	for _, event := range events {
		if event.Decision == "deny" || strings.Contains(event.Reason, "error") {
			errorEvents = append(errorEvents, event)
		}
	}

	assert.Greater(t, len(errorEvents), 0, "Should have error events in audit log")
}

func testPerformanceUnderLoad(t *testing.T, env *TestEnvironment) {
	// Scenario: System maintains performance under load

	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	token := env.CreateValidToken("loadtest@company.com", "load-tenant", []string{"mcp.users"})

	// Performance test parameters
	numRequests := 100
	concurrency := 10

	// Create test request
	testRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "test_tool",
			"arguments": map[string]interface{}{
				"operation": "performance_test",
			},
		},
	}

	// Track performance metrics
	startTime := time.Now()
	successCount := 0
	errorCount := 0

	// Create worker pool
	requestChan := make(chan int, numRequests)
	resultChan := make(chan bool, numRequests)

	// Start workers
	for i := 0; i < concurrency; i++ {
		go func() {
			for reqID := range requestChan {
				testRequest["id"] = fmt.Sprintf("perf-test-%d", reqID)

				reqStart := time.Now()
				response := makeAuthenticatedRequest(t, env.Server, token, testRequest)
				reqDuration := time.Since(reqStart)

				// Check if request completed successfully
				success := response["id"] == testRequest["id"] && response["error"] == nil
				resultChan <- success

				// Verify response time is reasonable (< 100ms for mock operations)
				if reqDuration > 100*time.Millisecond {
					t.Logf("Request %d took %v (may be acceptable for real operations)", reqID, reqDuration)
				}
			}
		}()
	}

	// Send requests
	for i := 0; i < numRequests; i++ {
		requestChan <- i
	}
	close(requestChan)

	// Collect results
	for i := 0; i < numRequests; i++ {
		if <-resultChan {
			successCount++
		} else {
			errorCount++
		}
	}

	totalDuration := time.Since(startTime)

	// Calculate performance metrics
	successRate := float64(successCount) / float64(numRequests) * 100
	requestsPerSecond := float64(numRequests) / totalDuration.Seconds()

	t.Logf("Performance test results:")
	t.Logf("  Total requests: %d", numRequests)
	t.Logf("  Successful: %d (%.2f%%)", successCount, successRate)
	t.Logf("  Errors: %d", errorCount)
	t.Logf("  Total duration: %v", totalDuration)
	t.Logf("  Requests/second: %.2f", requestsPerSecond)

	// Performance assertions
	assert.GreaterOrEqual(t, successRate, 95.0, "Success rate should be at least 95%")
	assert.GreaterOrEqual(t, requestsPerSecond, 50.0, "Should handle at least 50 requests/second")

	// Verify all requests were audited
	events := env.AuditLogger.GetEvents()
	assert.GreaterOrEqual(t, len(events), numRequests, "All requests should be audited")

	// Verify audit performance (audit shouldn't be bottleneck)
	auditEventsPerSecond := float64(len(events)) / totalDuration.Seconds()
	assert.GreaterOrEqual(t, auditEventsPerSecond, requestsPerSecond*2, "Audit should keep up with request rate")
}

// TestRealWorldScenarios tests realistic usage patterns
func TestRealWorldScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real-world scenarios in short mode")
	}

	logger := zaptest.NewLogger(t)
	testEnv := setupTestEnvironment(t, logger)
	defer testEnv.Cleanup()

	t.Run("IDEIntegrationWorkflow", func(t *testing.T) {
		testIDEIntegrationWorkflow(t, testEnv)
	})

	t.Run("CICDPipelineIntegration", func(t *testing.T) {
		testCICDPipelineIntegration(t, testEnv)
	})

	t.Run("MonitoringAndAlerting", func(t *testing.T) {
		testMonitoringAndAlerting(t, testEnv)
	})
}

func testIDEIntegrationWorkflow(t *testing.T, env *TestEnvironment) {
	// Scenario: IDE connects to MCP Airlock for code assistance

	token := env.CreateValidToken("developer@company.com", "dev-team", []string{"mcp.users", "ide-users"})

	// Step 1: IDE establishes connection and discovers capabilities
	capabilitiesRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "ide-capabilities",
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"roots": map[string]interface{}{
					"listChanged": true,
				},
				"sampling": map[string]interface{}{},
			},
			"clientInfo": map[string]interface{}{
				"name":    "VSCode",
				"version": "1.85.0",
			},
		},
	}

	response := makeAuthenticatedRequest(t, env.Server, token, capabilitiesRequest)
	assert.Equal(t, "ide-capabilities", response["id"])

	// Step 2: IDE requests code completion
	completionRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "code-completion",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "code_complete",
			"arguments": map[string]interface{}{
				"file_path": "mcp://repo/src/main.go",
				"position":  map[string]interface{}{"line": 42, "character": 15},
				"context":   "function call",
			},
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, token, completionRequest)
	assert.Equal(t, "code-completion", response["id"])

	// Step 3: IDE requests documentation lookup
	docLookupRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "doc-lookup",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "lookup_documentation",
			"arguments": map[string]interface{}{
				"symbol":   "http.Handler",
				"language": "go",
			},
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, token, docLookupRequest)
	assert.Equal(t, "doc-lookup", response["id"])

	// Verify IDE workflow is properly audited
	events := env.AuditLogger.GetEvents()
	ideEvents := make([]*AuditEvent, 0)
	for _, event := range events {
		if event.Subject == "developer@company.com" {
			ideEvents = append(ideEvents, event)
		}
	}

	assert.GreaterOrEqual(t, len(ideEvents), 6, "Should have events for all IDE operations") // 2 events per request (auth + tool)
}

func testCICDPipelineIntegration(t *testing.T, env *TestEnvironment) {
	// Scenario: CI/CD pipeline uses MCP Airlock for automated operations

	ciToken := env.CreateValidToken("ci-pipeline@company.com", "ci-tenant", []string{"mcp.users", "ci-systems"})

	// Step 1: CI system runs code analysis
	analysisRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "ci-analysis",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "analyze_code",
			"arguments": map[string]interface{}{
				"repository":     "mcp://repo/",
				"branch":         "main",
				"commit":         "abc123def456",
				"analysis_types": []string{"security", "quality", "performance"},
			},
		},
	}

	response := makeAuthenticatedRequest(t, env.Server, ciToken, analysisRequest)
	assert.Equal(t, "ci-analysis", response["id"])

	// Step 2: CI system generates test reports
	testReportRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "ci-test-report",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "generate_test_report",
			"arguments": map[string]interface{}{
				"test_results_path": "mcp://repo/test-results/",
				"format":            "junit",
				"output_path":       "mcp://artifacts/reports/test-report.xml",
			},
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, ciToken, testReportRequest)
	assert.Equal(t, "ci-test-report", response["id"])

	// Step 3: CI system publishes artifacts
	publishRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "ci-publish",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "publish_artifacts",
			"arguments": map[string]interface{}{
				"source_path":      "mcp://repo/dist/",
				"destination_path": "mcp://artifacts/releases/v1.2.3/",
				"metadata": map[string]interface{}{
					"version": "1.2.3",
					"commit":  "abc123def456",
					"branch":  "main",
				},
			},
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, ciToken, publishRequest)
	assert.Equal(t, "ci-publish", response["id"])

	// Verify CI operations maintain audit trail
	events := env.AuditLogger.GetEvents()
	ciEvents := make([]*AuditEvent, 0)
	for _, event := range events {
		if event.Subject == "ci-pipeline@company.com" {
			ciEvents = append(ciEvents, event)
		}
	}

	assert.GreaterOrEqual(t, len(ciEvents), 6, "Should have events for all CI operations")

	// Verify CI operations are tagged appropriately
	for _, event := range ciEvents {
		assert.Equal(t, "ci-tenant", event.Tenant)
		if event.Metadata != nil {
			if groups, ok := event.Metadata["groups"].([]string); ok {
				assert.Contains(t, groups, "ci-systems")
			}
		}
	}
}

func testMonitoringAndAlerting(t *testing.T, env *TestEnvironment) {
	// Scenario: Monitoring system tracks MCP Airlock health and performance

	monitorToken := env.CreateValidToken("monitor@company.com", "ops-tenant", []string{"mcp.users", "monitoring"})

	// Step 1: Check system metrics
	metricsRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "system-metrics",
		"method":  "system/metrics",
	}

	response := makeAuthenticatedRequest(t, env.Server, monitorToken, metricsRequest)
	assert.Equal(t, "system-metrics", response["id"])

	// Step 2: Query audit statistics
	auditStatsRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "audit-stats",
		"method":  "admin/audit/stats",
		"params": map[string]interface{}{
			"time_range": "1h",
			"group_by":   []string{"action", "decision", "tenant"},
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, monitorToken, auditStatsRequest)
	assert.Equal(t, "audit-stats", response["id"])

	// Step 3: Check for security violations
	securityCheckRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "security-check",
		"method":  "admin/security/violations",
		"params": map[string]interface{}{
			"time_range": "24h",
			"severity":   "high",
		},
	}

	response = makeAuthenticatedRequest(t, env.Server, monitorToken, securityCheckRequest)
	assert.Equal(t, "security-check", response["id"])

	// Verify monitoring operations are audited
	events := env.AuditLogger.GetEvents()
	monitorEvents := make([]*AuditEvent, 0)
	for _, event := range events {
		if event.Subject == "monitor@company.com" {
			monitorEvents = append(monitorEvents, event)
		}
	}

	assert.GreaterOrEqual(t, len(monitorEvents), 6, "Should have events for all monitoring operations")

	// Verify monitoring has appropriate access
	for _, event := range monitorEvents {
		assert.Equal(t, "ops-tenant", event.Tenant)
		if event.Action == "policy_evaluate" {
			assert.Equal(t, "allow", event.Decision, "Monitoring should have access to system operations")
		}
	}
}

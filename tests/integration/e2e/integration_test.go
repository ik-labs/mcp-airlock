package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEndToEndIntegration tests the complete Airlock system with real MCP servers
func TestEndToEndIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping end-to-end integration test in short mode")
	}

	// Check if we're running in a Kubernetes environment
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		t.Skip("Skipping end-to-end test - not running in Kubernetes")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Test configuration
	airlockURL := os.Getenv("AIRLOCK_URL")
	if airlockURL == "" {
		airlockURL = "http://airlock:8080"
	}

	testToken := os.Getenv("TEST_TOKEN")
	if testToken == "" {
		t.Skip("TEST_TOKEN not provided, skipping authenticated tests")
	}

	// Test suite
	t.Run("HealthChecks", func(t *testing.T) {
		testHealthChecks(t, ctx, airlockURL)
	})

	t.Run("Authentication", func(t *testing.T) {
		testAuthentication(t, ctx, airlockURL, testToken)
	})

	t.Run("MCPServerConnectivity", func(t *testing.T) {
		testMCPServerConnectivity(t, ctx, airlockURL, testToken)
	})

	t.Run("DocumentationServer", func(t *testing.T) {
		testDocumentationServer(t, ctx, airlockURL, testToken)
	})

	t.Run("AnalyticsServer", func(t *testing.T) {
		testAnalyticsServer(t, ctx, airlockURL, testToken)
	})

	t.Run("SecurityPolicies", func(t *testing.T) {
		testSecurityPolicies(t, ctx, airlockURL, testToken)
	})

	t.Run("RateLimiting", func(t *testing.T) {
		testRateLimiting(t, ctx, airlockURL, testToken)
	})

	t.Run("AuditLogging", func(t *testing.T) {
		testAuditLogging(t, ctx, airlockURL, testToken)
	})
}

func testHealthChecks(t *testing.T, _ context.Context, airlockURL string) {
	// Test liveness endpoint
	resp, err := http.Get(airlockURL + "/live")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Test readiness endpoint
	resp, err = http.Get(airlockURL + "/ready")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Test info endpoint
	resp, err = http.Get(airlockURL + "/info")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var info map[string]interface{}
	err = json.Unmarshal(body, &info)
	require.NoError(t, err)
	assert.Contains(t, info, "version")
}

func testAuthentication(t *testing.T, ctx context.Context, airlockURL, testToken string) {
	// Test unauthenticated request (should fail)
	req, err := http.NewRequestWithContext(ctx, "POST", airlockURL+"/mcp", strings.NewReader("{}"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Test authenticated request (should succeed or return different error)
	req, err = http.NewRequestWithContext(ctx, "POST", airlockURL+"/mcp", strings.NewReader("{}"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Should not be unauthorized anymore
	assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode)
}

func testMCPServerConnectivity(t *testing.T, ctx context.Context, airlockURL, testToken string) {
	// Test MCP server list endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", airlockURL+"/mcp/servers", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var servers map[string]interface{}
		err = json.Unmarshal(body, &servers)
		require.NoError(t, err)

		// Should have at least one server configured
		assert.NotEmpty(t, servers)
	}
}

func testDocumentationServer(t *testing.T, ctx context.Context, airlockURL, testToken string) {
	client := &http.Client{Timeout: 30 * time.Second}

	// Test search_docs tool
	searchRequest := map[string]interface{}{
		"method": "tools/call",
		"params": map[string]interface{}{
			"name": "search_docs",
			"arguments": map[string]interface{}{
				"query":       "documentation",
				"max_results": 5,
			},
		},
	}

	reqBody, err := json.Marshal(searchRequest)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(ctx, "POST", airlockURL+"/mcp", bytes.NewReader(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.Unmarshal(body, &response)
		require.NoError(t, err)

		// Should have search results
		if result, ok := response["result"].(map[string]interface{}); ok {
			assert.Contains(t, result, "query")
			assert.Contains(t, result, "results")
		}
	}

	// Test read_file tool
	readRequest := map[string]interface{}{
		"method": "tools/call",
		"params": map[string]interface{}{
			"name": "read_file",
			"arguments": map[string]interface{}{
				"file_path": "README.md",
			},
		},
	}

	reqBody, err = json.Marshal(readRequest)
	require.NoError(t, err)

	req, err = http.NewRequestWithContext(ctx, "POST", airlockURL+"/mcp", bytes.NewReader(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.Unmarshal(body, &response)
		require.NoError(t, err)

		// Should have file content
		if result, ok := response["result"].(map[string]interface{}); ok {
			assert.Contains(t, result, "content")
			assert.Contains(t, result, "path")
		}
	}
}

func testAnalyticsServer(t *testing.T, ctx context.Context, airlockURL, testToken string) {
	client := &http.Client{Timeout: 30 * time.Second}

	// Test query_metrics tool
	metricsRequest := map[string]interface{}{
		"method": "tools/call",
		"params": map[string]interface{}{
			"name": "query_metrics",
			"arguments": map[string]interface{}{
				"metric_name": "cpu_usage",
				"limit":       10,
			},
		},
	}

	reqBody, err := json.Marshal(metricsRequest)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(ctx, "POST", airlockURL+"/mcp", bytes.NewReader(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.Unmarshal(body, &response)
		require.NoError(t, err)

		// Should have metrics data
		if result, ok := response["result"].(map[string]interface{}); ok {
			assert.Contains(t, result, "results")
			assert.Contains(t, result, "total_results")
		}
	}

	// Test generate_report tool
	reportRequest := map[string]interface{}{
		"method": "tools/call",
		"params": map[string]interface{}{
			"name": "generate_report",
			"arguments": map[string]interface{}{
				"report_type": "summary",
			},
		},
	}

	reqBody, err = json.Marshal(reportRequest)
	require.NoError(t, err)

	req, err = http.NewRequestWithContext(ctx, "POST", airlockURL+"/mcp", bytes.NewReader(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.Unmarshal(body, &response)
		require.NoError(t, err)

		// Should have report data
		if result, ok := response["result"].(map[string]interface{}); ok {
			assert.Contains(t, result, "report_name")
			assert.Contains(t, result, "data")
		}
	}
}

func testSecurityPolicies(t *testing.T, ctx context.Context, airlockURL, testToken string) {
	client := &http.Client{Timeout: 30 * time.Second}

	// Test access to restricted path (should be denied)
	restrictedRequest := map[string]interface{}{
		"method": "tools/call",
		"params": map[string]interface{}{
			"name": "read_file",
			"arguments": map[string]interface{}{
				"file_path": "../../../etc/passwd",
			},
		},
	}

	reqBody, err := json.Marshal(restrictedRequest)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(ctx, "POST", airlockURL+"/mcp", bytes.NewReader(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be denied (either 403 or error in response)
	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.Unmarshal(body, &response)
		require.NoError(t, err)

		// Should have an error indicating access denied
		if result, ok := response["result"].(map[string]interface{}); ok {
			if errorMsg, hasError := result["error"]; hasError {
				assert.Contains(t, strings.ToLower(errorMsg.(string)), "access denied")
			}
		}
	} else {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func testRateLimiting(t *testing.T, ctx context.Context, airlockURL, testToken string) {
	client := &http.Client{Timeout: 5 * time.Second}

	// Make multiple rapid requests to trigger rate limiting
	request := map[string]interface{}{
		"method": "tools/call",
		"params": map[string]interface{}{
			"name": "search_docs",
			"arguments": map[string]interface{}{
				"query": "test",
			},
		},
	}

	reqBody, err := json.Marshal(request)
	require.NoError(t, err)

	rateLimitHit := false
	for i := 0; i < 100; i++ {
		req, err := http.NewRequestWithContext(ctx, "POST", airlockURL+"/mcp", bytes.NewReader(reqBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+testToken)

		resp, err := client.Do(req)
		if err != nil {
			continue // Skip network errors
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimitHit = true
			break
		}

		// Small delay to avoid overwhelming the server
		time.Sleep(10 * time.Millisecond)
	}

	// Rate limiting should eventually kick in
	assert.True(t, rateLimitHit, "Rate limiting should be triggered with rapid requests")
}

func testAuditLogging(t *testing.T, ctx context.Context, airlockURL, testToken string) {
	client := &http.Client{Timeout: 30 * time.Second}

	// Make a request that should be audited
	request := map[string]interface{}{
		"method": "tools/call",
		"params": map[string]interface{}{
			"name": "search_docs",
			"arguments": map[string]interface{}{
				"query": "audit_test_query",
			},
		},
	}

	reqBody, err := json.Marshal(request)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(ctx, "POST", airlockURL+"/mcp", bytes.NewReader(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	// Wait a moment for audit log to be written
	time.Sleep(2 * time.Second)

	// Try to access audit logs (if endpoint exists)
	auditReq, err := http.NewRequestWithContext(ctx, "GET", airlockURL+"/admin/audit", nil)
	require.NoError(t, err)
	auditReq.Header.Set("Authorization", "Bearer "+testToken)

	auditResp, err := client.Do(auditReq)
	require.NoError(t, err)
	defer auditResp.Body.Close()

	if auditResp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(auditResp.Body)
		require.NoError(t, err)

		// Should contain our test query in the audit log
		assert.Contains(t, string(body), "audit_test_query")
	}
}

// TestLoadTesting performs basic load testing
func TestLoadTesting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	// Check if we're running in a Kubernetes environment
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		t.Skip("Skipping load test - not running in Kubernetes")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	airlockURL := os.Getenv("AIRLOCK_URL")
	if airlockURL == "" {
		airlockURL = "http://airlock:8080"
	}

	testToken := os.Getenv("TEST_TOKEN")
	if testToken == "" {
		t.Skip("TEST_TOKEN not provided, skipping load test")
	}

	// Load test parameters
	concurrency := 10
	requestsPerWorker := 50
	totalRequests := concurrency * requestsPerWorker

	t.Logf("Starting load test: %d concurrent workers, %d requests each (%d total)",
		concurrency, requestsPerWorker, totalRequests)

	// Channel to collect results
	results := make(chan LoadTestResult, totalRequests)

	// Start workers
	for i := 0; i < concurrency; i++ {
		go loadTestWorker(ctx, airlockURL, testToken, requestsPerWorker, results)
	}

	// Collect results
	var successCount, errorCount int
	var totalResponseTime time.Duration

	for i := 0; i < totalRequests; i++ {
		result := <-results
		if result.Success {
			successCount++
			totalResponseTime += result.ResponseTime
		} else {
			errorCount++
		}
	}

	// Calculate metrics
	successRate := float64(successCount) / float64(totalRequests) * 100
	avgResponseTime := totalResponseTime / time.Duration(successCount)

	t.Logf("Load test results:")
	t.Logf("  Total requests: %d", totalRequests)
	t.Logf("  Successful: %d (%.2f%%)", successCount, successRate)
	t.Logf("  Errors: %d", errorCount)
	t.Logf("  Average response time: %v", avgResponseTime)

	// Assertions
	assert.GreaterOrEqual(t, successRate, 95.0, "Success rate should be at least 95%")
	assert.Less(t, avgResponseTime, 2*time.Second, "Average response time should be under 2 seconds")
}

type LoadTestResult struct {
	Success      bool
	ResponseTime time.Duration
	Error        error
}

func loadTestWorker(ctx context.Context, airlockURL, testToken string, requestCount int, results chan<- LoadTestResult) {
	client := &http.Client{Timeout: 30 * time.Second}

	request := map[string]interface{}{
		"method": "tools/call",
		"params": map[string]interface{}{
			"name": "search_docs",
			"arguments": map[string]interface{}{
				"query": "load_test",
			},
		},
	}

	reqBody, _ := json.Marshal(request)

	for i := 0; i < requestCount; i++ {
		start := time.Now()

		req, err := http.NewRequestWithContext(ctx, "POST", airlockURL+"/mcp", bytes.NewReader(reqBody))
		if err != nil {
			results <- LoadTestResult{Success: false, Error: err}
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+testToken)

		resp, err := client.Do(req)
		responseTime := time.Since(start)

		if err != nil {
			results <- LoadTestResult{Success: false, ResponseTime: responseTime, Error: err}
			continue
		}

		resp.Body.Close()

		success := resp.StatusCode >= 200 && resp.StatusCode < 400
		results <- LoadTestResult{Success: success, ResponseTime: responseTime}

		// Small delay between requests from same worker
		time.Sleep(10 * time.Millisecond)
	}
}

// TestKubernetesDeployment tests Kubernetes-specific functionality
func TestKubernetesDeployment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Kubernetes deployment test in short mode")
	}

	// Check if kubectl is available
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not available, skipping Kubernetes tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	namespace := os.Getenv("TEST_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	// Test pod status
	t.Run("PodStatus", func(t *testing.T) {
		cmd := exec.CommandContext(ctx, "kubectl", "get", "pods", "-l", "app.kubernetes.io/name=airlock", "-n", namespace, "-o", "json")
		output, err := cmd.Output()
		require.NoError(t, err)

		var podList map[string]interface{}
		err = json.Unmarshal(output, &podList)
		require.NoError(t, err)

		items, ok := podList["items"].([]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, items, "Should have at least one Airlock pod")

		// Check that all pods are running
		for _, item := range items {
			pod := item.(map[string]interface{})
			status := pod["status"].(map[string]interface{})
			phase := status["phase"].(string)
			assert.Equal(t, "Running", phase, "Pod should be in Running state")
		}
	})

	// Test service endpoints
	t.Run("ServiceEndpoints", func(t *testing.T) {
		cmd := exec.CommandContext(ctx, "kubectl", "get", "endpoints", "-l", "app.kubernetes.io/name=airlock", "-n", namespace, "-o", "json")
		output, err := cmd.Output()
		require.NoError(t, err)

		var endpointsList map[string]interface{}
		err = json.Unmarshal(output, &endpointsList)
		require.NoError(t, err)

		items, ok := endpointsList["items"].([]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, items, "Should have service endpoints")
	})

	// Test persistent volumes
	t.Run("PersistentVolumes", func(t *testing.T) {
		cmd := exec.CommandContext(ctx, "kubectl", "get", "pvc", "-l", "app.kubernetes.io/name=airlock", "-n", namespace, "-o", "json")
		output, err := cmd.Output()
		require.NoError(t, err)

		var pvcList map[string]interface{}
		err = json.Unmarshal(output, &pvcList)
		require.NoError(t, err)

		items, ok := pvcList["items"].([]interface{})
		require.True(t, ok)

		// Check that PVCs are bound
		for _, item := range items {
			pvc := item.(map[string]interface{})
			status := pvc["status"].(map[string]interface{})
			phase := status["phase"].(string)
			assert.Equal(t, "Bound", phase, "PVC should be bound")
		}
	})
}

// getProjectRoot returns the project root directory
// func getProjectRoot() (string, error) {
// 	wd, err := os.Getwd()
// 	if err != nil {
// 		return "", err
// 	}

// 	// Walk up the directory tree to find go.mod
// 	for {
// 		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
// 			return wd, nil
// 		}

// 		parent := filepath.Dir(wd)
// 		if parent == wd {
// 			return "", fmt.Errorf("could not find project root (go.mod not found)")
// 		}
// 		wd = parent
// 	}
// }

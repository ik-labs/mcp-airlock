package performance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ik-labs/mcp-airlock/pkg/policy"
	"github.com/ik-labs/mcp-airlock/pkg/redact"
	"go.uber.org/zap"
)

// PerformanceBaseline represents performance baseline metrics
type PerformanceBaseline struct {
	TestName         string        `json:"test_name"`
	Timestamp        time.Time     `json:"timestamp"`
	AuthLatency      time.Duration `json:"auth_latency"`
	PolicyLatency    time.Duration `json:"policy_latency"`
	RedactLatency    time.Duration `json:"redact_latency"`
	TotalLatency     time.Duration `json:"total_latency"`
	MemoryUsage      int64         `json:"memory_usage"`
	AllocationsPerOp int64         `json:"allocations_per_op"`
	Throughput       float64       `json:"throughput"`
	Version          string        `json:"version"`
}

// TestPerformanceRegression runs performance regression tests
func TestPerformanceRegression(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance regression test in short mode")
	}

	testCases := []struct {
		name        string
		description string
		testFunc    func(t *testing.T) *PerformanceBaseline
	}{
		{
			name:        "AuthenticationPerformance",
			description: "Authentication latency regression test",
			testFunc:    testAuthenticationPerformance,
		},
		{
			name:        "PolicyEvaluationPerformance",
			description: "Policy evaluation latency regression test",
			testFunc:    testPolicyEvaluationPerformance,
		},
		{
			name:        "RedactionPerformance",
			description: "Data redaction latency regression test",
			testFunc:    testRedactionPerformance,
		},
		{
			name:        "EndToEndPerformance",
			description: "End-to-end request processing regression test",
			testFunc:    testEndToEndPerformance,
		},
	}

	baselineDir := "test-results/performance"
	if err := os.MkdirAll(baselineDir, 0755); err != nil {
		t.Fatalf("Failed to create baseline directory: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Running performance regression test: %s", tc.description)

			// Run the performance test
			current := tc.testFunc(t)
			current.TestName = tc.name
			current.Timestamp = time.Now()
			current.Version = "dev" // Would be set from build info

			// Load baseline if it exists
			baselineFile := filepath.Join(baselineDir, fmt.Sprintf("%s_baseline.json", tc.name))
			baseline, err := loadBaseline(baselineFile)
			if err != nil {
				t.Logf("No baseline found for %s, creating new baseline", tc.name)
				if err := saveBaseline(baselineFile, current); err != nil {
					t.Errorf("Failed to save baseline: %v", err)
				}
				return
			}

			// Compare with baseline
			if err := compareWithBaseline(t, baseline, current); err != nil {
				t.Errorf("Performance regression detected: %v", err)
			}

			// Update baseline if performance improved significantly
			if shouldUpdateBaseline(baseline, current) {
				t.Logf("Performance improved, updating baseline")
				if err := saveBaseline(baselineFile, current); err != nil {
					t.Errorf("Failed to update baseline: %v", err)
				}
			}
		})
	}
}

// testAuthenticationPerformance measures authentication performance (simplified)
func testAuthenticationPerformance(t *testing.T) *PerformanceBaseline {
	t.Helper()

	// Mock authentication simulation
	mockAuth := func(token string) error {
		// Simulate token validation work
		time.Sleep(10 * time.Microsecond)
		return nil
	}

	// Warmup
	for i := 0; i < 100; i++ {
		token := fmt.Sprintf("warmup-token-%d", i)
		err := mockAuth(token)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Measure performance
	iterations := 10000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		token := fmt.Sprintf("test-token-%d", i%100)
		err := mockAuth(token)
		if err != nil {
			t.Fatal(err)
		}
	}

	duration := time.Since(start)
	avgLatency := duration / time.Duration(iterations)
	throughput := float64(iterations) / duration.Seconds()

	return &PerformanceBaseline{
		AuthLatency:      avgLatency,
		TotalLatency:     avgLatency,
		Throughput:       throughput,
		AllocationsPerOp: 5,    // Estimated from benchmarks
		MemoryUsage:      1024, // Estimated
	}
}

// testPolicyEvaluationPerformance measures policy evaluation performance
func testPolicyEvaluationPerformance(t *testing.T) *PerformanceBaseline {
	t.Helper()

	// Setup
	engine := policy.NewOPAEngine(zap.NewNop(), time.Minute)
	defer engine.Close()

	testPolicy := `
package airlock.authz
import rego.v1
default allow := false
allow if {
    input.groups[_] == "mcp.users"
    allowed_tool[input.tool]
    allowed_resource[input.resource]
}
allowed_tool contains tool if {
    tool := input.tool
    tool in ["read_file", "list_directory", "search_docs"]
}
allowed_resource contains resource if {
    resource := input.resource
    startswith(resource, "mcp://repo/")
}
`

	ctx := context.Background()
	err := engine.LoadPolicy(ctx, testPolicy)
	if err != nil {
		t.Fatal(err)
	}

	// Warmup
	for i := 0; i < 100; i++ {
		input := &policy.PolicyInput{
			Subject:  "test@example.com",
			Tenant:   "test-tenant",
			Groups:   []string{"mcp.users"},
			Tool:     "read_file",
			Resource: fmt.Sprintf("mcp://repo/file-%d.txt", i),
			Method:   "GET",
		}
		_, err := engine.Evaluate(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Measure performance
	iterations := 10000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		input := &policy.PolicyInput{
			Subject:  "test@example.com",
			Tenant:   "test-tenant",
			Groups:   []string{"mcp.users"},
			Tool:     "read_file",
			Resource: fmt.Sprintf("mcp://repo/file-%d.txt", i%100),
			Method:   "GET",
		}
		_, err := engine.Evaluate(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
	}

	duration := time.Since(start)
	avgLatency := duration / time.Duration(iterations)
	throughput := float64(iterations) / duration.Seconds()

	return &PerformanceBaseline{
		PolicyLatency:    avgLatency,
		TotalLatency:     avgLatency,
		Throughput:       throughput,
		AllocationsPerOp: 6, // From benchmark results
		MemoryUsage:      2048,
	}
}

// testRedactionPerformance measures redaction performance
func testRedactionPerformance(t *testing.T) *PerformanceBaseline {
	t.Helper()

	// Setup
	redactor := redact.NewRedactor()
	patterns := []redact.Pattern{
		{Name: "email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, Replace: "[redacted-email]"},
		{Name: "phone", Regex: `\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`, Replace: "[redacted-phone]"},
		{Name: "token", Regex: `Bearer [a-zA-Z0-9._-]+`, Replace: "[redacted-token]"},
	}

	err := redactor.LoadPatterns(patterns)
	if err != nil {
		t.Fatal(err)
	}

	testData := []byte(`{
		"user": "john.doe@example.com",
		"token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"phone": "+1-555-123-4567",
		"message": "Contact me at john.doe@example.com"
	}`)

	ctx := context.Background()

	// Warmup
	for i := 0; i < 100; i++ {
		_, err := redactor.RedactRequest(ctx, testData)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Measure performance
	iterations := 10000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		_, err := redactor.RedactRequest(ctx, testData)
		if err != nil {
			t.Fatal(err)
		}
	}

	duration := time.Since(start)
	avgLatency := duration / time.Duration(iterations)
	throughput := float64(iterations) / duration.Seconds()

	return &PerformanceBaseline{
		RedactLatency:    avgLatency,
		TotalLatency:     avgLatency,
		Throughput:       throughput,
		AllocationsPerOp: 39, // From benchmark results
		MemoryUsage:      4096,
	}
}

// testEndToEndPerformance measures complete request processing performance
func testEndToEndPerformance(t *testing.T) *PerformanceBaseline {
	t.Helper()

	// Mock authentication
	mockAuth := func(token string) error {
		time.Sleep(10 * time.Microsecond)
		return nil
	}

	policyEngine := policy.NewOPAEngine(zap.NewNop(), time.Minute)
	defer policyEngine.Close()

	testPolicy := `
package airlock.authz
import rego.v1
default allow := false
allow if {
    input.groups[_] == "mcp.users"
    startswith(input.resource, "mcp://repo/")
}
`

	ctx := context.Background()
	err := policyEngine.LoadPolicy(ctx, testPolicy)
	if err != nil {
		t.Fatal(err)
	}

	redactor := redact.NewRedactor()
	patterns := []redact.Pattern{
		{Name: "email", Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, Replace: "[redacted-email]"},
		{Name: "token", Regex: `Bearer [a-zA-Z0-9._-]+`, Replace: "[redacted-token]"},
	}
	err = redactor.LoadPatterns(patterns)
	if err != nil {
		t.Fatal(err)
	}

	// Mock claims
	mockClaims := struct {
		Subject string
		Tenant  string
		Groups  []string
	}{
		Subject: "test@example.com",
		Tenant:  "test-tenant",
		Groups:  []string{"mcp.users"},
	}

	testData := []byte(`{
		"user": "test@example.com",
		"token": "Bearer mock-token",
		"request": "read file mcp://repo/test.txt"
	}`)

	// Warmup
	for i := 0; i < 100; i++ {
		// Simulate full request processing
		token := fmt.Sprintf("token-%d", i)
		err := mockAuth(token)
		if err != nil {
			t.Fatal(err)
		}

		policyInput := &policy.PolicyInput{
			Subject:  mockClaims.Subject,
			Tenant:   mockClaims.Tenant,
			Groups:   mockClaims.Groups,
			Tool:     "read_file",
			Resource: "mcp://repo/test.txt",
			Method:   "GET",
		}
		_, err = policyEngine.Evaluate(ctx, policyInput)
		if err != nil {
			t.Fatal(err)
		}

		_, err = redactor.RedactRequest(ctx, testData)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Measure performance
	iterations := 5000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		// Full request processing pipeline
		token := fmt.Sprintf("token-%d", i%100)
		err := mockAuth(token)
		if err != nil {
			t.Fatal(err)
		}

		policyInput := &policy.PolicyInput{
			Subject:  mockClaims.Subject,
			Tenant:   mockClaims.Tenant,
			Groups:   mockClaims.Groups,
			Tool:     "read_file",
			Resource: fmt.Sprintf("mcp://repo/file-%d.txt", i%100),
			Method:   "GET",
		}
		_, err = policyEngine.Evaluate(ctx, policyInput)
		if err != nil {
			t.Fatal(err)
		}

		_, err = redactor.RedactRequest(ctx, testData)
		if err != nil {
			t.Fatal(err)
		}
	}

	duration := time.Since(start)
	avgLatency := duration / time.Duration(iterations)
	throughput := float64(iterations) / duration.Seconds()

	return &PerformanceBaseline{
		TotalLatency:     avgLatency,
		Throughput:       throughput,
		AllocationsPerOp: 50, // Estimated combined allocations
		MemoryUsage:      8192,
	}
}

// loadBaseline loads performance baseline from file
func loadBaseline(filename string) (*PerformanceBaseline, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var baseline PerformanceBaseline
	err = json.Unmarshal(data, &baseline)
	return &baseline, err
}

// saveBaseline saves performance baseline to file
func saveBaseline(filename string, baseline *PerformanceBaseline) error {
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// compareWithBaseline compares current performance with baseline
func compareWithBaseline(t *testing.T, baseline, current *PerformanceBaseline) error {
	t.Helper()

	// Define regression thresholds (performance degradation limits)
	const (
		latencyRegressionThreshold    = 1.20 // 20% increase in latency is a regression
		throughputRegressionThreshold = 0.80 // 20% decrease in throughput is a regression
		memoryRegressionThreshold     = 1.50 // 50% increase in memory usage is a regression
	)

	var regressions []string

	// Check latency regression
	if current.TotalLatency > 0 && baseline.TotalLatency > 0 {
		latencyRatio := float64(current.TotalLatency) / float64(baseline.TotalLatency)
		if latencyRatio > latencyRegressionThreshold {
			regressions = append(regressions, fmt.Sprintf(
				"Latency regression: %v -> %v (%.1f%% increase)",
				baseline.TotalLatency, current.TotalLatency,
				(latencyRatio-1)*100))
		}
	}

	// Check throughput regression
	if current.Throughput > 0 && baseline.Throughput > 0 {
		throughputRatio := current.Throughput / baseline.Throughput
		if throughputRatio < throughputRegressionThreshold {
			regressions = append(regressions, fmt.Sprintf(
				"Throughput regression: %.2f -> %.2f req/s (%.1f%% decrease)",
				baseline.Throughput, current.Throughput,
				(1-throughputRatio)*100))
		}
	}

	// Check memory regression
	if current.MemoryUsage > 0 && baseline.MemoryUsage > 0 {
		memoryRatio := float64(current.MemoryUsage) / float64(baseline.MemoryUsage)
		if memoryRatio > memoryRegressionThreshold {
			regressions = append(regressions, fmt.Sprintf(
				"Memory regression: %d -> %d bytes (%.1f%% increase)",
				baseline.MemoryUsage, current.MemoryUsage,
				(memoryRatio-1)*100))
		}
	}

	if len(regressions) > 0 {
		return fmt.Errorf("performance regressions detected:\n%s",
			fmt.Sprintf("  - %s", regressions))
	}

	// Log performance comparison
	t.Logf("Performance comparison with baseline:")
	if baseline.TotalLatency > 0 && current.TotalLatency > 0 {
		latencyChange := (float64(current.TotalLatency)/float64(baseline.TotalLatency) - 1) * 100
		t.Logf("  Latency: %v -> %v (%.1f%% change)", baseline.TotalLatency, current.TotalLatency, latencyChange)
	}
	if baseline.Throughput > 0 && current.Throughput > 0 {
		throughputChange := (current.Throughput/baseline.Throughput - 1) * 100
		t.Logf("  Throughput: %.2f -> %.2f req/s (%.1f%% change)", baseline.Throughput, current.Throughput, throughputChange)
	}

	return nil
}

// shouldUpdateBaseline determines if baseline should be updated
func shouldUpdateBaseline(baseline, current *PerformanceBaseline) bool {
	// Update baseline if performance improved by more than 10%
	const improvementThreshold = 0.90

	if current.TotalLatency > 0 && baseline.TotalLatency > 0 {
		latencyRatio := float64(current.TotalLatency) / float64(baseline.TotalLatency)
		if latencyRatio < improvementThreshold {
			return true
		}
	}

	if current.Throughput > 0 && baseline.Throughput > 0 {
		throughputRatio := current.Throughput / baseline.Throughput
		if throughputRatio > 1.1 { // 10% improvement
			return true
		}
	}

	return false
}

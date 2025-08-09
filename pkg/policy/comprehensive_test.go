package policy

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// Golden test cases for policy decisions
var goldenTestCases = []struct {
	name     string
	input    *PolicyInput
	expected *PolicyDecision
}{
	{
		name: "allow_read_file_for_mcp_users",
		input: &PolicyInput{
			Subject:  "user@example.com",
			Tenant:   "tenant-1",
			Groups:   []string{"mcp.users"},
			Tool:     "read_file",
			Resource: "mcp://repo/README.md",
			Method:   "GET",
		},
		expected: &PolicyDecision{
			Allow:  true,
			Reason: "policy allowed request",
			RuleID: "airlock.authz.allow",
		},
	},
	{
		name: "deny_write_file_for_mcp_users",
		input: &PolicyInput{
			Subject:  "user@example.com",
			Tenant:   "tenant-1",
			Groups:   []string{"mcp.users"},
			Tool:     "write_file",
			Resource: "mcp://repo/test.txt",
			Method:   "POST",
		},
		expected: &PolicyDecision{
			Allow:  false,
			Reason: "policy denied request",
			RuleID: "airlock.authz.default_deny",
		},
	},
	{
		name: "allow_write_file_for_mcp_admins",
		input: &PolicyInput{
			Subject:  "admin@example.com",
			Tenant:   "tenant-1",
			Groups:   []string{"mcp.admins"},
			Tool:     "write_file",
			Resource: "mcp://artifacts/data.json",
			Method:   "POST",
		},
		expected: &PolicyDecision{
			Allow:  true,
			Reason: "policy allowed request",
			RuleID: "airlock.authz.allow",
		},
	},
	{
		name: "deny_path_traversal_attack",
		input: &PolicyInput{
			Subject:  "user@example.com",
			Tenant:   "tenant-1",
			Groups:   []string{"mcp.users"},
			Tool:     "read_file",
			Resource: "mcp://repo/../etc/passwd",
			Method:   "GET",
		},
		expected: &PolicyDecision{
			Allow:  false,
			Reason: "policy denied request",
			RuleID: "airlock.authz.default_deny",
		},
	},
	{
		name: "deny_no_groups",
		input: &PolicyInput{
			Subject:  "user@example.com",
			Tenant:   "tenant-1",
			Groups:   []string{},
			Tool:     "read_file",
			Resource: "mcp://repo/README.md",
			Method:   "GET",
		},
		expected: &PolicyDecision{
			Allow:  false,
			Reason: "policy denied request",
			RuleID: "airlock.authz.default_deny",
		},
	},
}

// TestGoldenPolicyDecisions runs golden tests for policy decisions
func TestGoldenPolicyDecisions(t *testing.T) {
	logger := zaptest.NewLogger(t)

	for _, tc := range goldenTestCases {
		t.Run(tc.name, func(t *testing.T) {
			engine := NewOPAEngine(logger, time.Minute)
			defer engine.Close()

			// Load policy
			err := engine.LoadPolicy(context.Background(), testPolicy)
			if err != nil {
				t.Fatalf("failed to load policy: %v", err)
			}

			// Evaluate policy
			decision, err := engine.Evaluate(context.Background(), tc.input)
			if err != nil {
				t.Fatalf("policy evaluation failed: %v", err)
			}

			// Compare results
			if decision.Allow != tc.expected.Allow {
				t.Errorf("expected allow=%v, got allow=%v", tc.expected.Allow, decision.Allow)
			}

			if decision.Reason != tc.expected.Reason {
				t.Errorf("expected reason=%q, got reason=%q", tc.expected.Reason, decision.Reason)
			}

			if decision.RuleID != tc.expected.RuleID {
				t.Errorf("expected rule_id=%q, got rule_id=%q", tc.expected.RuleID, decision.RuleID)
			}
		})
	}
}

// generateRandomPolicyInput creates random policy inputs for testing
func generateRandomPolicyInput() *PolicyInput {
	subjects := []string{"user@example.com", "admin@example.com", "test@example.com"}
	tenants := []string{"tenant-1", "tenant-2", "org-1"}
	groupSets := [][]string{
		{"mcp.users"},
		{"mcp.admins"},
		{"mcp.users", "mcp.power_users"},
		{},
	}
	tools := []string{"read_file", "write_file", "list_directory", "search_docs", "delete_file"}
	resources := []string{
		"mcp://repo/README.md",
		"mcp://repo/src/main.go",
		"mcp://artifacts/data.json",
		"mcp://repo/../etc/passwd",
		"file:///etc/passwd",
	}
	methods := []string{"GET", "POST", "PUT", "DELETE"}

	return &PolicyInput{
		Subject:  subjects[rand.Intn(len(subjects))],
		Tenant:   tenants[rand.Intn(len(tenants))],
		Groups:   groupSets[rand.Intn(len(groupSets))],
		Tool:     tools[rand.Intn(len(tools))],
		Resource: resources[rand.Intn(len(resources))],
		Method:   methods[rand.Intn(len(methods))],
		Headers:  make(map[string]string),
	}
}

// TestPolicyEvaluationProperties tests policy evaluation properties
func TestPolicyEvaluationProperties(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load test policy
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	// Test 100 random inputs
	for i := 0; i < 100; i++ {
		input := generateRandomPolicyInput()

		// Property: Policy evaluation should always return a decision
		decision, err := engine.Evaluate(context.Background(), input)
		if err != nil {
			t.Errorf("iteration %d: policy evaluation failed: %v", i, err)
			continue
		}

		if decision == nil {
			t.Errorf("iteration %d: decision should not be nil", i)
			continue
		}

		if decision.RuleID == "" {
			t.Errorf("iteration %d: rule_id should not be empty", i)
		}

		// Property: Same input should always produce same decision (deterministic)
		decision2, err2 := engine.Evaluate(context.Background(), input)
		if err2 != nil {
			t.Errorf("iteration %d: second evaluation failed: %v", i, err2)
			continue
		}

		if decision.Allow != decision2.Allow ||
			decision.Reason != decision2.Reason ||
			decision.RuleID != decision2.RuleID {
			t.Errorf("iteration %d: policy evaluation is not deterministic", i)
		}
	}

	// Property: Invalid resources should be denied
	invalidResources := []string{
		"../etc/passwd",
		"file:///etc/passwd",
		"http://evil.com/data",
		"mcp://repo/../../../etc/passwd",
	}

	for _, resource := range invalidResources {
		input := &PolicyInput{
			Subject:  "user@example.com",
			Tenant:   "tenant-1",
			Groups:   []string{"mcp.users"},
			Tool:     "read_file",
			Resource: resource,
			Method:   "GET",
			Headers:  make(map[string]string),
		}

		decision, err := engine.Evaluate(context.Background(), input)
		if err != nil {
			continue // Skip on error
		}

		// Invalid resources should be denied
		if decision.Allow {
			t.Errorf("invalid resource should be denied: %s", resource)
		}
	}
}

// Fuzzing tests for policy input validation (Go 1.18+ fuzzing)
func FuzzPolicyInputValidation(f *testing.F) {
	logger := zaptest.NewLogger(f)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load test policy
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		f.Fatalf("failed to load policy: %v", err)
	}

	// Seed corpus with known inputs
	f.Add("user@example.com", "tenant-1", "mcp.users", "read_file", "mcp://repo/README.md", "GET")
	f.Add("admin@example.com", "tenant-1", "mcp.admins", "write_file", "mcp://artifacts/data.json", "POST")
	f.Add("", "", "", "", "", "")
	f.Add("user", "tenant", "group", "tool", "../../../etc/passwd", "GET")

	f.Fuzz(func(t *testing.T, subject, tenant, group, tool, resource, method string) {
		input := &PolicyInput{
			Subject:  subject,
			Tenant:   tenant,
			Groups:   []string{group},
			Tool:     tool,
			Resource: resource,
			Method:   method,
			Headers:  make(map[string]string),
		}

		// Policy evaluation should never panic
		decision, err := engine.Evaluate(context.Background(), input)

		// Should either succeed or fail gracefully
		if err != nil {
			// Error is acceptable, but should not be a panic
			return
		}

		// If successful, decision should be valid
		if decision == nil {
			t.Error("decision should not be nil on successful evaluation")
		}

		if decision != nil {
			// Decision should have required fields
			if decision.RuleID == "" {
				t.Error("rule_id should not be empty")
			}

			if decision.Reason == "" {
				t.Error("reason should not be empty")
			}

			// Path traversal attempts should be denied
			if strings.Contains(resource, "..") || strings.Contains(resource, "/etc/") {
				if decision.Allow {
					t.Errorf("path traversal attempt should be denied: %s", resource)
				}
			}

			// Non-MCP schemes should be denied
			if strings.HasPrefix(resource, "file://") || strings.HasPrefix(resource, "http://") {
				if decision.Allow {
					t.Errorf("non-MCP scheme should be denied: %s", resource)
				}
			}
		}
	})
}

// Tenant isolation tests with sharded cache validation
func TestTenantIsolation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load test policy
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	// Test that different tenants get isolated cache entries
	input1 := &PolicyInput{
		Subject:  "user@example.com",
		Tenant:   "tenant-1",
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/README.md",
		Method:   "GET",
	}

	input2 := &PolicyInput{
		Subject:  "user@example.com",
		Tenant:   "tenant-2", // Different tenant
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/README.md",
		Method:   "GET",
	}

	// Evaluate for both tenants
	decision1, err := engine.Evaluate(context.Background(), input1)
	if err != nil {
		t.Fatalf("evaluation failed for tenant-1: %v", err)
	}

	decision2, err := engine.Evaluate(context.Background(), input2)
	if err != nil {
		t.Fatalf("evaluation failed for tenant-2: %v", err)
	}

	// Both should succeed (same policy)
	if !decision1.Allow || !decision2.Allow {
		t.Error("both tenants should be allowed")
	}

	// Test cache isolation by checking cache keys
	cache := engine.cache
	key1 := engine.generateCacheKey(input1)
	key2 := engine.generateCacheKey(input2)

	// Cache keys should be the same (same input except tenant)
	if key1 != key2 {
		t.Error("cache keys should be the same for same input")
	}

	// But cache entries should be tenant-isolated
	cached1, found1 := cache.Get("tenant-1", key1)
	cached2, found2 := cache.Get("tenant-2", key2)

	if !found1 || !found2 {
		t.Error("both cache entries should be found")
	}

	if cached1 == nil || cached2 == nil {
		t.Error("cached decisions should not be nil")
	}

	// Test shard isolation
	shard1Key := cache.getShardKey("tenant-1", key1)
	shard2Key := cache.getShardKey("tenant-2", key2)

	if shard1Key == shard2Key {
		t.Error("shard keys should be different for different tenants")
	}
}

// Performance benchmarks targeting sub-millisecond policy evaluation
func BenchmarkPolicyEvaluation_SubMillisecond(b *testing.B) {
	logger := zaptest.NewLogger(b)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load test policy
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		b.Fatalf("failed to load policy: %v", err)
	}

	input := &PolicyInput{
		Subject:  "user@example.com",
		Tenant:   "tenant-1",
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/README.md",
		Method:   "GET",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		decision, err := engine.Evaluate(context.Background(), input)
		if err != nil {
			b.Fatal(err)
		}
		if decision == nil {
			b.Fatal("decision should not be nil")
		}
	}

	// Check that we're meeting sub-millisecond target
	elapsed := b.Elapsed()
	avgNs := elapsed.Nanoseconds() / int64(b.N)

	if avgNs > 1000000 { // 1ms in nanoseconds
		b.Errorf("Average evaluation time %dns exceeds 1ms target", avgNs)
	}
}

func BenchmarkPolicyEvaluation_ConcurrentTenants(b *testing.B) {
	logger := zaptest.NewLogger(b)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load test policy
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		b.Fatalf("failed to load policy: %v", err)
	}

	// Create inputs for different tenants
	inputs := make([]*PolicyInput, 10)
	for i := 0; i < 10; i++ {
		inputs[i] = &PolicyInput{
			Subject:  fmt.Sprintf("user%d@example.com", i),
			Tenant:   fmt.Sprintf("tenant-%d", i),
			Groups:   []string{"mcp.users"},
			Tool:     "read_file",
			Resource: "mcp://repo/README.md",
			Method:   "GET",
		}
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			input := inputs[i%len(inputs)]
			decision, err := engine.Evaluate(context.Background(), input)
			if err != nil {
				b.Fatal(err)
			}
			if decision == nil {
				b.Fatal("decision should not be nil")
			}
			i++
		}
	})
}

func BenchmarkPolicyEvaluation_CacheEffectiveness(b *testing.B) {
	logger := zaptest.NewLogger(b)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load test policy
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		b.Fatalf("failed to load policy: %v", err)
	}

	input := &PolicyInput{
		Subject:  "user@example.com",
		Tenant:   "tenant-1",
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/README.md",
		Method:   "GET",
	}

	// Prime the cache
	_, err = engine.Evaluate(context.Background(), input)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		decision, err := engine.Evaluate(context.Background(), input)
		if err != nil {
			b.Fatal(err)
		}
		if decision == nil {
			b.Fatal("decision should not be nil")
		}
	}
}

// TestPolicyEvaluationStress runs stress tests with many concurrent evaluations
func TestPolicyEvaluationStress(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load test policy
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	// Run 1000 concurrent evaluations
	const numGoroutines = 100
	const evaluationsPerGoroutine = 10

	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < evaluationsPerGoroutine; j++ {
				input := &PolicyInput{
					Subject:  fmt.Sprintf("user%d@example.com", goroutineID),
					Tenant:   fmt.Sprintf("tenant-%d", goroutineID%5), // 5 different tenants
					Groups:   []string{"mcp.users"},
					Tool:     "read_file",
					Resource: "mcp://repo/README.md",
					Method:   "GET",
				}

				decision, err := engine.Evaluate(context.Background(), input)
				if err != nil {
					errChan <- fmt.Errorf("goroutine %d, iteration %d: %v", goroutineID, j, err)
					return
				}

				if decision == nil {
					errChan <- fmt.Errorf("goroutine %d, iteration %d: decision is nil", goroutineID, j)
					return
				}

				if !decision.Allow {
					errChan <- fmt.Errorf("goroutine %d, iteration %d: expected allow=true", goroutineID, j)
					return
				}
			}
			errChan <- nil
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		if err := <-errChan; err != nil {
			t.Error(err)
		}
	}
}

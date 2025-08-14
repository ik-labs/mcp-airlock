package policy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"
)

// BenchmarkPolicyEvaluation benchmarks policy evaluation performance
func BenchmarkPolicyEvaluation(b *testing.B) {
	engine := setupBenchmarkEngine(b)
	defer engine.Close()

	ctx := context.Background()
	input := &PolicyInput{
		Subject:  "test@example.com",
		Tenant:   "test-tenant",
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/test.txt",
		Method:   "GET",
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := engine.Evaluate(ctx, input)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkPolicyEvaluationCached benchmarks cached policy evaluation
func BenchmarkPolicyEvaluationCached(b *testing.B) {
	engine := setupBenchmarkEngine(b)
	defer engine.Close()

	ctx := context.Background()
	input := &PolicyInput{
		Subject:  "test@example.com",
		Tenant:   "test-tenant",
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/test.txt",
		Method:   "GET",
	}

	// Warm up cache
	_, err := engine.Evaluate(ctx, input)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := engine.Evaluate(ctx, input)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkPolicyCache benchmarks the policy cache performance
func BenchmarkPolicyCache(b *testing.B) {
	cache := NewPolicyCache(5 * time.Minute)

	decision := &PolicyDecision{
		Allow:  true,
		Reason: "test decision",
		RuleID: "test.rule",
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Set", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("key-%d", i)
				cache.Set("test-tenant", key, decision)
				i++
			}
		})
	})

	b.Run("Get", func(b *testing.B) {
		// Pre-populate cache
		for i := 0; i < 1000; i++ {
			key := fmt.Sprintf("key-%d", i)
			cache.Set("test-tenant", key, decision)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("key-%d", i%1000)
				_, found := cache.Get("test-tenant", key)
				if !found {
					b.Fatal("expected cache hit")
				}
				i++
			}
		})
	})
}

// BenchmarkCacheKeyGeneration benchmarks cache key generation
func BenchmarkCacheKeyGeneration(b *testing.B) {
	engine := setupBenchmarkEngine(b)
	defer engine.Close()

	input := &PolicyInput{
		Subject:    "test@example.com",
		Tenant:     "test-tenant",
		Groups:     []string{"mcp.users", "mcp.developers"},
		Tool:       "read_file",
		Resource:   "mcp://repo/very/long/path/to/some/file.txt",
		Method:     "GET",
		VirtualURI: "mcp://repo/virtual/path",
		RealPath:   "/real/filesystem/path/to/file",
		RootType:   "fs",
		ReadOnly:   true,
		Operation:  "read",
		Headers: map[string]string{
			"Authorization": "Bearer token",
			"Content-Type":  "application/json",
			"User-Agent":    "test-client/1.0",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = engine.generateCacheKey(input)
		}
	})
}

// BenchmarkPolicyCompilation benchmarks policy compilation
func BenchmarkPolicyCompilation(b *testing.B) {
	engine := NewOPAEngine(zap.NewNop(), time.Minute)
	defer engine.Close()

	policy := `
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
    input.groups[_] == "mcp.users"
}

allowed_resource contains resource if {
    resource := input.resource
    startswith(resource, "mcp://repo/")
    not contains(resource, "../")
}
`

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := engine.LoadPolicy(ctx, policy)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConcurrentPolicyEvaluation benchmarks concurrent policy evaluation
func BenchmarkConcurrentPolicyEvaluation(b *testing.B) {
	engine := setupBenchmarkEngine(b)
	defer engine.Close()

	ctx := context.Background()

	// Test different concurrency levels
	concurrencyLevels := []int{1, 2, 4, 8, 16, 32}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Concurrency-%d", concurrency), func(b *testing.B) {
			b.SetParallelism(concurrency)
			b.ResetTimer()
			b.ReportAllocs()

			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					input := &PolicyInput{
						Subject:  fmt.Sprintf("user-%d@example.com", i%100),
						Tenant:   fmt.Sprintf("tenant-%d", i%10),
						Groups:   []string{"mcp.users"},
						Tool:     "read_file",
						Resource: fmt.Sprintf("mcp://repo/file-%d.txt", i%1000),
						Method:   "GET",
					}
					_, err := engine.Evaluate(ctx, input)
					if err != nil {
						b.Fatal(err)
					}
					i++
				}
			})
		})
	}
}

// BenchmarkDifferentPolicyInputs benchmarks evaluation with different input patterns
func BenchmarkDifferentPolicyInputs(b *testing.B) {
	engine := setupBenchmarkEngine(b)
	defer engine.Close()

	ctx := context.Background()

	testCases := []struct {
		name  string
		input *PolicyInput
	}{
		{
			name: "SimpleInput",
			input: &PolicyInput{
				Subject:  "test@example.com",
				Tenant:   "test-tenant",
				Groups:   []string{"mcp.users"},
				Tool:     "read_file",
				Resource: "mcp://repo/test.txt",
				Method:   "GET",
			},
		},
		{
			name: "ComplexInput",
			input: &PolicyInput{
				Subject:    "complex-user@example.com",
				Tenant:     "complex-tenant",
				Groups:     []string{"mcp.users", "mcp.developers", "mcp.admins"},
				Tool:       "complex_tool",
				Resource:   "mcp://repo/very/deep/nested/path/to/complex/resource.json",
				Method:     "POST",
				VirtualURI: "mcp://repo/virtual/complex/path",
				RealPath:   "/real/filesystem/complex/path/to/resource",
				RootType:   "s3",
				ReadOnly:   false,
				Operation:  "write",
				Headers: map[string]string{
					"Authorization":    "Bearer very-long-jwt-token-here",
					"Content-Type":     "application/json",
					"User-Agent":       "complex-client/2.0",
					"X-Correlation-ID": "complex-correlation-id-12345",
					"X-Tenant-ID":      "complex-tenant-identifier",
				},
			},
		},
		{
			name: "ManyGroups",
			input: &PolicyInput{
				Subject:  "multi-group@example.com",
				Tenant:   "multi-tenant",
				Groups:   []string{"group1", "group2", "group3", "group4", "group5", "group6", "group7", "group8", "group9", "group10"},
				Tool:     "multi_tool",
				Resource: "mcp://repo/multi.txt",
				Method:   "GET",
			},
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_, err := engine.Evaluate(ctx, tc.input)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	engine := setupBenchmarkEngine(b)
	defer engine.Close()

	ctx := context.Background()
	input := &PolicyInput{
		Subject:  "test@example.com",
		Tenant:   "test-tenant",
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/test.txt",
		Method:   "GET",
	}

	b.ResetTimer()
	b.ReportAllocs()

	// Measure memory allocations per operation
	for i := 0; i < b.N; i++ {
		_, err := engine.Evaluate(ctx, input)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// setupBenchmarkEngine creates a test policy engine for benchmarking
func setupBenchmarkEngine(b *testing.B) *OPAEngine {
	b.Helper()

	engine := NewOPAEngine(zap.NewNop(), time.Minute)

	policy := `
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
    tool in ["read_file", "list_directory", "search_docs", "complex_tool", "multi_tool"]
    input.groups[_] == "mcp.users"
}

allowed_resource contains resource if {
    resource := input.resource
    startswith(resource, "mcp://repo/")
    not contains(resource, "../")
}
`

	ctx := context.Background()
	err := engine.LoadPolicy(ctx, policy)
	if err != nil {
		b.Fatal(err)
	}

	return engine
}

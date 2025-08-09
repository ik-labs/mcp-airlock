package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// Test policy for basic allow/deny scenarios
const testPolicy = `
package airlock.authz

import rego.v1

# Default deny
default allow := false

# Allow if user has required group and tool is permitted
allow if {
    input.groups[_] == "mcp.users"
    input.tool in allowed_tools_for_users
    allowed_resource[input.resource]
}

allow if {
    input.groups[_] == "mcp.admins"
    input.tool in allowed_tools_for_admins
    allowed_resource[input.resource]
}

# Define allowed tools per group
allowed_tools_for_users := ["read_file", "list_directory", "search_docs"]
allowed_tools_for_admins := ["read_file", "write_file", "delete_file"]

# Define allowed resources with path restrictions
allowed_resource contains resource if {
    resource := input.resource
    startswith(resource, "mcp://repo/")
    not contains(resource, "../")
}

allowed_resource contains resource if {
    resource := input.resource
    startswith(resource, "mcp://artifacts/")
    input.groups[_] == "mcp.admins"
    not contains(resource, "../")
}
`

// Invalid policy for testing compilation errors
const invalidPolicy = `
package airlock.authz

# This policy has syntax errors
allow if {
    invalid_syntax_here ===
}
`

func TestOPAEngine_LoadPolicy(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	tests := []struct {
		name        string
		policy      string
		expectError bool
	}{
		{
			name:        "valid policy",
			policy:      testPolicy,
			expectError: false,
		},
		{
			name:        "invalid policy",
			policy:      invalidPolicy,
			expectError: true,
		},
		{
			name:        "empty policy",
			policy:      "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.LoadPolicy(context.Background(), tt.policy)
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestOPAEngine_Evaluate(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load test policy
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	tests := []struct {
		name     string
		input    *PolicyInput
		expected bool
		reason   string
	}{
		{
			name: "allow read_file for mcp.users",
			input: &PolicyInput{
				Subject:  "user@example.com",
				Tenant:   "tenant-1",
				Groups:   []string{"mcp.users"},
				Tool:     "read_file",
				Resource: "mcp://repo/README.md",
				Method:   "GET",
			},
			expected: true,
			reason:   "policy allowed request",
		},
		{
			name: "deny write_file for mcp.users",
			input: &PolicyInput{
				Subject:  "user@example.com",
				Tenant:   "tenant-1",
				Groups:   []string{"mcp.users"},
				Tool:     "write_file",
				Resource: "mcp://repo/test.txt",
				Method:   "POST",
			},
			expected: false,
			reason:   "policy denied request",
		},
		{
			name: "allow write_file for mcp.admins",
			input: &PolicyInput{
				Subject:  "admin@example.com",
				Tenant:   "tenant-1",
				Groups:   []string{"mcp.admins"},
				Tool:     "write_file",
				Resource: "mcp://artifacts/data.json",
				Method:   "POST",
			},
			expected: true,
			reason:   "policy allowed request",
		},
		{
			name: "deny path traversal",
			input: &PolicyInput{
				Subject:  "user@example.com",
				Tenant:   "tenant-1",
				Groups:   []string{"mcp.users"},
				Tool:     "read_file",
				Resource: "mcp://repo/../etc/passwd",
				Method:   "GET",
			},
			expected: false,
			reason:   "policy denied request",
		},
		{
			name: "deny no groups",
			input: &PolicyInput{
				Subject:  "user@example.com",
				Tenant:   "tenant-1",
				Groups:   []string{},
				Tool:     "read_file",
				Resource: "mcp://repo/README.md",
				Method:   "GET",
			},
			expected: false,
			reason:   "policy denied request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.Evaluate(context.Background(), tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if decision.Allow != tt.expected {
				t.Errorf("expected allow=%v, got allow=%v", tt.expected, decision.Allow)
			}

			if decision.Reason != tt.reason {
				t.Errorf("expected reason=%q, got reason=%q", tt.reason, decision.Reason)
			}

			if decision.RuleID == "" {
				t.Error("expected non-empty rule ID")
			}
		})
	}
}

func TestOPAEngine_LastKnownGood(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load valid policy first
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		t.Fatalf("failed to load initial policy: %v", err)
	}

	// Test that policy works
	input := &PolicyInput{
		Subject:  "user@example.com",
		Tenant:   "tenant-1",
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/README.md",
		Method:   "GET",
	}

	decision, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Allow {
		t.Error("expected policy to allow request")
	}

	// Try to load invalid policy - should fail but keep LKG
	err = engine.LoadPolicy(context.Background(), invalidPolicy)
	if err == nil {
		t.Error("expected error when loading invalid policy")
	}

	// Policy should still work using LKG
	decision, err = engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Allow {
		t.Error("expected LKG policy to allow request")
	}
}

func TestOPAEngine_NoPolicy(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Try to evaluate without loading any policy
	input := &PolicyInput{
		Subject:  "user@example.com",
		Tenant:   "tenant-1",
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/README.md",
		Method:   "GET",
	}

	decision, err := engine.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Allow {
		t.Error("expected policy to deny when no policy is loaded")
	}

	if decision.Reason != "no policy available" {
		t.Errorf("expected reason 'no policy available', got %q", decision.Reason)
	}

	if decision.RuleID != "system.no_policy" {
		t.Errorf("expected rule ID 'system.no_policy', got %q", decision.RuleID)
	}
}

func TestOPAEngine_ReloadPolicy(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load initial policy
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		t.Fatalf("failed to load initial policy: %v", err)
	}

	// Reload should work
	err = engine.ReloadPolicy(context.Background())
	if err != nil {
		t.Errorf("unexpected error during reload: %v", err)
	}

	// Test reload without initial policy
	engine2 := NewOPAEngine(logger, time.Minute)
	defer engine2.Close()

	err = engine2.ReloadPolicy(context.Background())
	if err == nil {
		t.Error("expected error when reloading without initial policy")
	}
	if !strings.Contains(err.Error(), "no policy source available") {
		t.Errorf("expected 'no policy source available' error, got: %v", err)
	}
}

func TestPolicyCache(t *testing.T) {
	cache := NewPolicyCache(100 * time.Millisecond)

	decision := &PolicyDecision{
		Allow:  true,
		Reason: "test decision",
		RuleID: "test.rule",
	}

	// Test cache miss
	result, found := cache.Get("tenant1", "key1")
	if found {
		t.Error("expected cache miss")
	}
	if result != nil {
		t.Error("expected nil result on cache miss")
	}

	// Test cache set and hit
	cache.Set("tenant1", "key1", decision)
	result, found = cache.Get("tenant1", "key1")
	if !found {
		t.Error("expected cache hit")
	}
	if result == nil {
		t.Fatal("expected non-nil result on cache hit")
	}
	if result.Allow != decision.Allow {
		t.Error("cached decision doesn't match original")
	}

	// Test tenant isolation
	result, found = cache.Get("tenant2", "key1")
	if found {
		t.Error("expected cache miss for different tenant")
	}

	// Test cache expiration
	time.Sleep(150 * time.Millisecond)
	result, found = cache.Get("tenant1", "key1")
	if found {
		t.Error("expected cache miss after expiration")
	}
}

func TestOPAEngine_CacheKey(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	input1 := &PolicyInput{
		Subject:  "user@example.com",
		Tenant:   "tenant-1",
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/README.md",
		Method:   "GET",
		Headers:  map[string]string{"Authorization": "Bearer token"},
	}

	input2 := &PolicyInput{
		Subject:  "user@example.com",
		Tenant:   "tenant-1",
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/README.md",
		Method:   "GET",
		Headers:  map[string]string{"Authorization": "Bearer token"},
	}

	input3 := &PolicyInput{
		Subject:  "user@example.com",
		Tenant:   "tenant-1",
		Groups:   []string{"mcp.users"},
		Tool:     "write_file", // Different tool
		Resource: "mcp://repo/README.md",
		Method:   "GET",
		Headers:  map[string]string{"Authorization": "Bearer token"},
	}

	key1 := engine.generateCacheKey(input1)
	key2 := engine.generateCacheKey(input2)
	key3 := engine.generateCacheKey(input3)

	if key1 != key2 {
		t.Error("identical inputs should generate same cache key")
	}

	if key1 == key3 {
		t.Error("different inputs should generate different cache keys")
	}

	if len(key1) != 16 {
		t.Errorf("expected cache key length 16, got %d", len(key1))
	}
}

func BenchmarkOPAEngine_Evaluate(b *testing.B) {
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
		_, err := engine.Evaluate(context.Background(), input)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOPAEngine_EvaluateWithCache(b *testing.B) {
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
		_, err := engine.Evaluate(context.Background(), input)
		if err != nil {
			b.Fatal(err)
		}
	}
}

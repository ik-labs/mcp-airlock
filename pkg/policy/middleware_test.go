package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestPolicyMiddleware_EvaluateRequest(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load test policy
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	middleware := NewPolicyMiddleware(engine, logger)

	tests := []struct {
		name        string
		reqCtx      *RequestContext
		expectAllow bool
		expectError bool
	}{
		{
			name: "allow read_file for mcp.users",
			reqCtx: &RequestContext{
				Subject:   "user@example.com",
				Tenant:    "tenant-1",
				Groups:    []string{"mcp.users"},
				Tool:      "read_file",
				Resource:  "mcp://repo/README.md",
				Method:    "GET",
				RequestID: "req-123",
				Timestamp: time.Now(),
				Headers:   map[string]string{"Authorization": "Bearer token"},
			},
			expectAllow: true,
			expectError: false,
		},
		{
			name: "deny write_file for mcp.users",
			reqCtx: &RequestContext{
				Subject:   "user@example.com",
				Tenant:    "tenant-1",
				Groups:    []string{"mcp.users"},
				Tool:      "write_file",
				Resource:  "mcp://repo/test.txt",
				Method:    "POST",
				RequestID: "req-124",
				Timestamp: time.Now(),
				Headers:   map[string]string{"Authorization": "Bearer token"},
			},
			expectAllow: false,
			expectError: false,
		},
		{
			name: "allow write_file for mcp.admins",
			reqCtx: &RequestContext{
				Subject:   "admin@example.com",
				Tenant:    "tenant-1",
				Groups:    []string{"mcp.admins"},
				Tool:      "write_file",
				Resource:  "mcp://artifacts/data.json",
				Method:    "POST",
				RequestID: "req-125",
				Timestamp: time.Now(),
				Headers:   map[string]string{"Authorization": "Bearer token"},
			},
			expectAllow: true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := middleware.EvaluateRequest(context.Background(), tt.reqCtx)

			if tt.expectError && result.Error == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && result.Error != nil {
				t.Errorf("unexpected error: %v", result.Error)
			}

			if result.Decision == nil {
				t.Fatal("expected decision but got nil")
			}

			if result.Decision.Allow != tt.expectAllow {
				t.Errorf("expected allow=%v, got allow=%v", tt.expectAllow, result.Decision.Allow)
			}

			if result.InputDigest == "" {
				t.Error("expected non-empty input digest")
			}

			if result.Duration <= 0 {
				t.Error("expected positive duration")
			}
		})
	}
}
func TestPolicyMiddleware_PolicyEngineFailure(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create engine but don't load any policy
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	middleware := NewPolicyMiddleware(engine, logger)

	reqCtx := &RequestContext{
		Subject:   "user@example.com",
		Tenant:    "tenant-1",
		Groups:    []string{"mcp.users"},
		Tool:      "read_file",
		Resource:  "mcp://repo/README.md",
		Method:    "GET",
		RequestID: "req-123",
		Timestamp: time.Now(),
		Headers:   map[string]string{"Authorization": "Bearer token"},
	}

	result := middleware.EvaluateRequest(context.Background(), reqCtx)

	// Should not error but should deny (fail-closed behavior)
	if result.Error != nil {
		t.Errorf("unexpected error: %v", result.Error)
	}

	if result.Decision == nil {
		t.Fatal("expected decision but got nil")
	}

	if result.Decision.Allow {
		t.Error("expected policy to deny when no policy is loaded (fail-closed)")
	}

	if result.Decision.Reason != "no policy available" {
		t.Errorf("expected reason 'no policy available', got %q", result.Decision.Reason)
	}
}

func TestPolicyMiddleware_CheckPolicyAvailable(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name        string
		setupEngine func() PolicyEngine
		expectError bool
	}{
		{
			name: "policy available",
			setupEngine: func() PolicyEngine {
				engine := NewOPAEngine(logger, time.Minute)
				err := engine.LoadPolicy(context.Background(), testPolicy)
				if err != nil {
					t.Fatalf("failed to load policy: %v", err)
				}
				return engine
			},
			expectError: false,
		},
		{
			name: "policy unavailable",
			setupEngine: func() PolicyEngine {
				return NewOPAEngine(logger, time.Minute)
			},
			expectError: false, // Should not error but will use system default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := tt.setupEngine()
			defer engine.Close()

			middleware := NewPolicyMiddleware(engine, logger)

			err := middleware.CheckPolicyAvailable(context.Background())

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestPolicyMiddleware_InputDigest(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	middleware := NewPolicyMiddleware(engine, logger)

	input1 := &PolicyInput{
		Subject:  "user@example.com",
		Tenant:   "tenant-1",
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/README.md",
		Method:   "GET",
		Headers:  map[string]string{"Authorization": "Bearer secret-token"},
	}

	input2 := &PolicyInput{
		Subject:  "user@example.com",
		Tenant:   "tenant-1",
		Groups:   []string{"mcp.users"},
		Tool:     "read_file",
		Resource: "mcp://repo/README.md",
		Method:   "GET",
		Headers:  map[string]string{"Authorization": "Bearer different-token"},
	}

	input3 := &PolicyInput{
		Subject:  "user@example.com",
		Tenant:   "tenant-1",
		Groups:   []string{"mcp.users"},
		Tool:     "write_file", // Different tool
		Resource: "mcp://repo/README.md",
		Method:   "GET",
		Headers:  map[string]string{"Authorization": "Bearer secret-token"},
	}

	digest1 := middleware.generateInputDigest(input1)
	digest2 := middleware.generateInputDigest(input2)
	digest3 := middleware.generateInputDigest(input3)

	// Same inputs with different header values should generate same digest
	// (we only hash header keys, not values, to avoid logging sensitive data)
	if digest1 != digest2 {
		t.Error("inputs with same structure but different header values should generate same digest")
	}

	// Different tools should generate different digests
	if digest1 == digest3 {
		t.Error("inputs with different tools should generate different digests")
	}

	if len(digest1) != 16 {
		t.Errorf("expected digest length 16, got %d", len(digest1))
	}

	// Ensure digest doesn't contain sensitive data
	if strings.Contains(digest1, "secret-token") {
		t.Error("digest should not contain sensitive header values")
	}
}

func BenchmarkPolicyMiddleware_EvaluateRequest(b *testing.B) {
	logger := zaptest.NewLogger(b)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load test policy
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		b.Fatalf("failed to load policy: %v", err)
	}

	middleware := NewPolicyMiddleware(engine, logger)

	reqCtx := &RequestContext{
		Subject:   "user@example.com",
		Tenant:    "tenant-1",
		Groups:    []string{"mcp.users"},
		Tool:      "read_file",
		Resource:  "mcp://repo/README.md",
		Method:    "GET",
		RequestID: "req-123",
		Timestamp: time.Now(),
		Headers:   map[string]string{"Authorization": "Bearer token"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := middleware.EvaluateRequest(context.Background(), reqCtx)
		if result.Error != nil {
			b.Fatal(result.Error)
		}
	}
}

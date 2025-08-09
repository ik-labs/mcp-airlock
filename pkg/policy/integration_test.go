package policy

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestPolicyIntegration_ProcessRequest(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	// Load test policy
	err := engine.LoadPolicy(context.Background(), testPolicy)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	middleware := NewPolicyMiddleware(engine, logger)
	integration := NewPolicyIntegration(middleware, logger)

	tests := []struct {
		name            string
		req             *MCPRequest
		auth            *AuthContext
		expectError     bool
		expectSuccess   bool
		expectedErrCode int
	}{
		{
			name: "allow read_file for mcp.users",
			req: &MCPRequest{
				ID:     "req-1",
				Method: "tools/call",
				Params: map[string]interface{}{
					"name": "read_file",
					"uri":  "mcp://repo/README.md",
				},
				Headers: map[string]string{"Authorization": "Bearer token"},
			},
			auth: &AuthContext{
				Subject: "user@example.com",
				Tenant:  "tenant-1",
				Groups:  []string{"mcp.users"},
			},
			expectError:   false,
			expectSuccess: true,
		},
		{
			name: "deny write_file for mcp.users",
			req: &MCPRequest{
				ID:     "req-2",
				Method: "tools/call",
				Params: map[string]interface{}{
					"name": "write_file",
					"uri":  "mcp://repo/test.txt",
				},
				Headers: map[string]string{"Authorization": "Bearer token"},
			},
			auth: &AuthContext{
				Subject: "user@example.com",
				Tenant:  "tenant-1",
				Groups:  []string{"mcp.users"},
			},
			expectError:     true,
			expectSuccess:   false,
			expectedErrCode: -32602,
		},
		{
			name: "allow write_file for mcp.admins",
			req: &MCPRequest{
				ID:     "req-3",
				Method: "tools/call",
				Params: map[string]interface{}{
					"name": "write_file",
					"uri":  "mcp://artifacts/data.json",
				},
				Headers: map[string]string{"Authorization": "Bearer token"},
			},
			auth: &AuthContext{
				Subject: "admin@example.com",
				Tenant:  "tenant-1",
				Groups:  []string{"mcp.admins"},
			},
			expectError:   false,
			expectSuccess: true,
		},
		{
			name: "deny path traversal",
			req: &MCPRequest{
				ID:     "req-4",
				Method: "tools/call",
				Params: map[string]interface{}{
					"name": "read_file",
					"uri":  "mcp://repo/../etc/passwd",
				},
				Headers: map[string]string{"Authorization": "Bearer token"},
			},
			auth: &AuthContext{
				Subject: "user@example.com",
				Tenant:  "tenant-1",
				Groups:  []string{"mcp.users"},
			},
			expectError:     true,
			expectSuccess:   false,
			expectedErrCode: -32602,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := integration.ProcessRequest(context.Background(), tt.req, tt.auth)

			if err != nil {
				t.Fatalf("unexpected processing error: %v", err)
			}

			if resp == nil {
				t.Fatal("expected response but got nil")
			}

			if tt.expectSuccess {
				if resp.Error != nil {
					t.Errorf("expected success but got error: %+v", resp.Error)
				}
				if resp.Result == nil {
					t.Error("expected result but got nil")
				}
			}

			if tt.expectError {
				if resp.Error == nil {
					t.Error("expected error but got none")
				} else {
					if resp.Error.Code != tt.expectedErrCode {
						t.Errorf("expected error code %d, got %d", tt.expectedErrCode, resp.Error.Code)
					}

					// Check that error contains required audit fields
					if resp.Error.Data == nil {
						t.Error("expected error data but got nil")
					} else {
						if _, ok := resp.Error.Data["correlation_id"]; !ok {
							t.Error("expected correlation_id in error data")
						}
						if _, ok := resp.Error.Data["rule_id"]; !ok && resp.Error.Code == -32602 {
							t.Error("expected rule_id in policy denial error data")
						}
					}
				}
			}
		})
	}
}

func TestPolicyIntegration_PolicyEngineFailure(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create engine but don't load any policy to simulate failure
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	middleware := NewPolicyMiddleware(engine, logger)
	integration := NewPolicyIntegration(middleware, logger)

	req := &MCPRequest{
		ID:     "req-fail",
		Method: "tools/call",
		Params: map[string]interface{}{
			"name": "read_file",
			"uri":  "mcp://repo/README.md",
		},
		Headers: map[string]string{"Authorization": "Bearer token"},
	}

	auth := &AuthContext{
		Subject: "user@example.com",
		Tenant:  "tenant-1",
		Groups:  []string{"mcp.users"},
	}

	resp, err := integration.ProcessRequest(context.Background(), req, auth)

	if err != nil {
		t.Fatalf("unexpected processing error: %v", err)
	}

	// Should fail-closed (deny request) when no policy is available
	if resp.Error == nil {
		t.Error("expected error due to no policy available (fail-closed behavior)")
	} else {
		if resp.Error.Code != -32602 {
			t.Errorf("expected error code -32602 (policy denial), got %d", resp.Error.Code)
		}

		if resp.Error.Data == nil {
			t.Error("expected error data but got nil")
		} else {
			if _, ok := resp.Error.Data["correlation_id"]; !ok {
				t.Error("expected correlation_id in error data")
			}
		}
	}
}

func TestPolicyIntegration_ExtractToolAndResource(t *testing.T) {
	logger := zaptest.NewLogger(t)
	engine := NewOPAEngine(logger, time.Minute)
	defer engine.Close()

	middleware := NewPolicyMiddleware(engine, logger)
	integration := NewPolicyIntegration(middleware, logger)

	tests := []struct {
		name             string
		req              *MCPRequest
		expectedTool     string
		expectedResource string
	}{
		{
			name: "tools/call with name and uri",
			req: &MCPRequest{
				Method: "tools/call",
				Params: map[string]interface{}{
					"name": "read_file",
					"uri":  "mcp://repo/README.md",
				},
			},
			expectedTool:     "read_file",
			expectedResource: "mcp://repo/README.md",
		},
		{
			name: "tools/call with name and path",
			req: &MCPRequest{
				Method: "tools/call",
				Params: map[string]interface{}{
					"name": "list_directory",
					"path": "/var/data",
				},
			},
			expectedTool:     "list_directory",
			expectedResource: "/var/data",
		},
		{
			name: "direct method call",
			req: &MCPRequest{
				Method: "read_file",
				Params: map[string]interface{}{
					"uri": "mcp://repo/test.txt",
				},
			},
			expectedTool:     "read_file",
			expectedResource: "mcp://repo/test.txt",
		},
		{
			name: "no resource params",
			req: &MCPRequest{
				Method: "health_check",
				Params: map[string]interface{}{},
			},
			expectedTool:     "health_check",
			expectedResource: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool, resource := integration.extractToolAndResource(tt.req)

			if tool != tt.expectedTool {
				t.Errorf("expected tool %q, got %q", tt.expectedTool, tool)
			}

			if resource != tt.expectedResource {
				t.Errorf("expected resource %q, got %q", tt.expectedResource, resource)
			}
		})
	}
}

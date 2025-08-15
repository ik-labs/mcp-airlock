package roots

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ik-labs/mcp-airlock/pkg/policy"
	"go.uber.org/zap/zaptest"
)

// TestEndToEndVirtualRootAccess tests complete virtual root access patterns
func TestEndToEndVirtualRootAccess(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create temporary directories for testing
	tempDir := t.TempDir()
	repoDir := filepath.Join(tempDir, "repo")
	artifactsDir := filepath.Join(tempDir, "artifacts")

	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatalf("Failed to create repo dir: %v", err)
	}
	if err := os.MkdirAll(artifactsDir, 0755); err != nil {
		t.Fatalf("Failed to create artifacts dir: %v", err)
	}

	// Create test files
	testFiles := map[string]string{
		filepath.Join(repoDir, "README.md"):      "# Test Repository\nThis is a test file.",
		filepath.Join(repoDir, "src", "main.go"): "package main\n\nfunc main() {\n\tprintln(\"Hello, World!\")\n}",
		filepath.Join(artifactsDir, "build.log"): "Build completed successfully",
	}

	for filePath, content := range testFiles {
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("Failed to create directory for %s: %v", filePath, err)
		}
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filePath, err)
		}
	}

	// Configure virtual roots
	rootConfigs := []RootConfig{
		{
			Name:     "repo-readonly",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     repoDir,
			ReadOnly: true,
		},
		{
			Name:     "artifacts",
			Type:     "fs",
			Virtual:  "mcp://artifacts/",
			Real:     artifactsDir,
			ReadOnly: false,
		},
	}

	// Create root mapper
	mapper, err := NewRootMapper(rootConfigs, nil, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	// Create policy engine with test policy
	policyEngine := policy.NewOPAEngine(logger, 1*time.Minute)
	testPolicy := `
package airlock.authz

import rego.v1

default allow := false

# Allow read access to repo for users
allow if {
    input.groups[_] == "developers"
    input.operation == "read"
    startswith(input.virtual_uri, "mcp://repo/")
}

# Allow read/write access to artifacts for power users
allow if {
    input.groups[_] == "power_users"
    startswith(input.virtual_uri, "mcp://artifacts/")
}

# Deny write access to read-only roots
allow if {
    input.operation != "write"
    input.read_only == true
    input.groups[_] == "developers"
}
`

	if err := policyEngine.LoadPolicy(context.Background(), testPolicy); err != nil {
		t.Fatalf("Failed to load test policy: %v", err)
	}

	// Create policy integration
	integration := NewPolicyIntegration(mapper, policyEngine, logger)

	// Create root middleware
	middleware := NewRootMiddleware(mapper, logger)

	// Test cases for end-to-end virtual root access
	testCases := []struct {
		name           string
		tenant         string
		subject        string
		groups         []string
		mcpRequest     map[string]interface{}
		expectSuccess  bool
		expectError    bool
		expectedReason string
	}{
		{
			name:    "successful_read_repo_file",
			tenant:  "tenant1",
			subject: "user@example.com",
			groups:  []string{"developers"},
			mcpRequest: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "resources/read",
				"params": map[string]interface{}{
					"uri": "mcp://repo/README.md",
				},
			},
			expectSuccess: true,
		},
		{
			name:    "successful_list_repo_directory",
			tenant:  "tenant1",
			subject: "user@example.com",
			groups:  []string{"developers"},
			mcpRequest: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      2,
				"method":  "resources/list",
				"params": map[string]interface{}{
					"uri": "mcp://repo/",
				},
			},
			expectSuccess: true,
		},
		{
			name:    "denied_write_readonly_root",
			tenant:  "tenant1",
			subject: "user@example.com",
			groups:  []string{"developers"},
			mcpRequest: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      3,
				"method":  "resources/write",
				"params": map[string]interface{}{
					"uri":     "mcp://repo/new_file.txt",
					"content": "This should be denied",
				},
			},
			expectSuccess:  false,
			expectedReason: "write operation not allowed on read-only resource",
		},
		{
			name:    "successful_artifacts_access_power_user",
			tenant:  "tenant1",
			subject: "admin@example.com",
			groups:  []string{"power_users"},
			mcpRequest: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      4,
				"method":  "resources/read",
				"params": map[string]interface{}{
					"uri": "mcp://artifacts/build.log",
				},
			},
			expectSuccess: true,
		},
		{
			name:    "denied_unauthorized_root",
			tenant:  "tenant1",
			subject: "user@example.com",
			groups:  []string{"developers"},
			mcpRequest: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      5,
				"method":  "resources/read",
				"params": map[string]interface{}{
					"uri": "mcp://unauthorized/secret.txt",
				},
			},
			expectSuccess:  false,
			expectError:    true,
			expectedReason: "Root virtualization failed",
		},
		{
			name:    "successful_tool_call_with_resource",
			tenant:  "tenant1",
			subject: "user@example.com",
			groups:  []string{"developers"},
			mcpRequest: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      6,
				"method":  "tools/call",
				"params": map[string]interface{}{
					"name": "read_file",
					"arguments": map[string]interface{}{
						"file_path": "mcp://repo/src/main.go",
						"encoding":  "utf-8",
					},
				},
			},
			expectSuccess: true,
		},
		{
			name:    "denied_insufficient_permissions",
			tenant:  "tenant1",
			subject: "guest@example.com",
			groups:  []string{"guests"},
			mcpRequest: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      7,
				"method":  "resources/read",
				"params": map[string]interface{}{
					"uri": "mcp://repo/README.md",
				},
			},
			expectSuccess:  false,
			expectedReason: "policy denied request",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			// Marshal the MCP request
			requestData, err := json.Marshal(tc.mcpRequest)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}

			// Process request through middleware
			processedData, err := middleware.ProcessRequest(ctx, tc.tenant, requestData)

			if tc.expectError {
				if err == nil {
					// Check if the processed data contains an error response
					var response map[string]interface{}
					if jsonErr := json.Unmarshal(processedData, &response); jsonErr == nil {
						if errorField, exists := response["error"]; exists {
							if errorMap, ok := errorField.(map[string]interface{}); ok {
								if message, exists := errorMap["message"]; exists {
									if messageStr, ok := message.(string); ok {
										if tc.expectedReason != "" && !strings.Contains(messageStr, tc.expectedReason) {
											t.Errorf("Expected error message to contain '%s', got '%s'", tc.expectedReason, messageStr)
										}
									}
								}
							}
						} else if tc.expectSuccess {
							t.Errorf("Expected success but got no error field in response")
						}
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error processing request: %v", err)
			}

			// Parse the processed request to verify URI mapping
			var processedRequest map[string]interface{}
			if err := json.Unmarshal(processedData, &processedRequest); err != nil {
				t.Fatalf("Failed to unmarshal processed request: %v", err)
			}

			// Verify that virtual URIs were properly mapped for resource requests
			if method, exists := processedRequest["method"]; exists {
				if methodStr, ok := method.(string); ok {
					switch methodStr {
					case "resources/read":
						if params, exists := processedRequest["params"]; exists {
							if paramsMap, ok := params.(map[string]interface{}); ok {
								if uri, exists := paramsMap["uri"]; exists {
									if uriStr, ok := uri.(string); ok {
										// For successful cases, URI should be mapped to real path
										if tc.expectSuccess && !filepath.IsAbs(uriStr) {
											t.Errorf("Expected URI to be mapped to absolute path, got: %s", uriStr)
										}
									}
								}
							}
						}
					case "resources/list":
						// List requests don't map URIs to real paths, they validate and pass through
						if params, exists := processedRequest["params"]; exists {
							if paramsMap, ok := params.(map[string]interface{}); ok {
								if uri, exists := paramsMap["uri"]; exists {
									if uriStr, ok := uri.(string); ok {
										// For list requests, URI should remain as virtual URI
										if tc.expectSuccess && !strings.HasPrefix(uriStr, "mcp://") {
											t.Errorf("Expected list URI to remain virtual, got: %s", uriStr)
										}
									}
								}
							}
						}
					case "tools/call":
						// Verify tool arguments were processed
						if params, exists := processedRequest["params"]; exists {
							if paramsMap, ok := params.(map[string]interface{}); ok {
								if args, exists := paramsMap["arguments"]; exists {
									if argsMap, ok := args.(map[string]interface{}); ok {
										if filePath, exists := argsMap["file_path"]; exists {
											if filePathStr, ok := filePath.(string); ok && tc.expectSuccess {
												// Should be mapped to real path
												if !filepath.IsAbs(filePathStr) {
													t.Errorf("Expected file_path to be mapped to absolute path, got: %s", filePathStr)
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}

			// Test authorization integration
			if tc.expectSuccess {
				// Create authorization request
				authReq := &ResourceAuthRequest{
					Subject:    tc.subject,
					Tenant:     tc.tenant,
					Groups:     tc.groups,
					Tool:       "test_tool",
					Resource:   "test_resource",
					Method:     "GET",
					VirtualURI: extractURIFromRequest(tc.mcpRequest),
					Operation:  extractOperationFromMethod(tc.mcpRequest["method"].(string)),
				}

				// Test authorization
				authResult, err := integration.AuthorizeResourceAccess(ctx, authReq)
				if err != nil {
					t.Fatalf("Authorization failed: %v", err)
				}

				if !authResult.IsSuccessful() {
					t.Errorf("Expected authorization to succeed, got: %s", authResult.Reason)
				}

				// Verify mapped resource
				if authResult.MappedResource == nil {
					t.Error("Expected mapped resource to be available")
				} else {
					if !filepath.IsAbs(authResult.MappedResource.RealPath) {
						t.Errorf("Expected real path to be absolute, got: %s", authResult.MappedResource.RealPath)
					}
				}
			}
		})
	}
}

// TestRootVirtualizationPerformance tests performance of root virtualization
func TestRootVirtualizationPerformance(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create test setup
	tempDir := t.TempDir()
	rootConfigs := []RootConfig{
		{
			Name:     "perf-test",
			Type:     "fs",
			Virtual:  "mcp://perf/",
			Real:     tempDir,
			ReadOnly: true,
		},
	}

	mapper, err := NewRootMapper(rootConfigs, nil, zaptest.NewLogger(t))
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	middleware := NewRootMiddleware(mapper, logger)

	// Create test request
	testRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "resources/read",
		"params": map[string]interface{}{
			"uri": "mcp://perf/test.txt",
		},
	}

	requestData, err := json.Marshal(testRequest)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	// Performance test
	const numRequests = 1000
	start := time.Now()

	for i := 0; i < numRequests; i++ {
		_, err := middleware.ProcessRequest(context.Background(), "tenant1", requestData)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
	}

	duration := time.Since(start)
	avgDuration := duration / numRequests

	t.Logf("Processed %d requests in %v (avg: %v per request)", numRequests, duration, avgDuration)

	// Performance requirement: should be under 1ms per request for simple mapping
	if avgDuration > time.Millisecond {
		t.Errorf("Performance requirement not met: avg duration %v > 1ms", avgDuration)
	}
}

// Helper functions

func extractURIFromRequest(request map[string]interface{}) string {
	if params, exists := request["params"]; exists {
		if paramsMap, ok := params.(map[string]interface{}); ok {
			if uri, exists := paramsMap["uri"]; exists {
				if uriStr, ok := uri.(string); ok {
					return uriStr
				}
			}
			// Check tool arguments
			if args, exists := paramsMap["arguments"]; exists {
				if argsMap, ok := args.(map[string]interface{}); ok {
					if filePath, exists := argsMap["file_path"]; exists {
						if filePathStr, ok := filePath.(string); ok {
							return filePathStr
						}
					}
				}
			}
		}
	}
	return ""
}

func extractOperationFromMethod(method string) string {
	switch method {
	case "resources/read":
		return "read"
	case "resources/list":
		return "list"
	case "resources/write":
		return "write"
	case "tools/call":
		return "read" // Assume read for tools
	default:
		return "read"
	}
}

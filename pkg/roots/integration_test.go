package roots

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ik-labs/mcp-airlock/pkg/policy"
	"go.uber.org/zap/zaptest"
)

// containsString checks if a string contains a substring
func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestPolicyIntegration_AuthorizeResourceAccess(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create temporary directory for testing
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Configure root mapper
	rootConfigs := []RootConfig{
		{
			Name:     "repo-readonly",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     tempDir,
			ReadOnly: true,
		},
		{
			Name:     "artifacts",
			Type:     "fs",
			Virtual:  "mcp://artifacts/",
			Real:     tempDir,
			ReadOnly: false,
		},
	}

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

# Allow read access to repo for developers
allow if {
    input.groups[_] == "developers"
    input.operation == "read"
    startswith(input.virtual_uri, "mcp://repo/")
}

# Allow write access to artifacts for power users
allow if {
    input.groups[_] == "power_users"
    startswith(input.virtual_uri, "mcp://artifacts/")
}

# Deny write to read-only resources
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

	tests := []struct {
		name           string
		request        *ResourceAuthRequest
		expectAllowed  bool
		expectError    bool
		expectedReason string
	}{
		{
			name: "successful_read_access",
			request: &ResourceAuthRequest{
				Subject:    "user@example.com",
				Tenant:     "tenant1",
				Groups:     []string{"developers"},
				Tool:       "read_file",
				Resource:   "test_resource",
				Method:     "GET",
				VirtualURI: "mcp://repo/test.txt",
				Operation:  "read",
			},
			expectAllowed: true,
		},
		{
			name: "denied_write_to_readonly",
			request: &ResourceAuthRequest{
				Subject:    "user@example.com",
				Tenant:     "tenant1",
				Groups:     []string{"developers"},
				Tool:       "write_file",
				Resource:   "test_resource",
				Method:     "POST",
				VirtualURI: "mcp://repo/test.txt",
				Operation:  "write",
			},
			expectAllowed:  false,
			expectedReason: "Access validation failed",
		},
		{
			name: "successful_write_to_artifacts",
			request: &ResourceAuthRequest{
				Subject:    "admin@example.com",
				Tenant:     "tenant1",
				Groups:     []string{"power_users"},
				Tool:       "write_file",
				Resource:   "test_resource",
				Method:     "POST",
				VirtualURI: "mcp://artifacts/build.log",
				Operation:  "write",
			},
			expectAllowed: true,
		},
		{
			name: "denied_insufficient_permissions",
			request: &ResourceAuthRequest{
				Subject:    "guest@example.com",
				Tenant:     "tenant1",
				Groups:     []string{"guests"},
				Tool:       "read_file",
				Resource:   "test_resource",
				Method:     "GET",
				VirtualURI: "mcp://repo/test.txt",
				Operation:  "read",
			},
			expectAllowed:  false,
			expectedReason: "policy denied request",
		},
		{
			name: "mapping_error_unauthorized_uri",
			request: &ResourceAuthRequest{
				Subject:    "user@example.com",
				Tenant:     "tenant1",
				Groups:     []string{"developers"},
				Tool:       "read_file",
				Resource:   "test_resource",
				Method:     "GET",
				VirtualURI: "mcp://unauthorized/secret.txt",
				Operation:  "read",
			},
			expectAllowed:  false,
			expectedReason: "Resource mapping failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			result, err := integration.AuthorizeResourceAccess(ctx, tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Allowed != tt.expectAllowed {
				t.Errorf("Expected allowed=%v, got allowed=%v (reason: %s)",
					tt.expectAllowed, result.Allowed, result.Reason)
			}

			if tt.expectedReason != "" {
				if !containsString(result.Reason, tt.expectedReason) {
					t.Errorf("Expected reason to contain '%s', got '%s'",
						tt.expectedReason, result.Reason)
				}
			}

			// Verify performance metrics
			if result.Duration <= 0 {
				t.Error("Expected duration to be recorded")
			}

			// For successful authorizations, verify mapped resource
			if result.Allowed && result.IsSuccessful() {
				if result.MappedResource == nil {
					t.Error("Expected mapped resource for successful authorization")
				} else {
					if !filepath.IsAbs(result.MappedResource.RealPath) {
						t.Errorf("Expected absolute real path, got: %s", result.MappedResource.RealPath)
					}
				}

				if result.PolicyDecision == nil {
					t.Error("Expected policy decision for successful authorization")
				}
			}
		})
	}
}

func TestValidateResourceRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     *ResourceAuthRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid_request",
			request: &ResourceAuthRequest{
				Subject:    "user@example.com",
				Tenant:     "tenant1",
				Groups:     []string{"developers"},
				VirtualURI: "mcp://repo/test.txt",
				Operation:  "read",
			},
			expectError: false,
		},
		{
			name: "missing_subject",
			request: &ResourceAuthRequest{
				Tenant:     "tenant1",
				Groups:     []string{"developers"},
				VirtualURI: "mcp://repo/test.txt",
				Operation:  "read",
			},
			expectError: true,
			errorMsg:    "subject is required",
		},
		{
			name: "missing_tenant",
			request: &ResourceAuthRequest{
				Subject:    "user@example.com",
				Groups:     []string{"developers"},
				VirtualURI: "mcp://repo/test.txt",
				Operation:  "read",
			},
			expectError: true,
			errorMsg:    "tenant is required",
		},
		{
			name: "missing_virtual_uri",
			request: &ResourceAuthRequest{
				Subject:   "user@example.com",
				Tenant:    "tenant1",
				Groups:    []string{"developers"},
				Operation: "read",
			},
			expectError: true,
			errorMsg:    "virtual URI is required",
		},
		{
			name: "missing_operation",
			request: &ResourceAuthRequest{
				Subject:    "user@example.com",
				Tenant:     "tenant1",
				Groups:     []string{"developers"},
				VirtualURI: "mcp://repo/test.txt",
			},
			expectError: true,
			errorMsg:    "operation is required",
		},
		{
			name: "invalid_operation",
			request: &ResourceAuthRequest{
				Subject:    "user@example.com",
				Tenant:     "tenant1",
				Groups:     []string{"developers"},
				VirtualURI: "mcp://repo/test.txt",
				Operation:  "invalid_op",
			},
			expectError: true,
			errorMsg:    "invalid operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateResourceRequest(tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'",
						tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCreatePolicyInputFromResource(t *testing.T) {
	request := &ResourceAuthRequest{
		Subject:    "user@example.com",
		Tenant:     "tenant1",
		Groups:     []string{"developers", "users"},
		Tool:       "read_file",
		Resource:   "test_resource",
		Method:     "GET",
		Headers:    map[string]string{"Authorization": "Bearer token"},
		VirtualURI: "mcp://repo/test.txt",
		Operation:  "read",
	}

	resource := &MappedResource{
		VirtualURI: "mcp://repo/test.txt",
		RealPath:   "/tmp/repo/test.txt",
		Type:       "fs",
		ReadOnly:   true,
	}

	policyInput := CreatePolicyInputFromResource(request, resource)

	// Verify all fields are correctly mapped
	if policyInput.Subject != request.Subject {
		t.Errorf("Expected subject %s, got %s", request.Subject, policyInput.Subject)
	}

	if policyInput.Tenant != request.Tenant {
		t.Errorf("Expected tenant %s, got %s", request.Tenant, policyInput.Tenant)
	}

	if len(policyInput.Groups) != len(request.Groups) {
		t.Errorf("Expected %d groups, got %d", len(request.Groups), len(policyInput.Groups))
	}

	if policyInput.VirtualURI != request.VirtualURI {
		t.Errorf("Expected virtual URI %s, got %s", request.VirtualURI, policyInput.VirtualURI)
	}

	if policyInput.RealPath != resource.RealPath {
		t.Errorf("Expected real path %s, got %s", resource.RealPath, policyInput.RealPath)
	}

	if policyInput.RootType != resource.Type {
		t.Errorf("Expected root type %s, got %s", resource.Type, policyInput.RootType)
	}

	if policyInput.ReadOnly != resource.ReadOnly {
		t.Errorf("Expected read only %v, got %v", resource.ReadOnly, policyInput.ReadOnly)
	}

	if policyInput.Operation != request.Operation {
		t.Errorf("Expected operation %s, got %s", request.Operation, policyInput.Operation)
	}
}

func TestResourceAuthResult_IsSuccessful(t *testing.T) {
	tests := []struct {
		name     string
		result   *ResourceAuthResult
		expected bool
	}{
		{
			name: "successful_result",
			result: &ResourceAuthResult{
				Allowed: true,
			},
			expected: true,
		},
		{
			name: "denied_result",
			result: &ResourceAuthResult{
				Allowed: false,
				Reason:  "Access denied",
			},
			expected: false,
		},
		{
			name: "mapping_error",
			result: &ResourceAuthResult{
				Allowed:      true,
				MappingError: fmt.Errorf("mapping failed"),
			},
			expected: false,
		},
		{
			name: "access_error",
			result: &ResourceAuthResult{
				Allowed:     true,
				AccessError: fmt.Errorf("access denied"),
			},
			expected: false,
		},
		{
			name: "policy_error",
			result: &ResourceAuthResult{
				Allowed:     true,
				PolicyError: fmt.Errorf("policy failed"),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.result.IsSuccessful()
			if result != tt.expected {
				t.Errorf("Expected IsSuccessful()=%v, got %v", tt.expected, result)
			}
		})
	}
}

func TestResourceAuthResult_GetPrimaryError(t *testing.T) {
	tests := []struct {
		name          string
		result        *ResourceAuthResult
		expectError   bool
		expectedError string
	}{
		{
			name: "no_error",
			result: &ResourceAuthResult{
				Allowed: true,
			},
			expectError: false,
		},
		{
			name: "mapping_error_priority",
			result: &ResourceAuthResult{
				Allowed:      false,
				MappingError: fmt.Errorf("mapping failed"),
				AccessError:  fmt.Errorf("access failed"),
				PolicyError:  fmt.Errorf("policy failed"),
			},
			expectError:   true,
			expectedError: "mapping failed",
		},
		{
			name: "access_error_priority",
			result: &ResourceAuthResult{
				Allowed:     false,
				AccessError: fmt.Errorf("access failed"),
				PolicyError: fmt.Errorf("policy failed"),
			},
			expectError:   true,
			expectedError: "access failed",
		},
		{
			name: "policy_error_priority",
			result: &ResourceAuthResult{
				Allowed:     false,
				PolicyError: fmt.Errorf("policy failed"),
			},
			expectError:   true,
			expectedError: "policy failed",
		},
		{
			name: "denied_without_specific_error",
			result: &ResourceAuthResult{
				Allowed: false,
				Reason:  "access denied by policy",
			},
			expectError:   true,
			expectedError: "access denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.result.GetPrimaryError()

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.expectedError != "" && !containsString(err.Error(), tt.expectedError) {
					t.Errorf("Expected error to contain '%s', got '%s'",
						tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

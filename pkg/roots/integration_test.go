package roots

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadOnlyEnforcement tests mount-level read-only enforcement (R4.2)
func TestReadOnlyEnforcement(t *testing.T) {
	tempDir := t.TempDir()

	// Create test file
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("original content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name          string
		readOnly      bool
		operation     string
		expectError   bool
		expectedError error
	}{
		{
			name:        "read on read-only filesystem",
			readOnly:    true,
			operation:   "read",
			expectError: false,
		},
		{
			name:          "write on read-only filesystem",
			readOnly:      true,
			operation:     "write",
			expectError:   true,
			expectedError: ErrReadOnlyFilesystem,
		},
		{
			name:        "write on read-write filesystem",
			readOnly:    false,
			operation:   "write",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := NewFilesystemBackend(tempDir, tt.readOnly)

			switch tt.operation {
			case "read":
				reader, err := backend.Read(context.Background(), testFile)
				if tt.expectError {
					if err == nil {
						t.Errorf("Expected error but got none")
						if reader != nil {
							reader.Close()
						}
					} else if tt.expectedError != nil && !errors.Is(err, tt.expectedError) {
						t.Errorf("Expected error %v, got: %v", tt.expectedError, err)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error: %v", err)
					} else if reader != nil {
						reader.Close()
					}
				}

			case "write":
				writeFile := filepath.Join(tempDir, "write_test.txt")
				err := backend.Write(context.Background(), writeFile, strings.NewReader("test content"))
				if tt.expectError {
					if err == nil {
						t.Errorf("Expected error but got none")
					} else if tt.expectedError != nil && !errors.Is(err, tt.expectedError) {
						t.Errorf("Expected error %v, got: %v", tt.expectedError, err)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error: %v", err)
					}
				}
			}
		})
	}
}

// TestPathSandboxing tests enhanced path sandboxing (R4.2)
func TestPathSandboxing(t *testing.T) {
	tempDir := t.TempDir()

	// Create a regular file
	regularFile := filepath.Join(tempDir, "regular.txt")
	if err := os.WriteFile(regularFile, []byte("content"), 0644); err != nil {
		t.Fatalf("Failed to create regular file: %v", err)
	}

	// Create a symlink (skip if not supported)
	symlinkFile := filepath.Join(tempDir, "symlink.txt")
	if err := os.Symlink(regularFile, symlinkFile); err != nil {
		t.Skipf("Cannot create symlink (may not be supported): %v", err)
	}

	backend := NewFilesystemBackend(tempDir, false).(*filesystemBackend)

	tests := []struct {
		name          string
		path          string
		expectError   bool
		expectedError error
	}{
		{
			name:        "regular file path",
			path:        regularFile,
			expectError: false,
		},
		{
			name:        "path with .. traversal",
			path:        filepath.Join(tempDir, "../../../etc/passwd"),
			expectError: true,
			// This will be caught by the "path outside root directory" check, not our new error type
		},
		{
			name:          "symlink in path",
			path:          symlinkFile,
			expectError:   true,
			expectedError: ErrSymlinkDetected,
		},
		{
			name:        "path with .. after cleaning",
			path:        filepath.Join(tempDir, "dir/../../../etc/passwd"),
			expectError: true,
			// This will be caught by the "path outside root directory" check, not our new error type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := backend.validatePath(tt.path)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none for path: %s", tt.path)
				} else if tt.expectedError != nil && !errors.Is(err, tt.expectedError) {
					t.Errorf("Expected error %v, got: %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for path %s: %v", tt.path, err)
				}
			}
		})
	}
}

// TestURISchemeValidation tests URI scheme whitelist validation (R19.1, R19.2)
func TestURISchemeValidation(t *testing.T) {
	tempDir := t.TempDir()

	configs := []RootConfig{
		{
			Name:     "repo",
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

	mapper, err := NewRootMapper(configs, nil)
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	tests := []struct {
		name          string
		virtualURI    string
		expectError   bool
		expectedError error
	}{
		{
			name:        "valid mcp://repo/ URI",
			virtualURI:  "mcp://repo/test.txt",
			expectError: false,
		},
		{
			name:        "valid mcp://artifacts/ URI",
			virtualURI:  "mcp://artifacts/build.zip",
			expectError: false,
		},
		{
			name:          "invalid file:// scheme",
			virtualURI:    "file:///etc/passwd",
			expectError:   true,
			expectedError: ErrUnauthorizedScheme,
		},
		{
			name:          "invalid http:// scheme",
			virtualURI:    "http://example.com/file.txt",
			expectError:   true,
			expectedError: ErrUnauthorizedScheme,
		},
		{
			name:          "invalid https:// scheme",
			virtualURI:    "https://example.com/file.txt",
			expectError:   true,
			expectedError: ErrUnauthorizedScheme,
		},
		{
			name:        "invalid mcp:// path",
			virtualURI:  "mcp://unauthorized/file.txt",
			expectError: true,
			// This will be caught by the virtual root validation, not the scheme validation
		},
		{
			name:          "invalid ftp:// scheme",
			virtualURI:    "ftp://example.com/file.txt",
			expectError:   true,
			expectedError: ErrUnauthorizedScheme,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mapper.MapURI(context.Background(), tt.virtualURI, "tenant1")

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for URI %s but got none", tt.virtualURI)
				} else if tt.expectedError != nil && !errors.Is(err, tt.expectedError) {
					t.Errorf("Expected error %v, got: %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for URI %s: %v", tt.virtualURI, err)
				}
			}
		})
	}
}

// TestS3ReadOnlyWithArtifactsPrefix tests S3 read-only mode with artifacts exception (R19.4)
func TestS3ReadOnlyWithArtifactsPrefix(t *testing.T) {
	mockClient := newMockS3Client()

	tests := []struct {
		name           string
		s3URI          string
		path           string
		operation      string
		expectError    bool
		expectedError  error
		expectedPrefix string
	}{
		{
			name:        "read from repo prefix",
			s3URI:       "s3://test-bucket/repo/",
			path:        "file.txt",
			operation:   "read",
			expectError: false,
		},
		{
			name:          "write to repo prefix (should fail)",
			s3URI:         "s3://test-bucket/repo/",
			path:          "file.txt",
			operation:     "write",
			expectError:   true,
			expectedError: ErrReadOnlyS3Backend,
		},
		{
			name:           "write to artifacts prefix (should succeed)",
			s3URI:          "s3://test-bucket/artifacts/",
			path:           "build.zip",
			operation:      "write",
			expectError:    false,
			expectedPrefix: "artifacts",
		},
		{
			name:        "read from artifacts prefix",
			s3URI:       "s3://test-bucket/artifacts/",
			path:        "build.zip",
			operation:   "read",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := NewS3Backend(mockClient, tt.s3URI, false).(*s3Backend)

			// Verify the allowedWritePrefix is set correctly
			if tt.expectedPrefix != "" {
				if !strings.Contains(backend.allowedWritePrefix, tt.expectedPrefix) {
					t.Errorf("Expected allowedWritePrefix to contain '%s', got: %s", tt.expectedPrefix, backend.allowedWritePrefix)
				}
			}

			switch tt.operation {
			case "read":
				// Set up test data for read operations
				key := backend.buildKey(tt.path)
				mockClient.setObject(key, []byte("test content"))

				reader, err := backend.Read(context.Background(), tt.path)
				if tt.expectError {
					if err == nil {
						t.Errorf("Expected error but got none")
						if reader != nil {
							reader.Close()
						}
					} else if tt.expectedError != nil && !errors.Is(err, tt.expectedError) {
						t.Errorf("Expected error %v, got: %v", tt.expectedError, err)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error: %v", err)
					} else if reader != nil {
						reader.Close()
					}
				}

			case "write":
				err := backend.Write(context.Background(), tt.path, strings.NewReader("test content"))
				if tt.expectError {
					if err == nil {
						t.Errorf("Expected error but got none")
					} else if tt.expectedError != nil && !errors.Is(err, tt.expectedError) {
						t.Errorf("Expected error %v, got: %v", tt.expectedError, err)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error: %v", err)
					}
				}
			}
		})
	}
}

// TestCaseInsensitiveURIMatching tests case-insensitive URI matching
func TestCaseInsensitiveURIMatching(t *testing.T) {
	tempDir := t.TempDir()

	configs := []RootConfig{
		{
			Name:     "repo",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     tempDir,
			ReadOnly: true,
		},
		{
			Name:     "artifacts",
			Type:     "fs",
			Virtual:  "mcp://ARTIFACTS/", // Mixed case virtual root
			Real:     tempDir,
			ReadOnly: false,
		},
	}

	mapper, err := NewRootMapper(configs, nil)
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	tests := []struct {
		name        string
		virtualURI  string
		expectError bool
	}{
		{
			name:        "lowercase repo URI",
			virtualURI:  "mcp://repo/test.txt",
			expectError: false,
		},
		{
			name:        "uppercase repo URI",
			virtualURI:  "mcp://REPO/test.txt",
			expectError: false,
		},
		{
			name:        "mixed case repo URI",
			virtualURI:  "mcp://Repo/test.txt",
			expectError: false,
		},
		{
			name:        "lowercase artifacts URI",
			virtualURI:  "mcp://artifacts/build.zip",
			expectError: false,
		},
		{
			name:        "uppercase artifacts URI",
			virtualURI:  "mcp://ARTIFACTS/build.zip",
			expectError: false,
		},
		{
			name:        "mixed case artifacts URI",
			virtualURI:  "mcp://Artifacts/build.zip",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mapper.MapURI(context.Background(), tt.virtualURI, "tenant1")

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for URI %s but got none", tt.virtualURI)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for URI %s: %v", tt.virtualURI, err)
				}
			}
		})
	}
}

// TestIntegratedSecurityValidation tests the complete security validation pipeline
func TestIntegratedSecurityValidation(t *testing.T) {
	tempDir := t.TempDir()

	configs := []RootConfig{
		{
			Name:     "repo",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     tempDir,
			ReadOnly: true,
		},
	}

	mapper, err := NewRootMapper(configs, nil)
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	// Test cases that should all fail due to various security violations
	securityViolations := []struct {
		name          string
		virtualURI    string
		operation     string
		expectError   bool
		expectedError error
	}{
		{
			name:        "scheme injection attempt",
			virtualURI:  "mcp://repo/../file://etc/passwd",
			operation:   "read",
			expectError: true,
			// This will be caught by path validation, not a specific error type
		},
		{
			name:          "write to read-only root",
			virtualURI:    "mcp://repo/test.txt",
			operation:     "write",
			expectError:   true,
			expectedError: ErrReadOnlyResource,
		},
		{
			name:          "unauthorized scheme",
			virtualURI:    "file:///etc/passwd",
			operation:     "read",
			expectError:   true,
			expectedError: ErrUnauthorizedScheme,
		},
		{
			name:        "path traversal in mcp URI",
			virtualURI:  "mcp://repo/../../../etc/passwd",
			operation:   "read",
			expectError: true,
			// This will be caught by path validation, not a specific error type
		},
	}

	for _, tt := range securityViolations {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := mapper.MapURI(context.Background(), tt.virtualURI, "tenant1")

			// Check if URI mapping itself fails (expected for scheme violations)
			if err != nil {
				if tt.expectError && tt.expectedError != nil && errors.Is(err, tt.expectedError) {
					return // Expected error at URI mapping stage
				}
				if !tt.expectError {
					t.Errorf("Unexpected error during URI mapping: %v", err)
					return
				}
			}

			if resource == nil && tt.expectError {
				return // Expected failure at URI mapping stage
			}

			// Test access validation
			if resource != nil {
				err = mapper.ValidateAccess(context.Background(), resource, tt.operation)
				if tt.expectError {
					if err == nil {
						t.Errorf("Expected error for %s operation on %s but got none", tt.operation, tt.virtualURI)
					} else if tt.expectedError != nil && !errors.Is(err, tt.expectedError) {
						t.Errorf("Expected error %v, got: %v", tt.expectedError, err)
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error for %s operation on %s: %v", tt.operation, tt.virtualURI, err)
					}
				}
			}
		})
	}
}

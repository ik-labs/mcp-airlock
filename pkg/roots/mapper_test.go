package roots

import (
	"context"
	"math/rand"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/quick"

	"go.uber.org/zap"
)

func TestRootMapper_MapURI(t *testing.T) {
	// Create temporary directory for testing
	tempDir := t.TempDir()

	configs := []RootConfig{
		{
			Name:     "test-fs",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     tempDir,
			ReadOnly: true,
		},
	}

	mapper, err := NewRootMapper(configs, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	tests := []struct {
		name         string
		virtualURI   string
		tenant       string
		expectError  bool
		expectedType string
	}{
		{
			name:         "valid file path",
			virtualURI:   "mcp://repo/test.txt",
			tenant:       "tenant1",
			expectError:  false,
			expectedType: "fs",
		},
		{
			name:        "path traversal attempt",
			virtualURI:  "mcp://repo/../../../etc/passwd",
			tenant:      "tenant1",
			expectError: true,
		},
		{
			name:        "absolute path attempt",
			virtualURI:  "mcp://repo/../etc/passwd",
			tenant:      "tenant1",
			expectError: true,
		},
		{
			name:        "unknown virtual root",
			virtualURI:  "mcp://unknown/test.txt",
			tenant:      "tenant1",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := mapper.MapURI(context.Background(), tt.virtualURI, tt.tenant)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if resource.Type != tt.expectedType {
				t.Errorf("Expected type %s, got %s", tt.expectedType, resource.Type)
			}

			// Verify the real path is within the temp directory
			if !strings.HasPrefix(resource.RealPath, tempDir) {
				t.Errorf("Real path %s is not within temp directory %s", resource.RealPath, tempDir)
			}
		})
	}
}

// Property-based test for path traversal prevention
func TestPathTraversalPrevention(t *testing.T) {
	tempDir := t.TempDir()

	configs := []RootConfig{
		{
			Name:     "test-fs",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     tempDir,
			ReadOnly: true,
		},
	}

	mapper, err := NewRootMapper(configs, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	rm := mapper.(*rootMapper)

	// Property: No path should escape the root directory
	property := func(pathComponents []string) bool {
		if len(pathComponents) == 0 {
			return true
		}

		// Build a potentially malicious path
		maliciousPath := strings.Join(pathComponents, "/")

		// Try to validate the path
		cleanPath, err := rm.validatePath(maliciousPath, tempDir)

		if err != nil {
			// If validation fails, that's expected for malicious paths
			return true
		}

		// If validation succeeds, ensure the path is still within the root
		absTemp, _ := filepath.Abs(tempDir)
		absClean, _ := filepath.Abs(cleanPath)

		return strings.HasPrefix(absClean, absTemp+string(filepath.Separator)) || absClean == absTemp
	}

	if err := quick.Check(property, &quick.Config{MaxCount: 1000}); err != nil {
		t.Errorf("Path traversal prevention property failed: %v", err)
	}
}

// Test specific path traversal patterns
func TestSpecificPathTraversalPatterns(t *testing.T) {
	tempDir := t.TempDir()

	configs := []RootConfig{
		{
			Name:     "test-fs",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     tempDir,
			ReadOnly: true,
		},
	}

	mapper, err := NewRootMapper(configs, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	maliciousPaths := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc/passwd",
		"../etc/passwd",
		"..\\etc\\passwd",
		"./../../etc/passwd",
		"foo/../../../etc/passwd",
		"foo/bar/../../../../../../etc/passwd",
		"./../.ssh/id_rsa",
		"../../../../../proc/self/environ",
	}

	for _, maliciousPath := range maliciousPaths {
		t.Run("malicious_path_"+maliciousPath, func(t *testing.T) {
			virtualURI := "mcp://repo/" + maliciousPath
			_, err := mapper.MapURI(context.Background(), virtualURI, "tenant1")

			if err == nil {
				t.Errorf("Expected error for malicious path %s, but got none", maliciousPath)
			}
		})
	}
}

// Property-based test for URI validation
func TestURIValidation(t *testing.T) {
	tempDir := t.TempDir()

	configs := []RootConfig{
		{
			Name:     "test-fs",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     tempDir,
			ReadOnly: true,
		},
	}

	mapper, err := NewRootMapper(configs, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	// Property: Valid URIs should not contain dangerous patterns
	property := func(pathSuffix string) bool {
		// Skip empty strings and strings with null bytes
		if pathSuffix == "" || strings.Contains(pathSuffix, "\x00") {
			return true
		}

		virtualURI := "mcp://repo/" + pathSuffix
		resource, err := mapper.MapURI(context.Background(), virtualURI, "tenant1")

		if err != nil {
			// Errors are acceptable for invalid paths
			return true
		}

		// If successful, ensure the real path is safe
		absTemp, _ := filepath.Abs(tempDir)
		absReal, _ := filepath.Abs(resource.RealPath)

		return strings.HasPrefix(absReal, absTemp+string(filepath.Separator)) || absReal == absTemp
	}

	config := &quick.Config{
		MaxCount: 500,
		Values: func(values []reflect.Value, rand *rand.Rand) {
			// Generate potentially problematic path suffixes
			patterns := []string{
				"../",
				"./",
				"//",
				"\\",
				"..",
				".",
				"/",
			}

			// Build a random path with potentially dangerous components
			var parts []string
			numParts := rand.Intn(5) + 1

			for i := 0; i < numParts; i++ {
				if rand.Float32() < 0.3 {
					// Add a dangerous pattern
					parts = append(parts, patterns[rand.Intn(len(patterns))])
				} else {
					// Add a normal path component
					length := rand.Intn(10) + 1
					component := make([]byte, length)
					for j := range component {
						component[j] = byte(rand.Intn(26) + 'a')
					}
					parts = append(parts, string(component))
				}
			}

			pathSuffix := strings.Join(parts, "")
			values[0] = reflect.ValueOf(pathSuffix)
		},
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("URI validation property failed: %v", err)
	}
}

func TestValidateAccess(t *testing.T) {
	tempDir := t.TempDir()

	configs := []RootConfig{
		{
			Name:     "readonly-fs",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     tempDir,
			ReadOnly: true,
		},
		{
			Name:     "readwrite-fs",
			Type:     "fs",
			Virtual:  "mcp://artifacts/",
			Real:     tempDir,
			ReadOnly: false,
		},
	}

	mapper, err := NewRootMapper(configs, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	tests := []struct {
		name        string
		virtualURI  string
		operation   string
		expectError bool
	}{
		{
			name:        "read on readonly",
			virtualURI:  "mcp://repo/test.txt",
			operation:   "read",
			expectError: false,
		},
		{
			name:        "write on readonly",
			virtualURI:  "mcp://repo/test.txt",
			operation:   "write",
			expectError: true,
		},
		{
			name:        "write on readwrite",
			virtualURI:  "mcp://artifacts/test.txt",
			operation:   "write",
			expectError: false,
		},
		{
			name:        "delete on readonly",
			virtualURI:  "mcp://repo/test.txt",
			operation:   "delete",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := mapper.MapURI(context.Background(), tt.virtualURI, "tenant1")
			if err != nil {
				t.Fatalf("Failed to map URI: %v", err)
			}

			err = mapper.ValidateAccess(context.Background(), resource, tt.operation)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for operation %s on %s", tt.operation, tt.virtualURI)
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for operation %s on %s: %v", tt.operation, tt.virtualURI, err)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      RootConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: RootConfig{
				Name:     "test",
				Type:     "fs",
				Virtual:  "mcp://repo/",
				Real:     "/tmp",
				ReadOnly: true,
			},
			expectError: false,
		},
		{
			name: "empty name",
			config: RootConfig{
				Name:     "",
				Type:     "fs",
				Virtual:  "mcp://repo/",
				Real:     "/tmp",
				ReadOnly: true,
			},
			expectError: true,
		},
		{
			name: "invalid type",
			config: RootConfig{
				Name:     "test",
				Type:     "invalid",
				Virtual:  "mcp://repo/",
				Real:     "/tmp",
				ReadOnly: true,
			},
			expectError: true,
		},
		{
			name: "empty virtual path",
			config: RootConfig{
				Name:     "test",
				Type:     "fs",
				Virtual:  "",
				Real:     "/tmp",
				ReadOnly: true,
			},
			expectError: true,
		},
		{
			name: "invalid virtual URI",
			config: RootConfig{
				Name:     "test",
				Type:     "fs",
				Virtual:  "://invalid",
				Real:     "/tmp",
				ReadOnly: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRootMapper([]RootConfig{tt.config}, nil, zap.NewNop())

			if tt.expectError && err == nil {
				t.Errorf("Expected error for config %+v", tt.config)
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for config %+v: %v", tt.config, err)
			}
		})
	}
}

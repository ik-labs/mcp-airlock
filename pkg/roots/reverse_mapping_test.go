package roots

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRootMapper_ReverseMap(t *testing.T) {
	// Create temporary directory for testing
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Configure virtual roots
	rootConfigs := []RootConfig{
		{
			Name:     "repo",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     tempDir,
			ReadOnly: true,
		},
		{
			Name:     "artifacts",
			Type:     "s3",
			Virtual:  "mcp://artifacts/",
			Real:     "s3://test-bucket/artifacts",
			ReadOnly: false,
		},
	}

	// Create root mapper with mock S3 client
	mockS3Client := newMockS3Client()
	mapper, err := NewRootMapper(rootConfigs, mockS3Client)
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	ctx := context.Background()
	tenant := "tenant1"

	tests := []struct {
		name        string
		realPath    string
		expectedURI string
		shouldFind  bool
		description string
	}{
		{
			name:        "filesystem_exact_root",
			realPath:    tempDir,
			expectedURI: "mcp://repo/",
			shouldFind:  true,
			description: "Should map exact filesystem root to virtual URI",
		},
		{
			name:        "filesystem_file_in_root",
			realPath:    testFile,
			expectedURI: "mcp://repo/test.txt",
			shouldFind:  true,
			description: "Should map filesystem file to virtual URI with relative path",
		},
		{
			name:        "s3_exact_root",
			realPath:    "s3://test-bucket/artifacts",
			expectedURI: "mcp://artifacts/",
			shouldFind:  true,
			description: "Should map exact S3 root to virtual URI",
		},
		{
			name:        "s3_file_in_root",
			realPath:    "s3://test-bucket/artifacts/build.log",
			expectedURI: "mcp://artifacts/build.log",
			shouldFind:  true,
			description: "Should map S3 file to virtual URI with relative path",
		},
		{
			name:        "s3_nested_file",
			realPath:    "s3://test-bucket/artifacts/logs/build.log",
			expectedURI: "mcp://artifacts/logs/build.log",
			shouldFind:  true,
			description: "Should map nested S3 file to virtual URI",
		},
		{
			name:        "unmapped_filesystem_path",
			realPath:    "/tmp/unmapped.txt",
			expectedURI: "",
			shouldFind:  false,
			description: "Should not find mapping for unmapped filesystem path",
		},
		{
			name:        "unmapped_s3_path",
			realPath:    "s3://other-bucket/file.txt",
			expectedURI: "",
			shouldFind:  false,
			description: "Should not find mapping for unmapped S3 path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			virtualURI, found := mapper.ReverseMap(ctx, tenant, tt.realPath)

			if found != tt.shouldFind {
				t.Errorf("Expected found=%v, got found=%v for path %s", tt.shouldFind, found, tt.realPath)
			}

			if tt.shouldFind && virtualURI != tt.expectedURI {
				t.Errorf("Expected virtual URI %q, got %q for path %s", tt.expectedURI, virtualURI, tt.realPath)
			}

			if !tt.shouldFind && virtualURI != "" {
				t.Errorf("Expected empty virtual URI for unmapped path, got %q", virtualURI)
			}

			t.Logf("%s: %s -> %s (found: %v)", tt.description, tt.realPath, virtualURI, found)
		})
	}
}

func TestRootMiddleware_ConvertRealPathToVirtualURI(t *testing.T) {
	// Create temporary directory for testing
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Configure virtual roots
	rootConfigs := []RootConfig{
		{
			Name:     "repo",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     tempDir,
			ReadOnly: true,
		},
	}

	// Create root mapper and middleware
	mapper, err := NewRootMapper(rootConfigs, nil)
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	middleware := NewRootMiddleware(mapper, nil)

	ctx := context.Background()
	tenant := "tenant1"

	tests := []struct {
		name         string
		inputPath    string
		expectedPath string
		description  string
	}{
		{
			name:         "mapped_filesystem_file",
			inputPath:    testFile,
			expectedPath: "mcp://repo/test.txt",
			description:  "Should convert mapped filesystem file to virtual URI",
		},
		{
			name:         "unmapped_filesystem_file",
			inputPath:    "/tmp/unmapped.txt",
			expectedPath: "/tmp/unmapped.txt",
			description:  "Should return original path for unmapped filesystem file",
		},
		{
			name:         "non_absolute_path",
			inputPath:    "relative/path.txt",
			expectedPath: "relative/path.txt",
			description:  "Should return original path for non-absolute path",
		},
		{
			name:         "mapped_s3_path",
			inputPath:    "s3://test-bucket/file.txt",
			expectedPath: "s3://test-bucket/file.txt",
			description:  "Should return original path for unmapped S3 path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := middleware.convertRealPathToVirtualURI(ctx, tenant, tt.inputPath)

			if result != tt.expectedPath {
				t.Errorf("Expected %q, got %q for input %s", tt.expectedPath, result, tt.inputPath)
			}

			t.Logf("%s: %s -> %s", tt.description, tt.inputPath, result)
		})
	}
}

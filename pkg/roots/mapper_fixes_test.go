package roots

import (
	"context"
	"strings"
	"testing"
)

func TestDuplicateVirtualRootPrevention(t *testing.T) {
	tests := []struct {
		name        string
		configs     []RootConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "unique virtual roots",
			configs: []RootConfig{
				{
					Name:     "docs",
					Type:     "fs",
					Virtual:  "mcp://docs/",
					Real:     "/var/docs",
					ReadOnly: true,
				},
				{
					Name:     "artifacts",
					Type:     "fs",
					Virtual:  "mcp://artifacts/",
					Real:     "/var/artifacts",
					ReadOnly: false,
				},
			},
			expectError: false,
		},
		{
			name: "duplicate virtual roots",
			configs: []RootConfig{
				{
					Name:     "docs1",
					Type:     "fs",
					Virtual:  "mcp://docs/",
					Real:     "/var/docs1",
					ReadOnly: true,
				},
				{
					Name:     "docs2",
					Type:     "fs",
					Virtual:  "mcp://docs/", // Duplicate!
					Real:     "/var/docs2",
					ReadOnly: false,
				},
			},
			expectError: true,
			errorMsg:    "duplicate virtual root",
		},
		{
			name: "case sensitive virtual roots",
			configs: []RootConfig{
				{
					Name:     "docs-lower",
					Type:     "fs",
					Virtual:  "mcp://docs/",
					Real:     "/var/docs1",
					ReadOnly: true,
				},
				{
					Name:     "docs-upper",
					Type:     "fs",
					Virtual:  "mcp://DOCS/", // Different case - should be allowed
					Real:     "/var/docs2",
					ReadOnly: false,
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRootMapper(tt.configs, nil)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestS3URIPathConstruction(t *testing.T) {
	tempDir := t.TempDir()

	configs := []RootConfig{
		{
			Name:     "s3-test",
			Type:     "fs", // Use fs type to avoid S3 client requirement
			Virtual:  "mcp://s3test/",
			Real:     "s3://test-bucket/prefix/",
			ReadOnly: true,
		},
		{
			Name:     "fs-test",
			Type:     "fs",
			Virtual:  "mcp://fstest/",
			Real:     tempDir,
			ReadOnly: true,
		},
	}

	mapper, err := NewRootMapper(configs, nil)
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	tests := []struct {
		name         string
		virtualURI   string
		expectedPath string
		expectError  bool
	}{
		{
			name:         "S3 URI root path",
			virtualURI:   "mcp://s3test/",
			expectedPath: "s3://test-bucket/prefix/",
			expectError:  false,
		},
		{
			name:         "S3 URI with file",
			virtualURI:   "mcp://s3test/file.txt",
			expectedPath: "s3://test-bucket/prefix/file.txt",
			expectError:  false,
		},
		{
			name:         "S3 URI with nested path",
			virtualURI:   "mcp://s3test/dir/subdir/file.txt",
			expectedPath: "s3://test-bucket/prefix/dir/subdir/file.txt",
			expectError:  false,
		},
		{
			name:        "filesystem path",
			virtualURI:  "mcp://fstest/file.txt",
			expectError: false,
			// expectedPath will be the temp dir + file.txt (tested separately)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := mapper.MapURI(context.Background(), tt.virtualURI, "tenant1")

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

			if tt.expectedPath != "" {
				if resource.RealPath != tt.expectedPath {
					t.Errorf("Expected path %q, got %q", tt.expectedPath, resource.RealPath)
				}
			}

			// For S3 URIs, ensure they weren't corrupted by filepath.Join
			if strings.Contains(tt.virtualURI, "s3test") {
				if !strings.Contains(resource.RealPath, "s3://") {
					t.Errorf("S3 URI was corrupted: %s", resource.RealPath)
				}
				if strings.Contains(resource.RealPath, "s3:/") && !strings.Contains(resource.RealPath, "s3://") {
					t.Errorf("S3 URI was corrupted by filepath.Join: %s", resource.RealPath)
				}
			}
		})
	}
}

func TestS3URIEdgeCases(t *testing.T) {
	configs := []RootConfig{
		{
			Name:     "s3-root",
			Type:     "fs", // Use fs to avoid S3 client requirement
			Virtual:  "mcp://s3root/",
			Real:     "s3://bucket/",
			ReadOnly: true,
		},
		{
			Name:     "s3-with-prefix",
			Type:     "fs",
			Virtual:  "mcp://s3prefix/",
			Real:     "s3://bucket/some/prefix/",
			ReadOnly: true,
		},
	}

	mapper, err := NewRootMapper(configs, nil)
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	tests := []struct {
		name         string
		virtualURI   string
		expectedPath string
	}{
		{
			name:         "S3 bucket root",
			virtualURI:   "mcp://s3root/",
			expectedPath: "s3://bucket/",
		},
		{
			name:         "S3 bucket root with file",
			virtualURI:   "mcp://s3root/file.txt",
			expectedPath: "s3://bucket/file.txt",
		},
		{
			name:         "S3 with prefix root",
			virtualURI:   "mcp://s3prefix/",
			expectedPath: "s3://bucket/some/prefix/",
		},
		{
			name:         "S3 with prefix and file",
			virtualURI:   "mcp://s3prefix/file.txt",
			expectedPath: "s3://bucket/some/prefix/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := mapper.MapURI(context.Background(), tt.virtualURI, "tenant1")
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if resource.RealPath != tt.expectedPath {
				t.Errorf("Expected path %q, got %q", tt.expectedPath, resource.RealPath)
			}
		})
	}
}

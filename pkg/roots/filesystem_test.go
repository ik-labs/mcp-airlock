package roots

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesystemBackend_Read(t *testing.T) {
	tempDir := t.TempDir()

	// Create test file
	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "Hello, World!"
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	backend := NewFilesystemBackend(tempDir, false)

	tests := []struct {
		name            string
		path            string
		expectError     bool
		expectedContent string
	}{
		{
			name:            "read existing file",
			path:            testFile,
			expectError:     false,
			expectedContent: testContent,
		},
		{
			name:        "read non-existent file",
			path:        filepath.Join(tempDir, "nonexistent.txt"),
			expectError: true,
		},
		{
			name:        "read outside root",
			path:        "/etc/passwd",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := backend.Read(context.Background(), tt.path)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					if reader != nil {
						reader.Close()
					}
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			defer reader.Close()

			content, err := io.ReadAll(reader)
			if err != nil {
				t.Errorf("Failed to read content: %v", err)
				return
			}

			if string(content) != tt.expectedContent {
				t.Errorf("Expected content %q, got %q", tt.expectedContent, string(content))
			}
		})
	}
}

func TestFilesystemBackend_Write(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		readOnly    bool
		path        string
		content     string
		expectError bool
	}{
		{
			name:        "write to read-write backend",
			readOnly:    false,
			path:        filepath.Join(tempDir, "write_test.txt"),
			content:     "test content",
			expectError: false,
		},
		{
			name:        "write to read-only backend",
			readOnly:    true,
			path:        filepath.Join(tempDir, "readonly_test.txt"),
			content:     "test content",
			expectError: true,
		},
		{
			name:        "write outside root",
			readOnly:    false,
			path:        "/tmp/outside_root.txt",
			content:     "test content",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := NewFilesystemBackend(tempDir, tt.readOnly)

			err := backend.Write(context.Background(), tt.path, strings.NewReader(tt.content))

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

			// Verify file was written
			content, err := os.ReadFile(tt.path)
			if err != nil {
				t.Errorf("Failed to read written file: %v", err)
				return
			}

			if string(content) != tt.content {
				t.Errorf("Expected content %q, got %q", tt.content, string(content))
			}
		})
	}
}

func TestFilesystemBackend_List(t *testing.T) {
	tempDir := t.TempDir()

	// Create test files and directories
	testFiles := []string{"file1.txt", "file2.txt"}
	testDirs := []string{"dir1", "dir2"}

	for _, file := range testFiles {
		path := filepath.Join(tempDir, file)
		if err := os.WriteFile(path, []byte("content"), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
	}

	for _, dir := range testDirs {
		path := filepath.Join(tempDir, dir)
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatalf("Failed to create test directory %s: %v", dir, err)
		}
	}

	backend := NewFilesystemBackend(tempDir, false)

	files, err := backend.List(context.Background(), tempDir)
	if err != nil {
		t.Fatalf("Failed to list directory: %v", err)
	}

	// Check that we got the expected number of entries
	expectedCount := len(testFiles) + len(testDirs)
	if len(files) != expectedCount {
		t.Errorf("Expected %d entries, got %d", expectedCount, len(files))
	}

	// Check that all expected files and directories are present
	foundNames := make(map[string]bool)
	for _, file := range files {
		foundNames[file.Name] = true
	}

	for _, expectedFile := range testFiles {
		if !foundNames[expectedFile] {
			t.Errorf("Expected file %s not found in listing", expectedFile)
		}
	}

	for _, expectedDir := range testDirs {
		if !foundNames[expectedDir] {
			t.Errorf("Expected directory %s not found in listing", expectedDir)
		}
	}
}

func TestFilesystemBackend_Stat(t *testing.T) {
	tempDir := t.TempDir()

	// Create test file
	testFile := filepath.Join(tempDir, "stat_test.txt")
	testContent := "test content for stat"
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	backend := NewFilesystemBackend(tempDir, false)

	tests := []struct {
		name         string
		path         string
		expectError  bool
		expectedSize int64
	}{
		{
			name:         "stat existing file",
			path:         testFile,
			expectError:  false,
			expectedSize: int64(len(testContent)),
		},
		{
			name:        "stat non-existent file",
			path:        filepath.Join(tempDir, "nonexistent.txt"),
			expectError: true,
		},
		{
			name:        "stat outside root",
			path:        "/etc/passwd",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := backend.Stat(context.Background(), tt.path)

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

			if info.Size != tt.expectedSize {
				t.Errorf("Expected size %d, got %d", tt.expectedSize, info.Size)
			}

			if info.Name == "" {
				t.Errorf("Expected non-empty name")
			}
		})
	}
}

func TestFilesystemBackend_PathValidation(t *testing.T) {
	tempDir := t.TempDir()
	backend := NewFilesystemBackend(tempDir, false).(*filesystemBackend)

	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "valid path within root",
			path:        filepath.Join(tempDir, "valid.txt"),
			expectError: false,
		},
		{
			name:        "path outside root",
			path:        "/etc/passwd",
			expectError: true,
		},
		{
			name:        "path traversal attempt",
			path:        filepath.Join(tempDir, "../../../etc/passwd"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := backend.validatePath(tt.path)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none for path: %s", tt.path)
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for path %s: %v", tt.path, err)
			}
		})
	}
}

func TestFilesystemBackend_SymlinkValidation(t *testing.T) {
	tempDir := t.TempDir()

	// Create a regular file
	regularFile := filepath.Join(tempDir, "regular.txt")
	if err := os.WriteFile(regularFile, []byte("content"), 0644); err != nil {
		t.Fatalf("Failed to create regular file: %v", err)
	}

	// Create a symlink
	symlinkFile := filepath.Join(tempDir, "symlink.txt")
	if err := os.Symlink(regularFile, symlinkFile); err != nil {
		t.Skipf("Cannot create symlink (may not be supported): %v", err)
	}

	backend := NewFilesystemBackend(tempDir, false).(*filesystemBackend)

	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "regular file",
			path:        regularFile,
			expectError: false,
		},
		{
			name:        "symlink file",
			path:        symlinkFile,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := backend.validateNotSymlink(tt.path)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for symlink validation but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for symlink validation: %v", err)
			}
		})
	}
}

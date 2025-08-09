package roots

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesystemBackend_WriteSymlinkSecurity(t *testing.T) {
	tempDir := t.TempDir()

	// Create a regular file
	regularFile := filepath.Join(tempDir, "regular.txt")
	if err := os.WriteFile(regularFile, []byte("content"), 0644); err != nil {
		t.Fatalf("Failed to create regular file: %v", err)
	}

	// Create a symlink pointing to a file outside the root
	outsideFile := "/tmp/outside.txt"
	symlinkFile := filepath.Join(tempDir, "symlink.txt")
	if err := os.Symlink(outsideFile, symlinkFile); err != nil {
		t.Skipf("Cannot create symlink (may not be supported): %v", err)
	}

	backend := NewFilesystemBackend(tempDir, false)

	tests := []struct {
		name        string
		path        string
		content     string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "write to regular file",
			path:        regularFile,
			content:     "new content",
			expectError: false,
		},
		{
			name:        "write through symlink",
			path:        symlinkFile,
			content:     "malicious content",
			expectError: true,
			errorMsg:    "symlink",
		},
		{
			name:        "write to new file",
			path:        filepath.Join(tempDir, "new.txt"),
			content:     "new file content",
			expectError: false,
		},
	}

	for _, tt := range tests {
		tt := tt // capture loop variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := backend.Write(context.Background(), tt.path, strings.NewReader(tt.content))

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
				return
			}

			// Verify content was written correctly
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

func TestFilesystemBackend_SymlinkEscapeDetection(t *testing.T) {
	tempDir := t.TempDir()

	// Create a subdirectory
	subDir := filepath.Join(tempDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Create a file outside the root
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("outside content"), 0644); err != nil {
		t.Fatalf("Failed to create outside file: %v", err)
	}

	// Create a symlink in subdir pointing outside the root
	symlinkInSub := filepath.Join(subDir, "escape.txt")
	if err := os.Symlink(outsideFile, symlinkInSub); err != nil {
		t.Skipf("Cannot create symlink (may not be supported): %v", err)
	}

	// Create a symlink to a directory outside the root
	symlinkDir := filepath.Join(tempDir, "escape_dir")
	if err := os.Symlink(outsideDir, symlinkDir); err != nil {
		t.Skipf("Cannot create directory symlink (may not be supported): %v", err)
	}

	backend := NewFilesystemBackend(tempDir, false).(*filesystemBackend)

	tests := []struct {
		name        string
		path        string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "regular file in root",
			path:        filepath.Join(tempDir, "regular.txt"),
			expectError: false,
		},
		{
			name:        "file in subdirectory",
			path:        filepath.Join(subDir, "regular.txt"),
			expectError: false,
		},
		{
			name:        "symlink escape from subdirectory",
			path:        symlinkInSub,
			expectError: true,
			errorMsg:    "symlink escape detected",
		},
		{
			name:        "symlink directory escape",
			path:        filepath.Join(symlinkDir, "file.txt"),
			expectError: true,
			errorMsg:    "symlink escape detected",
		},
	}

	for _, tt := range tests {
		tt := tt // capture loop variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := backend.validatePath(tt.path)

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

func TestFilesystemBackend_NestedSymlinkEscape(t *testing.T) {
	tempDir := t.TempDir()

	// Create nested directory structure
	level1 := filepath.Join(tempDir, "level1")
	level2 := filepath.Join(level1, "level2")
	if err := os.MkdirAll(level2, 0755); err != nil {
		t.Fatalf("Failed to create nested directories: %v", err)
	}

	// Create a file outside the root
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret content"), 0644); err != nil {
		t.Fatalf("Failed to create outside file: %v", err)
	}

	// Create a chain of symlinks that eventually escape
	// level1/escape -> ../../../outside_dir
	escapeLink := filepath.Join(level1, "escape")
	if err := os.Symlink("../../../"+filepath.Base(outsideDir), escapeLink); err != nil {
		t.Skipf("Cannot create symlink (may not be supported): %v", err)
	}

	// level2/nested_escape -> ../escape/secret.txt
	nestedEscape := filepath.Join(level2, "nested_escape")
	if err := os.Symlink("../escape/secret.txt", nestedEscape); err != nil {
		t.Skipf("Cannot create nested symlink (may not be supported): %v", err)
	}

	backend := NewFilesystemBackend(tempDir, false).(*filesystemBackend)

	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "direct symlink escape",
			path:        escapeLink,
			expectError: true,
		},
		{
			name:        "nested symlink escape",
			path:        nestedEscape,
			expectError: true,
		},
		{
			name:        "file through escaped symlink",
			path:        filepath.Join(escapeLink, "secret.txt"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture loop variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := backend.validatePath(tt.path)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for nested symlink escape but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestFilesystemBackend_CreateFileSecure(t *testing.T) {
	tempDir := t.TempDir()

	// Create a symlink pointing outside the root
	outsideFile := "/tmp/outside_target.txt"
	symlinkFile := filepath.Join(tempDir, "symlink.txt")
	if err := os.Symlink(outsideFile, symlinkFile); err != nil {
		t.Skipf("Cannot create symlink (may not be supported): %v", err)
	}

	backend := NewFilesystemBackend(tempDir, false).(*filesystemBackend)

	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "create regular file",
			path:        filepath.Join(tempDir, "regular.txt"),
			expectError: false,
		},
		{
			name:        "create through symlink",
			path:        symlinkFile,
			expectError: true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture loop variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			file, err := backend.createFileSecure(tt.path)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					if file != nil {
						file.Close()
					}
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if file == nil {
				t.Errorf("Expected file but got nil")
				return
			}

			if file != nil {
				file.Close()
			}

			// Verify file was created
			if _, err := os.Stat(tt.path); err != nil {
				t.Errorf("File was not created: %v", err)
			}
		})
	}
}

func TestFilesystemBackend_ReadSymlinkValidation(t *testing.T) {
	tempDir := t.TempDir()

	// Create a regular file
	regularFile := filepath.Join(tempDir, "regular.txt")
	if err := os.WriteFile(regularFile, []byte("content"), 0644); err != nil {
		t.Fatalf("Failed to create regular file: %v", err)
	}

	// Create a symlink pointing to the regular file (within root)
	symlinkFile := filepath.Join(tempDir, "symlink.txt")
	if err := os.Symlink(regularFile, symlinkFile); err != nil {
		t.Skipf("Cannot create symlink (may not be supported): %v", err)
	}

	backend := NewFilesystemBackend(tempDir, false)

	// Test that reading through symlink is blocked
	_, err := backend.Read(context.Background(), symlinkFile)
	if err == nil {
		t.Errorf("Expected error when reading through symlink but got none")
	} else if !strings.Contains(err.Error(), "symlinks not allowed") {
		t.Errorf("Expected symlink error, got: %v", err)
	}
}

package roots

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// filesystemBackend implements Backend for local filesystem
type filesystemBackend struct {
	rootPath string
	readOnly bool
}

// NewFilesystemBackend creates a new filesystem backend
func NewFilesystemBackend(rootPath string, readOnly bool) Backend {
	return &filesystemBackend{
		rootPath: rootPath,
		readOnly: readOnly,
	}
}

// Read returns a reader for the file at the given path
func (fs *filesystemBackend) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	// Validate path is within root
	if err := fs.validatePath(path); err != nil {
		return nil, err
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Open file for reading
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		if os.IsPermission(err) {
			return nil, fmt.Errorf("permission denied: %s", path)
		}
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}

	// Validate it's not a symlink (security measure)
	if err := fs.validateNotSymlink(path); err != nil {
		file.Close()
		return nil, err
	}

	return file, nil
}

// Write writes data to the file at the given path
func (fs *filesystemBackend) Write(ctx context.Context, path string, data io.Reader) error {
	if fs.readOnly {
		return fmt.Errorf("write operation not allowed on read-only filesystem")
	}

	// Validate path is within root
	if err := fs.validatePath(path); err != nil {
		return err
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Create/open file for writing
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer file.Close()

	// Copy data to file
	_, err = io.Copy(file, data)
	if err != nil {
		return fmt.Errorf("failed to write data to file %s: %w", path, err)
	}

	return nil
}

// List returns a list of files in the directory
func (fs *filesystemBackend) List(ctx context.Context, path string) ([]FileInfo, error) {
	// Validate path is within root
	if err := fs.validatePath(path); err != nil {
		return nil, err
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Open directory
	entries, err := os.ReadDir(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("directory not found: %s", path)
		}
		if os.IsPermission(err) {
			return nil, fmt.Errorf("permission denied: %s", path)
		}
		return nil, fmt.Errorf("failed to read directory %s: %w", path, err)
	}

	// Convert to FileInfo slice
	var files []FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue // Skip entries we can't stat
		}

		fileInfo := FileInfo{
			Name:    entry.Name(),
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().Format(time.RFC3339),
			IsDir:   entry.IsDir(),
		}
		files = append(files, fileInfo)
	}

	return files, nil
}

// Stat returns file information
func (fs *filesystemBackend) Stat(ctx context.Context, path string) (*FileInfo, error) {
	// Validate path is within root
	if err := fs.validatePath(path); err != nil {
		return nil, err
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Get file info
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		if os.IsPermission(err) {
			return nil, fmt.Errorf("permission denied: %s", path)
		}
		return nil, fmt.Errorf("failed to stat file %s: %w", path, err)
	}

	fileInfo := &FileInfo{
		Name:    info.Name(),
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime().Format(time.RFC3339),
		IsDir:   info.IsDir(),
	}

	return fileInfo, nil
}

// validatePath ensures the path is within the root directory
func (fs *filesystemBackend) validatePath(path string) error {
	// Get absolute paths
	absRoot, err := filepath.Abs(fs.rootPath)
	if err != nil {
		return fmt.Errorf("failed to resolve root path: %w", err)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Ensure path is within root
	if !strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) && absPath != absRoot {
		return fmt.Errorf("path outside root directory: %s", path)
	}

	return nil
}

// validateNotSymlink ensures the path is not a symlink
func (fs *filesystemBackend) validateNotSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("failed to lstat file: %w", err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlinks not allowed: %s", path)
	}

	return nil
}

// setReadOnlyMount attempts to set read-only mount flags (Linux-specific)
func (fs *filesystemBackend) setReadOnlyMount() error {
	if !fs.readOnly {
		return nil
	}

	// This would require root privileges and is typically done at the container/mount level
	// For demonstration, we'll use syscall.Mount with MS_RDONLY flag
	// In practice, this should be handled by the container runtime or init system

	// Note: This is a placeholder - actual implementation would require careful
	// consideration of mount namespaces and privileges
	// The syscall constants are Linux-specific and not available on all platforms
	return fmt.Errorf("read-only mount enforcement should be handled at container/mount level")
}

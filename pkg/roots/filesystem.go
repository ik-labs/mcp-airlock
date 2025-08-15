package roots

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// Error types for better test robustness
var (
	ErrReadOnlyFilesystem = errors.New("write operation not allowed on read-only filesystem")
	ErrPathTraversal      = errors.New("path traversal attempt detected")
	ErrSymlinkDetected    = errors.New("symlink detected in path")
)

// filesystemBackend implements Backend for local filesystem
type filesystemBackend struct {
	rootPath     string
	readOnly     bool
	mountLevelRO bool // R4.2: Mount-level read-only enforcement
	logger       *zap.Logger
}

// NewFilesystemBackend creates a new filesystem backend
func NewFilesystemBackend(rootPath string, readOnly bool, logger *zap.Logger) Backend {
	return &filesystemBackend{
		rootPath:     rootPath,
		readOnly:     readOnly,
		mountLevelRO: readOnly, // R4.2: Enable mount-level enforcement for read-only roots
		logger:       logger,
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

	// Reject symlinks first
	if err := fs.validateNotSymlink(path); err != nil {
		return nil, err
	}
	// Now open file for reading (no-follow on Linux)
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
	// R4.2: Mount-level read-only enforcement
	if fs.readOnly || fs.mountLevelRO {
		return fmt.Errorf("%w (mount-level enforcement)", ErrReadOnlyFilesystem)
	}

	// Validate path is within root and follows security constraints
	if err := fs.validatePath(path); err != nil {
		return err
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Validate target path is not a symlink before writing (only if it exists)
	if _, err := os.Lstat(path); err == nil {
		if err := fs.validateNotSymlink(path); err != nil {
			return err
		}
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Create/open file for writing with symlink protection
	file, err := fs.createFileSecure(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			fs.logger.Error("Failed to close file", zap.String("path", path), zap.Error(closeErr))
		}
	}()

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
	// R4.2: Use filepath.Clean to normalize path first
	cleanPath := filepath.Clean(path)

	// R4.2: Deny any path component that exactly equals ".." after cleaning
	pathComponents := strings.Split(cleanPath, string(filepath.Separator))
	for _, component := range pathComponents {
		if component == ".." {
			return fmt.Errorf("%w after cleaning: %s", ErrPathTraversal, path)
		}
	}

	// Get absolute paths
	absRoot, err := filepath.Abs(fs.rootPath)
	if err != nil {
		return fmt.Errorf("failed to resolve root path: %w", err)
	}

	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Ensure path is within root before symlink resolution
	if !strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) && absPath != absRoot {
		return fmt.Errorf("path outside root directory: %s", path)
	}

	// R4.2: Enhanced path sandboxing - deny symlinks in path components within root
	if err := fs.checkSymlinksInPathSandboxed(absPath, absRoot); err != nil {
		return err
	}

	// Resolve symlinks to detect symlink-based escapes
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return fmt.Errorf("failed to resolve root symlinks: %w", err)
	}

	// Check for symlinks in the path by walking up the directory tree
	return fs.checkSymlinksInPath(absPath, resolvedRoot)
}

// checkSymlinksInPath checks for symlinks in the path and all parent directories
func (fs *filesystemBackend) checkSymlinksInPath(absPath, resolvedRoot string) error {
	// Check each component of the path for symlinks, but only within our control
	currentPath := absPath
	for strings.HasPrefix(currentPath, resolvedRoot) && currentPath != resolvedRoot {
		if info, err := os.Lstat(currentPath); err == nil {
			// If it's a symlink, check where it points
			if info.Mode()&os.ModeSymlink != 0 {
				// Try to resolve the symlink
				resolvedPath, err := filepath.EvalSymlinks(currentPath)
				if err != nil {
					// If we can't resolve it (e.g., broken symlink), check the target manually
					target, readErr := os.Readlink(currentPath)
					if readErr != nil {
						return fmt.Errorf("failed to read symlink: %w", readErr)
					}

					// If target is absolute, it's definitely outside our control
					if filepath.IsAbs(target) {
						return fmt.Errorf("symlink points to absolute path outside root: %s -> %s", currentPath, target)
					}

					// Resolve relative target against the symlink's directory
					symlinkDir := filepath.Dir(currentPath)
					targetPath := filepath.Join(symlinkDir, target)
					targetPath, err = filepath.Abs(targetPath)
					if err != nil {
						return fmt.Errorf("failed to resolve symlink target: %w", err)
					}

					// Check if the target would be outside the root
					if !strings.HasPrefix(targetPath, resolvedRoot+string(filepath.Separator)) && targetPath != resolvedRoot {
						return fmt.Errorf("symlink escape detected: path %s points to %s outside root %s", currentPath, targetPath, resolvedRoot)
					}
				} else {
					// Successfully resolved symlink, check if it's within root
					if !strings.HasPrefix(resolvedPath, resolvedRoot+string(filepath.Separator)) && resolvedPath != resolvedRoot {
						return fmt.Errorf("symlink escape detected: path %s resolves to %s outside root %s", currentPath, resolvedPath, resolvedRoot)
					}
				}
			}
		}

		// Move up to parent directory
		parentPath := filepath.Dir(currentPath)
		if parentPath == currentPath {
			break // Reached root
		}
		currentPath = parentPath
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

// checkSymlinksInPathSandboxed performs R4.2 path sandboxing - deny symlinks within root
func (fs *filesystemBackend) checkSymlinksInPathSandboxed(absPath, absRoot string) error {
	// Walk through each component of the path to check for symlinks
	currentPath := absPath
	for strings.HasPrefix(currentPath, absRoot) && currentPath != absRoot {
		if info, err := os.Lstat(currentPath); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w (denied by sandboxing): %s", ErrSymlinkDetected, currentPath)
			}
		}

		// Move to parent directory
		parentPath := filepath.Dir(currentPath)
		if parentPath == currentPath {
			break // Reached root
		}
		currentPath = parentPath
	}

	return nil
}

// createFileSecure creates a file with symlink protection
func (fs *filesystemBackend) createFileSecure(path string) (*os.File, error) {
	// On Linux, use O_NOFOLLOW to prevent following symlinks
	if runtime.GOOS == "linux" {
		return os.OpenFile(path, syscall.O_NOFOLLOW|os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	}

	// On other platforms, validate no symlink exists if file exists
	if _, err := os.Lstat(path); err == nil {
		if err := fs.validateNotSymlink(path); err != nil {
			return nil, err
		}
	}

	return os.Create(path)
}

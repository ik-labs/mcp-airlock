package roots

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// RootMapper handles virtual URI to real path mapping with security controls
type RootMapper interface {
	MapURI(ctx context.Context, virtualURI string, tenant string) (*MappedResource, error)
	ValidateAccess(ctx context.Context, resource *MappedResource, operation string) error
	StreamResource(ctx context.Context, resource *MappedResource) (io.ReadCloser, error)
}

// MappedResource represents a mapped virtual resource
type MappedResource struct {
	VirtualURI string            `json:"virtual_uri"`
	RealPath   string            `json:"real_path"`
	Type       string            `json:"type"` // "fs", "s3"
	ReadOnly   bool              `json:"read_only"`
	Metadata   map[string]string `json:"metadata"`
	Backend    Backend           `json:"-"`
}

// Backend interface for different storage types
type Backend interface {
	Read(ctx context.Context, path string) (io.ReadCloser, error)
	Write(ctx context.Context, path string, data io.Reader) error
	List(ctx context.Context, path string) ([]FileInfo, error)
	Stat(ctx context.Context, path string) (*FileInfo, error)
}

// FileInfo represents file metadata
type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
	IsDir   bool   `json:"is_dir"`
}

// RootConfig represents a virtual root configuration
type RootConfig struct {
	Name     string            `yaml:"name"`
	Type     string            `yaml:"type"` // "fs", "s3"
	Virtual  string            `yaml:"virtual"`
	Real     string            `yaml:"real"`
	ReadOnly bool              `yaml:"read_only"`
	Metadata map[string]string `yaml:"metadata,omitempty"`
}

// rootMapper implements RootMapper interface
type rootMapper struct {
	roots    map[string]*RootConfig
	backends map[string]Backend
	mu       sync.RWMutex
}

// NewRootMapper creates a new RootMapper instance
func NewRootMapper(configs []RootConfig, s3Client S3Client) (RootMapper, error) {
	rm := &rootMapper{
		roots:    make(map[string]*RootConfig),
		backends: make(map[string]Backend),
	}

	for _, config := range configs {
		// Validate configuration
		if err := rm.validateConfig(&config); err != nil {
			return nil, fmt.Errorf("invalid root config %s: %w", config.Name, err)
		}

		// Normalize virtual root key for consistent comparison
		normalizedVirtual := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(config.Virtual, "/")))

		// Check for duplicate virtual roots using normalized key
		for existingVirtual := range rm.roots {
			existingNormalized := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(existingVirtual, "/")))
			if normalizedVirtual == existingNormalized {
				return nil, fmt.Errorf("duplicate virtual root: %s conflicts with existing %s", config.Virtual, existingVirtual)
			}
		}

		rm.roots[config.Virtual] = &config

		// Create appropriate backend
		switch config.Type {
		case "fs":
			rm.backends[config.Virtual] = NewFilesystemBackend(config.Real, config.ReadOnly)
		case "s3":
			if s3Client == nil {
				return nil, fmt.Errorf("S3 client required for S3 backend %s", config.Name)
			}
			rm.backends[config.Virtual] = NewS3Backend(s3Client, config.Real, config.ReadOnly)
		default:
			return nil, fmt.Errorf("unsupported backend type: %s", config.Type)
		}
	}

	return rm, nil
}

// MapURI maps a virtual URI to a real resource with security validation
func (rm *rootMapper) MapURI(ctx context.Context, virtualURI string, tenant string) (*MappedResource, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Parse and validate URI
	parsedURI, err := url.Parse(virtualURI)
	if err != nil {
		return nil, fmt.Errorf("invalid URI format: %w", err)
	}

	// Validate URI scheme whitelist (R19.1, R19.2)
	if err := rm.validateURIScheme(parsedURI); err != nil {
		return nil, fmt.Errorf("URI scheme validation failed: %w", err)
	}

	// Find matching root configuration
	var rootConfig *RootConfig
	var relativePath string

	for virtualRoot, config := range rm.roots {
		if strings.HasPrefix(virtualURI, virtualRoot) {
			rootConfig = config
			// Extract relative path after the virtual root
			relativePath = strings.TrimPrefix(virtualURI, virtualRoot)
			relativePath = strings.TrimPrefix(relativePath, "/")
			break
		}
	}

	if rootConfig == nil {
		return nil, fmt.Errorf("no root mapping found for URI: %s", virtualURI)
	}

	// Validate and clean the path
	cleanPath, err := rm.validatePath(relativePath, rootConfig.Real)
	if err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}

	// Create mapped resource
	resource := &MappedResource{
		VirtualURI: virtualURI,
		RealPath:   cleanPath,
		Type:       rootConfig.Type,
		ReadOnly:   rootConfig.ReadOnly,
		Metadata:   rootConfig.Metadata,
		Backend:    rm.backends[rootConfig.Virtual],
	}

	return resource, nil
}

// ValidateAccess validates if an operation is allowed on a resource
func (rm *rootMapper) ValidateAccess(ctx context.Context, resource *MappedResource, operation string) error {
	// Check read-only enforcement
	if resource.ReadOnly && isWriteOperation(operation) {
		return fmt.Errorf("write operation %s not allowed on read-only resource", operation)
	}

	// Additional validation can be added here (e.g., tenant-specific checks)
	return nil
}

// StreamResource returns a streaming reader for the resource
func (rm *rootMapper) StreamResource(ctx context.Context, resource *MappedResource) (io.ReadCloser, error) {
	if resource.Backend == nil {
		return nil, fmt.Errorf("no backend available for resource")
	}

	return resource.Backend.Read(ctx, resource.RealPath)
}

// validatePath performs comprehensive path validation and sanitization
func (rm *rootMapper) validatePath(relativePath, realRoot string) (string, error) {
	// Reject absolute paths before cleaning
	if filepath.IsAbs(relativePath) {
		return "", fmt.Errorf("absolute paths not allowed: %s", relativePath)
	}

	// Reject paths starting with / or \ (Windows)
	if strings.HasPrefix(relativePath, "/") || strings.HasPrefix(relativePath, "\\") {
		return "", fmt.Errorf("absolute paths not allowed: %s", relativePath)
	}

	// Clean the path to resolve . and .. elements
	cleaned := filepath.Clean(relativePath)

	// Reject paths containing .. after cleaning
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("path traversal attempt detected: %s", relativePath)
	}

	// Additional check for paths that start with .. after cleaning
	if strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("path traversal attempt detected: %s", relativePath)
	}

	// Build the real path - handle S3 URIs differently
	var realPath string
	if strings.HasPrefix(realRoot, "s3://") {
		// For S3 URIs, don't use filepath.Join as it corrupts the URI
		if cleaned == "." || cleaned == "" {
			realPath = realRoot
		} else {
			// Ensure proper S3 path construction
			realPath = strings.TrimSuffix(realRoot, "/") + "/" + cleaned
		}

		// For S3 URIs, we can't use filepath.Abs, so just return the constructed path
		// The S3 backend will handle its own validation
		return realPath, nil
	}

	// For filesystem paths, use standard path handling
	realPath = filepath.Join(realRoot, cleaned)

	// Ensure the resolved path is still within the root directory
	absRoot, err := filepath.Abs(realRoot)
	if err != nil {
		return "", fmt.Errorf("failed to resolve root path: %w", err)
	}

	absReal, err := filepath.Abs(realPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve real path: %w", err)
	}

	// Check if the resolved path is within the root
	if !strings.HasPrefix(absReal, absRoot+string(filepath.Separator)) && absReal != absRoot {
		return "", fmt.Errorf("path escape attempt detected: %s", relativePath)
	}

	// Optional: Use openat2 on Linux for additional security
	if runtime.GOOS == "linux" {
		return rm.openat2Resolve(absRoot, cleaned)
	}

	return absReal, nil
}

// openat2Resolve uses Linux openat2 syscall for secure path resolution
func (rm *rootMapper) openat2Resolve(rootPath, relativePath string) (string, error) {
	// This is a placeholder for openat2 implementation
	// In a real implementation, you would use syscall.Syscall6 with SYS_OPENAT2
	// For now, we'll fall back to the standard validation
	return filepath.Join(rootPath, relativePath), nil
}

// validateConfig validates a root configuration
func (rm *rootMapper) validateConfig(config *RootConfig) error {
	if config.Name == "" {
		return fmt.Errorf("root name cannot be empty")
	}

	if config.Virtual == "" {
		return fmt.Errorf("virtual path cannot be empty")
	}

	if config.Real == "" {
		return fmt.Errorf("real path cannot be empty")
	}

	if config.Type != "fs" && config.Type != "s3" {
		return fmt.Errorf("unsupported type: %s", config.Type)
	}

	// Validate virtual URI format
	if _, err := url.Parse(config.Virtual); err != nil {
		return fmt.Errorf("invalid virtual URI: %w", err)
	}

	return nil
}

// validateURIScheme validates that the URI uses only allowed schemes (R19.1, R19.2)
func (rm *rootMapper) validateURIScheme(parsedURI *url.URL) error {
	// Define allowed schemes - only mcp:// with specific paths
	allowedSchemes := map[string]bool{
		"mcp": true,
	}

	// Check if scheme is allowed
	if !allowedSchemes[parsedURI.Scheme] {
		return fmt.Errorf("unauthorized scheme '%s': only mcp:// schemes are allowed", parsedURI.Scheme)
	}

	// For mcp:// scheme, validate against configured virtual roots
	if parsedURI.Scheme == "mcp" {
		// Reconstruct the full URI path for validation
		fullURI := parsedURI.Scheme + "://" + parsedURI.Host + parsedURI.Path

		// Check if the URI matches any configured virtual root
		allowed := false
		for virtualRoot := range rm.roots {
			if strings.HasPrefix(fullURI, virtualRoot) {
				allowed = true
				break
			}
		}

		if !allowed {
			// Get list of configured virtual roots for error message
			var configuredRoots []string
			for virtualRoot := range rm.roots {
				configuredRoots = append(configuredRoots, virtualRoot)
			}
			return fmt.Errorf("unauthorized mcp:// path '%s': only configured virtual roots are allowed: %v", fullURI, configuredRoots)
		}
	}

	return nil
}

// isWriteOperation determines if an operation is a write operation
func isWriteOperation(operation string) bool {
	writeOps := []string{"write", "create", "update", "delete", "mkdir", "rmdir"}
	for _, op := range writeOps {
		if strings.EqualFold(operation, op) {
			return true
		}
	}
	return false
}

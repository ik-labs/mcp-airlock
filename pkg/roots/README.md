# Root Virtualization Package

This package implements virtual root mapping with comprehensive security controls for the MCP Airlock gateway. It provides secure, policy-enforced access to filesystem and S3 resources through virtual URI schemes.

## Features

- **Virtual URI Mapping**: Maps virtual URIs (e.g., `mcp://repo/file.txt`) to real filesystem or S3 paths
- **Path Security**: Comprehensive path traversal prevention using `filepath.Clean` and validation
- **Symlink Protection**: Denies access to symbolic links for security
- **Read-Only Enforcement**: Mount-level and path-based read-only enforcement
- **Zero-Copy Streaming**: Efficient streaming for large files using `io.Reader`
- **Multiple Backends**: Support for filesystem and S3 storage backends
- **Property-Based Testing**: Extensive testing using `testing/quick` for path traversal prevention

## Architecture

### Core Components

1. **RootMapper**: Main interface for virtual URI mapping and access validation
2. **Backend Interface**: Abstraction for different storage types (filesystem, S3)
3. **FilesystemBackend**: Local filesystem access with security controls
4. **S3Backend**: AWS S3 access with prefix-based isolation
5. **Security Validation**: Comprehensive path validation and sanitization

### Security Features

- **Path Traversal Prevention**: Blocks `../`, absolute paths, and other traversal attempts
- **Symlink Denial**: Rejects symbolic links to prevent privilege escalation
- **Symlink Escape Detection**: Resolves symlinks to detect escapes via nested symlinks
- **Write-Through Symlink Prevention**: Blocks writing through symlinks that could escape root
- **Linux O_NOFOLLOW Support**: Uses `O_NOFOLLOW` flag on Linux to prevent symlink following during file creation
- **Root Containment**: Ensures all paths remain within configured root directories
- **URI Validation**: Validates virtual URI format and schemes
- **Read-Only Enforcement**: Prevents write operations on read-only resources

## Usage

### Basic Setup

```go
import "github.com/ik-labs/mcp-airlock/pkg/roots"

// Configure virtual roots
configs := []roots.RootConfig{
    {
        Name:     "docs",
        Type:     "fs",
        Virtual:  "mcp://docs/",
        Real:     "/var/docs",
        ReadOnly: true,
    },
    {
        Name:     "artifacts",
        Type:     "s3",
        Virtual:  "mcp://artifacts/",
        Real:     "s3://my-bucket/artifacts/",
        ReadOnly: false,
    },
}

// Create root mapper
mapper, err := roots.NewRootMapper(configs, s3Client)
if err != nil {
    log.Fatal(err)
}
```

### Virtual URI Mapping

```go
// Map virtual URI to real resource
resource, err := mapper.MapURI(ctx, "mcp://docs/readme.txt", "tenant1")
if err != nil {
    log.Printf("Mapping failed: %v", err)
    return
}

fmt.Printf("Virtual: %s -> Real: %s\n", resource.VirtualURI, resource.RealPath)
```

### Access Validation

```go
// Validate read access
err = mapper.ValidateAccess(ctx, resource, "read")
if err != nil {
    log.Printf("Read access denied: %v", err)
}

// Validate write access
err = mapper.ValidateAccess(ctx, resource, "write")
if err != nil {
    log.Printf("Write access denied: %v", err)
}
```

### Streaming Resources

```go
// Stream resource content
reader, err := mapper.StreamResource(ctx, resource)
if err != nil {
    log.Printf("Stream failed: %v", err)
    return
}
defer reader.Close()

// Copy to destination with zero-copy streaming
_, err = io.Copy(destination, reader)
```

## Configuration

The package validates configurations to prevent common issues:

- **Duplicate Virtual Roots**: Prevents silent overwrites by enforcing unique virtual root keys
- **Backend Type Validation**: Ensures only supported backend types are used
- **URI Format Validation**: Validates virtual URI format and schemes
- **S3 URI Handling**: Properly handles S3 URIs without corrupting them with filesystem path operations

### Filesystem Backend

```yaml
roots:
  - name: "repo-readonly"
    type: "fs"
    virtual: "mcp://repo/"
    real: "/var/airlock/mounts/repo"
    read_only: true
    metadata:
      description: "Read-only repository access"
```

### S3 Backend

```yaml
roots:
  - name: "artifacts"
    type: "s3"
    virtual: "mcp://artifacts/"
    real: "s3://airlock-artifacts/tenant-data/"
    read_only: false
    metadata:
      region: "us-west-2"
      encryption: "AES256"
```

## Security Considerations

### Path Traversal Prevention

The package implements multiple layers of path traversal prevention:

1. **Pre-validation**: Rejects absolute paths and paths starting with `/` or `\`
2. **Path Cleaning**: Uses `filepath.Clean` to resolve `.` and `..` elements
3. **Post-validation**: Checks for remaining `..` sequences after cleaning
4. **Root Containment**: Ensures resolved paths remain within the configured root
5. **Symlink Denial**: Rejects symbolic links using `os.Lstat`
6. **Symlink Resolution**: Uses `filepath.EvalSymlinks` to detect symlink-based escapes
7. **Write Protection**: Validates target paths before writing to prevent symlink attacks

### Read-Only Enforcement

Read-only enforcement is implemented at multiple levels:

1. **Configuration Level**: Read-only flag in root configuration
2. **Operation Level**: Write operations are blocked for read-only resources
3. **Mount Level**: Container-level read-only mount enforcement (recommended)
4. **Path Level**: Path-based sandboxing with `filepath.Clean`

### S3 Security

S3 backend security features:

1. **Prefix Isolation**: All operations are scoped to configured S3 prefix
2. **Key Validation**: S3 keys are validated for length and invalid characters
3. **Path Traversal**: Same path traversal prevention as filesystem backend
4. **Read-Only Mode**: Configurable read-only mode for S3 buckets

## Testing

The package includes comprehensive tests:

- **Unit Tests**: Test individual components and functions
- **Integration Tests**: Test component interactions
- **Property-Based Tests**: Use `testing/quick` for path traversal prevention
- **Security Tests**: Test specific attack patterns and edge cases
- **Performance Tests**: Benchmark critical paths

### Running Tests

```bash
# Run all tests
go test ./pkg/roots/... -v

# Run property-based tests
go test ./pkg/roots/... -v -run "Property"

# Run security tests
go test ./pkg/roots/... -v -run "PathTraversal"

# Run with race detection
go test ./pkg/roots/... -v -race
```

## Performance

The package is optimized for performance:

- **Zero-Copy Streaming**: Uses `io.Reader` for efficient large file handling
- **Path Caching**: Validated paths can be cached at higher levels
- **Minimal Allocations**: Reuses buffers and avoids unnecessary allocations
- **Concurrent Safe**: All operations are safe for concurrent use

## Requirements Satisfied

This implementation satisfies the following requirements:

- **R4.1**: Virtual root mapping for MCP resources
- **R4.3**: Path traversal attack prevention
- **R4.4**: Virtual URI to real location mapping
- **R4.5**: Multiple root type support (filesystem, S3)

## Recent Improvements

### Bug Fixes

- **Duplicate Virtual Root Prevention**: Added validation to prevent silent overwrites when multiple configurations use the same virtual root key
- **S3 URI Path Construction**: Fixed issue where `filepath.Join` was corrupting S3 URIs (e.g., `s3://bucket/prefix` becoming `s3:/bucket/prefix`)
- **S3 List Security Gap**: Fixed missing path validation in S3 List method that could allow malicious paths to bypass security checks
- **Enhanced Symlink Security**: Improved symlink detection and prevention in write operations
- **Cross-Platform Compatibility**: Better handling of platform-specific path behaviors

### Security Enhancements

- **Write-Through Symlink Protection**: Prevents writing through symlinks that could escape the root directory
- **Linux O_NOFOLLOW Support**: Uses `O_NOFOLLOW` flag on Linux for additional symlink protection
- **Nested Symlink Detection**: Detects and prevents complex symlink escape chains
- **Comprehensive Path Validation**: Multi-layer validation with symlink resolution
- **Consistent S3 Security**: All S3 backend methods now have consistent path validation before key construction
- **Pre-Build Validation**: Path validation occurs before S3 key construction to catch absolute paths before they're trimmed

## Future Enhancements

Potential future enhancements:

1. **openat2 Support**: Linux-specific `openat2` syscall for additional security
2. **Additional Backends**: Support for other storage backends (Azure Blob, GCS)
3. **Caching Layer**: Add caching for frequently accessed resources
4. **Metrics**: Add performance and security metrics
5. **Audit Integration**: Integration with audit logging system
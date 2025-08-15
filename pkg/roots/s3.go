package roots

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"go.uber.org/zap"
)

// Error types for better test robustness
var (
	ErrReadOnlyS3Backend = errors.New("write operation not allowed on read-only S3 backend")
)

// S3Client interface for S3 operations (allows mocking)
type S3Client interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

// s3Backend implements Backend for AWS S3
type s3Backend struct {
	client             S3Client
	bucket             string
	prefix             string
	readOnly           bool
	allowedWritePrefix string // For R19.4: single allow-listed artifacts prefix
	logger             *zap.Logger
}

// NewS3Backend creates a new S3 backend
func NewS3Backend(client S3Client, s3URI string, readOnly bool, logger *zap.Logger) Backend {
	// Parse S3 URI (s3://bucket/prefix/)
	uri := strings.TrimPrefix(s3URI, "s3://")
	parts := strings.SplitN(uri, "/", 2)

	bucket := parts[0]
	prefix := ""
	if len(parts) > 1 {
		prefix = strings.TrimSuffix(parts[1], "/")
	}

	// For R19.4: S3 roots start read-only except for artifacts prefix
	allowedWritePrefix := ""
	effectiveReadOnly := readOnly

	// If prefix contains "artifacts", allow writes to this prefix
	if strings.Contains(prefix, "artifacts") {
		allowedWritePrefix = prefix
	}
	// Note: R19.4 enforcement is implemented in validateWriteAccess method

	return &s3Backend{
		client:             client,
		bucket:             bucket,
		prefix:             prefix,
		readOnly:           effectiveReadOnly,
		allowedWritePrefix: allowedWritePrefix,
		logger:             logger,
	}
}

// Read returns a reader for the S3 object
func (s3b *s3Backend) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	// Validate path before building key
	if err := s3b.validatePath(path); err != nil {
		return nil, err
	}

	key := s3b.buildKey(path)

	// Validate key format
	if err := s3b.validateKey(key); err != nil {
		return nil, err
	}

	// Get object from S3
	result, err := s3b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s3b.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "NotFound") {
			return nil, fmt.Errorf("object not found: s3://%s/%s", s3b.bucket, key)
		}
		return nil, fmt.Errorf("failed to get S3 object s3://%s/%s: %w", s3b.bucket, key, err)
	}

	return result.Body, nil
}

// Write uploads data to S3
func (s3b *s3Backend) Write(ctx context.Context, path string, data io.Reader) error {
	// Validate path before building key
	if err := s3b.validatePath(path); err != nil {
		return err
	}

	key := s3b.buildKey(path)

	// Validate key format
	if err := s3b.validateKey(key); err != nil {
		return err
	}

	// R19.4: Check read-only enforcement with artifacts prefix exception
	if err := s3b.validateWriteAccess(key); err != nil {
		return err
	}

	// Upload to S3
	_, err := s3b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s3b.bucket),
		Key:    aws.String(key),
		Body:   data,
	})
	if err != nil {
		return fmt.Errorf("failed to put S3 object s3://%s/%s: %w", s3b.bucket, key, err)
	}

	return nil
}

// List returns a list of objects with the given prefix
func (s3b *s3Backend) List(ctx context.Context, path string) ([]FileInfo, error) {
	// Validate path before building key (to catch absolute paths before they're trimmed)
	if err := s3b.validatePath(path); err != nil {
		return nil, err
	}

	prefix := s3b.buildKey(path)

	// Validate final key format for additional security
	if err := s3b.validateKey(prefix); err != nil {
		return nil, err
	}

	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	// List objects with prefix
	result, err := s3b.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:    aws.String(s3b.bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"), // Only list immediate children
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 objects with prefix s3://%s/%s: %w", s3b.bucket, prefix, err)
	}

	var files []FileInfo

	// Add directories (common prefixes)
	for _, commonPrefix := range result.CommonPrefixes {
		if commonPrefix.Prefix == nil {
			continue
		}

		// Extract directory name
		dirPath := strings.TrimPrefix(*commonPrefix.Prefix, prefix)
		dirPath = strings.TrimSuffix(dirPath, "/")

		if dirPath != "" {
			files = append(files, FileInfo{
				Name:    dirPath,
				Size:    0,
				Mode:    "drwxr-xr-x",
				ModTime: time.Now().Format(time.RFC3339),
				IsDir:   true,
			})
		}
	}

	// Add files
	for _, obj := range result.Contents {
		if obj.Key == nil {
			continue
		}

		// Skip the prefix itself if it's listed as an object
		if *obj.Key == prefix {
			continue
		}

		// Extract file name
		fileName := strings.TrimPrefix(*obj.Key, prefix)

		if fileName != "" {
			size := int64(0)
			if obj.Size != nil {
				size = *obj.Size
			}

			modTime := time.Now().Format(time.RFC3339)
			if obj.LastModified != nil {
				modTime = obj.LastModified.Format(time.RFC3339)
			}

			files = append(files, FileInfo{
				Name:    fileName,
				Size:    size,
				Mode:    "-rw-r--r--",
				ModTime: modTime,
				IsDir:   false,
			})
		}
	}

	return files, nil
}

// Stat returns information about a specific S3 object
func (s3b *s3Backend) Stat(ctx context.Context, path string) (*FileInfo, error) {
	// Validate path before building key
	if err := s3b.validatePath(path); err != nil {
		return nil, err
	}

	key := s3b.buildKey(path)

	// Validate key format
	if err := s3b.validateKey(key); err != nil {
		return nil, err
	}

	// Head object to get metadata
	result, err := s3b.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s3b.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "NoSuchKey") {
			return nil, fmt.Errorf("object not found: s3://%s/%s", s3b.bucket, key)
		}
		return nil, fmt.Errorf("failed to head S3 object s3://%s/%s: %w", s3b.bucket, key, err)
	}

	size := int64(0)
	if result.ContentLength != nil {
		size = *result.ContentLength
	}

	modTime := time.Now().Format(time.RFC3339)
	if result.LastModified != nil {
		modTime = result.LastModified.Format(time.RFC3339)
	}

	// Extract file name from key
	fileName := key
	if s3b.prefix != "" {
		fileName = strings.TrimPrefix(key, s3b.prefix+"/")
	}

	return &FileInfo{
		Name:    fileName,
		Size:    size,
		Mode:    "-rw-r--r--",
		ModTime: modTime,
		IsDir:   false,
	}, nil
}

// validatePath validates the input path before key construction
func (s3b *s3Backend) validatePath(path string) error {
	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal attempt in S3 path: %s", path)
	}

	// Check for absolute paths (before buildKey trims them)
	if strings.HasPrefix(path, "/") {
		return fmt.Errorf("absolute paths not allowed in S3 path: %s", path)
	}

	// Check for invalid characters
	invalidChars := []string{"\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08", "\x09", "\x0A", "\x0B", "\x0C", "\x0D", "\x0E", "\x0F"}
	for _, char := range invalidChars {
		if strings.Contains(path, char) {
			return fmt.Errorf("invalid character in S3 path: %s", path)
		}
	}

	return nil
}

// buildKey constructs the S3 key from the path
func (s3b *s3Backend) buildKey(path string) string {
	// Remove leading slash if present
	path = strings.TrimPrefix(path, "/")

	if s3b.prefix == "" {
		return path
	}

	if path == "" {
		return s3b.prefix
	}

	return s3b.prefix + "/" + path
}

// validateWriteAccess validates write access based on read-only settings and allowed prefixes (R19.4)
func (s3b *s3Backend) validateWriteAccess(_ string) error {
	// R19.4: First check if this is an artifacts prefix that should allow writes
	if s3b.allowedWritePrefix != "" && strings.EqualFold(s3b.prefix, s3b.allowedWritePrefix) {
		// This is an artifacts backend with proper setup - allow writes even if readOnly is true
		return nil
	}

	// If backend is explicitly read-only and not an artifacts exception, deny writes
	if s3b.readOnly {
		return fmt.Errorf("%w", ErrReadOnlyS3Backend)
	}

	// R19.4: Apply additional restrictions for repo/artifacts prefixes
	if strings.Contains(strings.ToLower(s3b.prefix), "repo") {
		// Repo prefixes should be read-only by default
		return fmt.Errorf("%w (R19.4: repo prefix)", ErrReadOnlyS3Backend)
	}

	// For other backends (test backends, etc.), allow normal operation
	return nil
}

// validateKey validates the S3 key format and security
func (s3b *s3Backend) validateKey(key string) error {
	// Check for path traversal attempts
	if strings.Contains(key, "..") {
		return fmt.Errorf("path traversal attempt in S3 key: %s", key)
	}

	// Check for absolute paths
	if strings.HasPrefix(key, "/") {
		return fmt.Errorf("absolute paths not allowed in S3 key: %s", key)
	}

	// Validate key length (S3 limit is 1024 bytes)
	if len(key) > 1024 {
		return fmt.Errorf("S3 key too long: %d bytes (max 1024)", len(key))
	}

	// Check for invalid characters
	invalidChars := []string{"\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07", "\x08", "\x09", "\x0A", "\x0B", "\x0C", "\x0D", "\x0E", "\x0F"}
	for _, char := range invalidChars {
		if strings.Contains(key, char) {
			return fmt.Errorf("invalid character in S3 key: %s", key)
		}
	}

	return nil
}

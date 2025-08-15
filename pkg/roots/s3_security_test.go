package roots

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"go.uber.org/zap"
)

func TestS3Backend_ListSecurityValidation(t *testing.T) {
	mockClient := newMockS3Client()

	// Set up some test data
	testObjects := map[string][]byte{
		"test-prefix/file1.txt":      []byte("content1"),
		"test-prefix/file2.txt":      []byte("content2"),
		"test-prefix/dir1/file3.txt": []byte("content3"),
	}

	for key, content := range testObjects {
		mockClient.setObject(key, content)
	}

	backend := NewS3Backend(mockClient, "s3://test-bucket/test-prefix/", false, zap.NewNop())

	tests := []struct {
		name        string
		path        string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid path",
			path:        "dir1",
			expectError: false,
		},
		{
			name:        "empty path (root)",
			path:        "",
			expectError: false,
		},
		{
			name:        "path traversal attempt",
			path:        "../../../etc",
			expectError: true,
			errorMsg:    "path traversal attempt",
		},
		{
			name:        "absolute path attempt",
			path:        "/etc/passwd",
			expectError: true,
			errorMsg:    "absolute paths not allowed",
		},
		{
			name:        "key too long",
			path:        strings.Repeat("a", 1025), // Exceeds S3 key limit
			expectError: true,
			errorMsg:    "S3 key too long",
		},
		{
			name:        "key with null byte",
			path:        "test\x00file",
			expectError: true,
			errorMsg:    "invalid character",
		},
	}

	for _, tt := range tests {
		tt := tt // capture loop variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			files, err := backend.List(context.Background(), tt.path)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// For successful cases, verify we got some results
			if files == nil {
				t.Errorf("Expected file list but got nil")
			}
		})
	}
}

func TestS3Backend_SecurityConsistency(t *testing.T) {
	mockClient := newMockS3Client()
	backend := NewS3Backend(mockClient, "s3://test-bucket/test-prefix/", false, zap.NewNop())

	// Test paths that should be rejected by all methods
	maliciousPaths := []string{
		"../../../etc/passwd",
		"/etc/passwd",
		"test\x00file",
		string(make([]byte, 1025)), // Too long
	}

	for i, maliciousPath := range maliciousPaths {
		i, maliciousPath := i, maliciousPath // capture loop variables
		t.Run(fmt.Sprintf("malicious_path_case_%d", i), func(t *testing.T) {
			t.Parallel()
			// Test Read method
			_, readErr := backend.Read(context.Background(), maliciousPath)

			// Test List method
			_, listErr := backend.List(context.Background(), maliciousPath)

			// Test Stat method
			_, statErr := backend.Stat(context.Background(), maliciousPath)

			// All methods should reject the malicious path
			if readErr == nil {
				t.Errorf("Read method should have rejected malicious path: %s", maliciousPath)
			}

			if listErr == nil {
				t.Errorf("List method should have rejected malicious path: %s", maliciousPath)
			}

			if statErr == nil {
				t.Errorf("Stat method should have rejected malicious path: %s", maliciousPath)
			}

			// Verify all methods return similar error types for consistency
			if readErr != nil && listErr != nil && statErr != nil {
				// All should be validation errors, not S3 operation errors
				if contains(readErr.Error(), "failed to get S3 object") {
					t.Errorf("Read method should fail at validation, not S3 operation")
				}
				if contains(listErr.Error(), "failed to list S3 objects") {
					t.Errorf("List method should fail at validation, not S3 operation")
				}
				if contains(statErr.Error(), "failed to head S3 object") {
					t.Errorf("Stat method should fail at validation, not S3 operation")
				}
			}
		})
	}
}

func TestS3Backend_ListValidationBeforeS3Call(t *testing.T) {
	// Create a mock client that will track if S3 operations were called
	mockClient := &trackingMockS3Client{
		mockS3Client: newMockS3Client(),
		listCalled:   false,
	}

	backend := NewS3Backend(mockClient, "s3://test-bucket/test-prefix/", false, zap.NewNop())

	// Try to list with a malicious path
	_, err := backend.List(context.Background(), "../../../etc")

	// Should get an error
	if err == nil {
		t.Errorf("Expected error for malicious path")
	}

	// S3 ListObjectsV2 should NOT have been called
	if mockClient.listCalled {
		t.Errorf("S3 ListObjectsV2 was called despite validation failure - security bypass!")
	}
}

// trackingMockS3Client wraps mockS3Client to track method calls
type trackingMockS3Client struct {
	*mockS3Client
	listCalled bool
}

func (t *trackingMockS3Client) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	t.listCalled = true
	return t.mockS3Client.ListObjectsV2(ctx, params, optFns...)
}

// Helper function for string contains check
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

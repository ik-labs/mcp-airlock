package roots

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// mockS3Client implements a mock S3 client for testing
type mockS3Client struct {
	objects map[string][]byte
	errors  map[string]error
}

func newMockS3Client() *mockS3Client {
	return &mockS3Client{
		objects: make(map[string][]byte),
		errors:  make(map[string]error),
	}
}

func (m *mockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := *params.Key

	if err, exists := m.errors[key]; exists {
		return nil, err
	}

	content, exists := m.objects[key]
	if !exists {
		return nil, &types.NoSuchKey{
			Message: aws.String("The specified key does not exist."),
		}
	}

	return &s3.GetObjectOutput{
		Body: io.NopCloser(strings.NewReader(string(content))),
	}, nil
}

func (m *mockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	key := *params.Key

	if err, exists := m.errors[key]; exists {
		return nil, err
	}

	content, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}

	m.objects[key] = content

	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3Client) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	prefix := ""
	if params.Prefix != nil {
		prefix = *params.Prefix
	}

	delimiter := ""
	if params.Delimiter != nil {
		delimiter = *params.Delimiter
	}

	var contents []types.Object
	var commonPrefixes []types.CommonPrefix

	// Simple mock implementation
	for key, content := range m.objects {
		if strings.HasPrefix(key, prefix) {
			if delimiter != "" {
				// Handle delimiter logic for directory-like listing
				remaining := strings.TrimPrefix(key, prefix)
				if idx := strings.Index(remaining, delimiter); idx != -1 {
					// This is a "subdirectory"
					commonPrefix := prefix + remaining[:idx+1]
					found := false
					for _, cp := range commonPrefixes {
						if *cp.Prefix == commonPrefix {
							found = true
							break
						}
					}
					if !found {
						commonPrefixes = append(commonPrefixes, types.CommonPrefix{
							Prefix: aws.String(commonPrefix),
						})
					}
					continue
				}
			}

			contents = append(contents, types.Object{
				Key:  aws.String(key),
				Size: aws.Int64(int64(len(content))),
			})
		}
	}

	return &s3.ListObjectsV2Output{
		Contents:       contents,
		CommonPrefixes: commonPrefixes,
	}, nil
}

func (m *mockS3Client) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	key := *params.Key

	if err, exists := m.errors[key]; exists {
		return nil, err
	}

	content, exists := m.objects[key]
	if !exists {
		return nil, &types.NoSuchKey{
			Message: aws.String("The specified key does not exist."),
		}
	}

	return &s3.HeadObjectOutput{
		ContentLength: aws.Int64(int64(len(content))),
	}, nil
}

func (m *mockS3Client) setObject(key string, content []byte) {
	m.objects[key] = content
}

func (m *mockS3Client) setError(key string, err error) {
	m.errors[key] = err
}

func TestS3Backend_Read(t *testing.T) {
	mockClient := newMockS3Client()

	// Set up test data
	testKey := "test-prefix/test.txt"
	testContent := "Hello, S3!"
	mockClient.setObject(testKey, []byte(testContent))

	backend := NewS3Backend(mockClient, "s3://test-bucket/test-prefix/", false)

	tests := []struct {
		name            string
		path            string
		expectError     bool
		expectedContent string
	}{
		{
			name:            "read existing object",
			path:            "test.txt",
			expectError:     false,
			expectedContent: testContent,
		},
		{
			name:        "read non-existent object",
			path:        "nonexistent.txt",
			expectError: true,
		},
		{
			name:        "path traversal attempt",
			path:        "../../../etc/passwd",
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

func TestS3Backend_Write(t *testing.T) {
	mockClient := newMockS3Client()

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
			path:        "write_test.txt",
			content:     "test content",
			expectError: false,
		},
		{
			name:        "write to read-only backend",
			readOnly:    true,
			path:        "readonly_test.txt",
			content:     "test content",
			expectError: true,
		},
		{
			name:        "path traversal attempt",
			readOnly:    false,
			path:        "../../../etc/passwd",
			content:     "malicious content",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := NewS3Backend(mockClient, "s3://test-bucket/test-prefix/", tt.readOnly)

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

			// Verify object was written to mock client
			expectedKey := "test-prefix/" + tt.path
			if content, exists := mockClient.objects[expectedKey]; !exists {
				t.Errorf("Object not found in mock client: %s", expectedKey)
			} else if string(content) != tt.content {
				t.Errorf("Expected content %q, got %q", tt.content, string(content))
			}
		})
	}
}

func TestS3Backend_List(t *testing.T) {
	mockClient := newMockS3Client()

	// Set up test data
	testObjects := map[string][]byte{
		"test-prefix/file1.txt":      []byte("content1"),
		"test-prefix/file2.txt":      []byte("content2"),
		"test-prefix/dir1/file3.txt": []byte("content3"),
		"test-prefix/dir2/file4.txt": []byte("content4"),
	}

	for key, content := range testObjects {
		mockClient.setObject(key, content)
	}

	backend := NewS3Backend(mockClient, "s3://test-bucket/test-prefix/", false)

	files, err := backend.List(context.Background(), "")
	if err != nil {
		t.Fatalf("Failed to list objects: %v", err)
	}

	// Should find files and directories at the root level
	expectedFiles := []string{"file1.txt", "file2.txt"}
	expectedDirs := []string{"dir1", "dir2"}

	foundFiles := make(map[string]bool)
	foundDirs := make(map[string]bool)

	for _, file := range files {
		if file.IsDir {
			foundDirs[file.Name] = true
		} else {
			foundFiles[file.Name] = true
		}
	}

	for _, expectedFile := range expectedFiles {
		if !foundFiles[expectedFile] {
			t.Errorf("Expected file %s not found in listing", expectedFile)
		}
	}

	for _, expectedDir := range expectedDirs {
		if !foundDirs[expectedDir] {
			t.Errorf("Expected directory %s not found in listing", expectedDir)
		}
	}
}

func TestS3Backend_Stat(t *testing.T) {
	mockClient := newMockS3Client()

	// Set up test data
	testKey := "test-prefix/stat_test.txt"
	testContent := "test content for stat"
	mockClient.setObject(testKey, []byte(testContent))

	backend := NewS3Backend(mockClient, "s3://test-bucket/test-prefix/", false)

	tests := []struct {
		name         string
		path         string
		expectError  bool
		expectedSize int64
	}{
		{
			name:         "stat existing object",
			path:         "stat_test.txt",
			expectError:  false,
			expectedSize: int64(len(testContent)),
		},
		{
			name:        "stat non-existent object",
			path:        "nonexistent.txt",
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

func TestS3Backend_KeyValidation(t *testing.T) {
	mockClient := newMockS3Client()
	backend := NewS3Backend(mockClient, "s3://test-bucket/test-prefix/", false).(*s3Backend)

	tests := []struct {
		name        string
		key         string
		expectError bool
	}{
		{
			name:        "valid key",
			key:         "test-prefix/valid.txt",
			expectError: false,
		},
		{
			name:        "path traversal attempt",
			key:         "test-prefix/../../../etc/passwd",
			expectError: true,
		},
		{
			name:        "absolute path attempt",
			key:         "/etc/passwd",
			expectError: true,
		},
		{
			name:        "key too long",
			key:         strings.Repeat("a", 1025),
			expectError: true,
		},
		{
			name:        "key with null byte",
			key:         "test\x00file.txt",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := backend.validateKey(tt.key)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for key validation but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error for key validation: %v", err)
			}
		})
	}
}

func TestS3Backend_BuildKey(t *testing.T) {
	tests := []struct {
		name        string
		s3URI       string
		path        string
		expectedKey string
	}{
		{
			name:        "with prefix",
			s3URI:       "s3://bucket/prefix/",
			path:        "file.txt",
			expectedKey: "prefix/file.txt",
		},
		{
			name:        "without prefix",
			s3URI:       "s3://bucket/",
			path:        "file.txt",
			expectedKey: "file.txt",
		},
		{
			name:        "nested path",
			s3URI:       "s3://bucket/prefix/",
			path:        "dir/file.txt",
			expectedKey: "prefix/dir/file.txt",
		},
		{
			name:        "empty path",
			s3URI:       "s3://bucket/prefix/",
			path:        "",
			expectedKey: "prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockS3Client()
			backend := NewS3Backend(mockClient, tt.s3URI, false).(*s3Backend)

			key := backend.buildKey(tt.path)

			if key != tt.expectedKey {
				t.Errorf("Expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}

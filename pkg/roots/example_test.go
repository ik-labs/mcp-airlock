package roots

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// ExampleRootMapper demonstrates basic usage of the RootMapper
func ExampleRootMapper() {
	// Create root configurations
	configs := []RootConfig{
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

	// Create root mapper (nil S3 client for this example)
	mapper, err := NewRootMapper(configs, nil)
	if err != nil {
		fmt.Printf("Error creating mapper: %v\n", err)
		return
	}

	// Map a virtual URI to a real resource
	resource, err := mapper.MapURI(context.Background(), "mcp://docs/readme.txt", "tenant1")
	if err != nil {
		fmt.Printf("Error mapping URI: %v\n", err)
		return
	}

	fmt.Printf("Virtual URI: %s\n", resource.VirtualURI)
	fmt.Printf("Real Path: %s\n", resource.RealPath)
	fmt.Printf("Type: %s\n", resource.Type)
	fmt.Printf("Read Only: %t\n", resource.ReadOnly)

	// Validate access for different operations
	err = mapper.ValidateAccess(context.Background(), resource, "read")
	if err != nil {
		fmt.Printf("Read access denied: %v\n", err)
	} else {
		fmt.Println("Read access allowed")
	}

	err = mapper.ValidateAccess(context.Background(), resource, "write")
	if err != nil {
		fmt.Printf("Write access denied: %v\n", err)
	} else {
		fmt.Println("Write access allowed")
	}

	// Output:
	// Virtual URI: mcp://docs/readme.txt
	// Real Path: /var/docs/readme.txt
	// Type: fs
	// Read Only: true
	// Read access allowed
	// Write access denied: write operation write not allowed on read-only resource
}

// TestZeroCopyStreaming demonstrates zero-copy streaming capabilities
func TestZeroCopyStreaming(t *testing.T) {
	tempDir := t.TempDir()

	// Create test file
	testContent := "This is test content for streaming"
	testFile := tempDir + "/stream_test.txt"
	if err := writeTestFile(testFile, testContent); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create filesystem backend
	backend := NewFilesystemBackend(tempDir, false)

	// Stream the file content
	reader, err := backend.Read(context.Background(), testFile)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	defer reader.Close()

	// Read content in chunks to demonstrate streaming
	buffer := make([]byte, 8) // Small buffer to demonstrate streaming
	var result strings.Builder

	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			result.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Error reading stream: %v", err)
		}
	}

	if result.String() != testContent {
		t.Errorf("Expected content %q, got %q", testContent, result.String())
	}
}

// Helper function to write test files
func writeTestFile(path, content string) error {
	// Use os.WriteFile for test setup
	return os.WriteFile(path, []byte(content), 0644)
}

package roots

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap/zaptest"
)

func TestRootMiddleware_ProcessRequest(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create temporary directory for testing
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Configure root mapper
	rootConfigs := []RootConfig{
		{
			Name:     "test-repo",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     tempDir,
			ReadOnly: true,
		},
	}

	mapper, err := NewRootMapper(rootConfigs, nil)
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	middleware := NewRootMiddleware(mapper, logger)

	tests := []struct {
		name           string
		tenant         string
		request        map[string]interface{}
		expectError    bool
		expectModified bool
	}{
		{
			name:   "resource_read_request",
			tenant: "tenant1",
			request: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "resources/read",
				"params": map[string]interface{}{
					"uri": "mcp://repo/test.txt",
				},
			},
			expectModified: true,
		},
		{
			name:   "resource_list_request",
			tenant: "tenant1",
			request: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      2,
				"method":  "resources/list",
				"params": map[string]interface{}{
					"uri": "mcp://repo/",
				},
			},
			expectModified: false, // List requests are validated but not modified
		},
		{
			name:   "tool_call_with_resource",
			tenant: "tenant1",
			request: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      3,
				"method":  "tools/call",
				"params": map[string]interface{}{
					"name": "read_file",
					"arguments": map[string]interface{}{
						"file_path": "mcp://repo/test.txt",
						"encoding":  "utf-8",
					},
				},
			},
			expectModified: true,
		},
		{
			name:   "non_resource_request",
			tenant: "tenant1",
			request: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      4,
				"method":  "initialize",
				"params": map[string]interface{}{
					"protocolVersion": "2024-11-05",
				},
			},
			expectModified: false,
		},
		{
			name:   "unauthorized_resource",
			tenant: "tenant1",
			request: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      5,
				"method":  "resources/read",
				"params": map[string]interface{}{
					"uri": "mcp://unauthorized/secret.txt",
				},
			},
			expectError: true,
		},
		{
			name:   "write_to_readonly_resource",
			tenant: "tenant1",
			request: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      6,
				"method":  "resources/write",
				"params": map[string]interface{}{
					"uri":     "mcp://repo/new_file.txt",
					"content": "new content",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal request
			requestData, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}

			// Process request
			processedData, err := middleware.ProcessRequest(context.Background(), tt.tenant, requestData)

			if tt.expectError {
				// Check if error is returned or error response is generated
				if err == nil {
					// Check if processed data contains error response
					var response map[string]interface{}
					if jsonErr := json.Unmarshal(processedData, &response); jsonErr == nil {
						if _, hasError := response["error"]; !hasError {
							t.Error("Expected error response but got none")
						}
					} else {
						t.Error("Expected error but got none")
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Parse processed request
			var processedRequest map[string]interface{}
			if err := json.Unmarshal(processedData, &processedRequest); err != nil {
				t.Fatalf("Failed to unmarshal processed request: %v", err)
			}

			// Verify modification expectations
			if tt.expectModified {
				// Check if URI was mapped to real path
				if method, exists := processedRequest["method"]; exists {
					if methodStr, ok := method.(string); ok {
						if methodStr == "resources/read" {
							if params, exists := processedRequest["params"]; exists {
								if paramsMap, ok := params.(map[string]interface{}); ok {
									if uri, exists := paramsMap["uri"]; exists {
										if uriStr, ok := uri.(string); ok {
											if !filepath.IsAbs(uriStr) {
												t.Errorf("Expected URI to be mapped to absolute path, got: %s", uriStr)
											}
										}
									}
								}
							}
						} else if methodStr == "tools/call" {
							if params, exists := processedRequest["params"]; exists {
								if paramsMap, ok := params.(map[string]interface{}); ok {
									if args, exists := paramsMap["arguments"]; exists {
										if argsMap, ok := args.(map[string]interface{}); ok {
											if filePath, exists := argsMap["file_path"]; exists {
												if filePathStr, ok := filePath.(string); ok {
													if !filepath.IsAbs(filePathStr) {
														t.Errorf("Expected file_path to be mapped to absolute path, got: %s", filePathStr)
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			} else {
				// For non-modified requests, ensure they remain unchanged
				originalRequest := tt.request
				if processedRequest["method"] != originalRequest["method"] {
					t.Error("Non-resource request was unexpectedly modified")
				}
			}
		})
	}
}

func TestRootMiddleware_ProcessResponse(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create root mapper (not used directly in response processing but needed for middleware)
	rootConfigs := []RootConfig{
		{
			Name:     "test-repo",
			Type:     "fs",
			Virtual:  "mcp://repo/",
			Real:     "/tmp/test",
			ReadOnly: true,
		},
	}

	mapper, err := NewRootMapper(rootConfigs, nil)
	if err != nil {
		t.Fatalf("Failed to create root mapper: %v", err)
	}

	middleware := NewRootMiddleware(mapper, logger)

	tests := []struct {
		name     string
		tenant   string
		response map[string]interface{}
	}{
		{
			name:   "successful_response",
			tenant: "tenant1",
			response: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      1,
				"result": map[string]interface{}{
					"content": "file content",
					"uri":     "/tmp/test/file.txt",
				},
			},
		},
		{
			name:   "error_response",
			tenant: "tenant1",
			response: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      2,
				"error": map[string]interface{}{
					"code":    -32000,
					"message": "File not found",
				},
			},
		},
		{
			name:   "list_response",
			tenant: "tenant1",
			response: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      3,
				"result": map[string]interface{}{
					"resources": []interface{}{
						map[string]interface{}{
							"uri":  "/tmp/test/file1.txt",
							"name": "file1.txt",
						},
						map[string]interface{}{
							"uri":  "/tmp/test/file2.txt",
							"name": "file2.txt",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal response
			responseData, err := json.Marshal(tt.response)
			if err != nil {
				t.Fatalf("Failed to marshal response: %v", err)
			}

			// Process response
			processedData, err := middleware.ProcessResponse(context.Background(), tt.tenant, responseData)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Parse processed response
			var processedResponse map[string]interface{}
			if err := json.Unmarshal(processedData, &processedResponse); err != nil {
				t.Fatalf("Failed to unmarshal processed response: %v", err)
			}

			// Verify response structure is maintained
			if processedResponse["jsonrpc"] != tt.response["jsonrpc"] {
				t.Error("JSONRPC version was modified")
			}

			// Compare IDs with type conversion handling (JSON marshaling can change int to float64)
			originalID := tt.response["id"]
			processedID := processedResponse["id"]
			if !compareJSONValues(originalID, processedID) {
				t.Errorf("Request ID was modified: original=%v (%T), processed=%v (%T)",
					originalID, originalID, processedID, processedID)
			}

			// For error responses, ensure error is preserved
			if _, hasError := tt.response["error"]; hasError {
				if _, processedHasError := processedResponse["error"]; !processedHasError {
					t.Error("Error response was lost during processing")
				}
			}
		})
	}
}

func TestRootMiddleware_IsResourceRequest(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mapper, _ := NewRootMapper([]RootConfig{}, nil)
	middleware := NewRootMiddleware(mapper, logger)

	tests := []struct {
		method   string
		expected bool
	}{
		{"resources/list", true},
		{"resources/read", true},
		{"resources/subscribe", true},
		{"resources/unsubscribe", true},
		{"tools/call", true},
		{"initialize", false},
		{"ping", false},
		{"notifications/initialized", false},
		{"completion/complete", false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			result := middleware.isResourceRequest(tt.method)
			if result != tt.expected {
				t.Errorf("isResourceRequest(%s) = %v, expected %v", tt.method, result, tt.expected)
			}
		})
	}
}

func TestRootMiddleware_IsURIParameter(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mapper, _ := NewRootMapper([]RootConfig{}, nil)
	middleware := NewRootMiddleware(mapper, logger)

	tests := []struct {
		param    string
		expected bool
	}{
		{"uri", true},
		{"url", true},
		{"path", true},
		{"file", true},
		{"file_path", true},
		{"source_uri", true},
		{"target_path", true},
		{"input_file", true},
		{"output_location", true},
		{"name", false},
		{"encoding", false},
		{"format", false},
		{"timeout", false},
	}

	for _, tt := range tests {
		t.Run(tt.param, func(t *testing.T) {
			result := middleware.isURIParameter(tt.param)
			if result != tt.expected {
				t.Errorf("isURIParameter(%s) = %v, expected %v", tt.param, result, tt.expected)
			}
		})
	}
}

// compareJSONValues compares two values that may have been affected by JSON marshaling/unmarshaling
func compareJSONValues(a, b interface{}) bool {
	// Handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Handle numeric conversions (int to float64 during JSON processing)
	switch aVal := a.(type) {
	case int:
		if bFloat, ok := b.(float64); ok {
			return float64(aVal) == bFloat
		}
	case float64:
		if bInt, ok := b.(int); ok {
			return aVal == float64(bInt)
		}
	}

	// Default comparison
	return a == b
}

package roots

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// RootMiddleware provides root virtualization middleware for MCP requests
type RootMiddleware struct {
	mapper RootMapper
	logger *zap.Logger
}

// NewRootMiddleware creates a new root virtualization middleware
func NewRootMiddleware(mapper RootMapper, logger *zap.Logger) *RootMiddleware {
	return &RootMiddleware{
		mapper: mapper,
		logger: logger,
	}
}

// MCPRequest represents an MCP JSON-RPC request
type MCPRequest struct {
	ID      interface{} `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	JSONRPC string      `json:"jsonrpc"`
}

// MCPResponse represents an MCP JSON-RPC response
type MCPResponse struct {
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
	JSONRPC string      `json:"jsonrpc"`
}

// MCPError represents an MCP JSON-RPC error
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ProcessRequest processes an MCP request and applies root virtualization
func (rm *RootMiddleware) ProcessRequest(ctx context.Context, tenant string, requestData []byte) ([]byte, error) {
	start := time.Now()

	// Parse the MCP request
	var request MCPRequest
	if err := json.Unmarshal(requestData, &request); err != nil {
		rm.logger.Error("Failed to parse MCP request",
			zap.Error(err),
			zap.String("tenant", tenant))
		return rm.createErrorResponse(nil, -32700, "Parse error", nil)
	}

	correlationID := getCorrelationIDFromContext(ctx)

	rm.logger.Debug("Processing MCP request with root virtualization",
		zap.String("correlation_id", correlationID),
		zap.String("tenant", tenant),
		zap.String("method", request.Method),
		zap.Any("id", request.ID))

	// Check if this request involves resource access
	if rm.isResourceRequest(request.Method) {
		// Apply root virtualization to the request
		modifiedRequest, err := rm.virtualizeRequest(ctx, tenant, &request)
		if err != nil {
			rm.logger.Error("Root virtualization failed",
				zap.String("correlation_id", correlationID),
				zap.String("tenant", tenant),
				zap.String("method", request.Method),
				zap.Error(err))
			return rm.createErrorResponse(request.ID, -32000, "Root virtualization failed", map[string]interface{}{
				"reason":         err.Error(),
				"correlation_id": correlationID,
			})
		}

		// Marshal the modified request
		modifiedData, err := json.Marshal(modifiedRequest)
		if err != nil {
			rm.logger.Error("Failed to marshal modified request",
				zap.String("correlation_id", correlationID),
				zap.Error(err))
			return rm.createErrorResponse(request.ID, -32603, "Internal error", map[string]interface{}{
				"correlation_id": correlationID,
			})
		}

		duration := time.Since(start)
		rm.logger.Info("Root virtualization applied to request",
			zap.String("correlation_id", correlationID),
			zap.String("tenant", tenant),
			zap.String("method", request.Method),
			zap.Duration("duration", duration))

		return modifiedData, nil
	}

	// For non-resource requests, pass through unchanged
	rm.logger.Debug("Request does not involve resources, passing through",
		zap.String("correlation_id", correlationID),
		zap.String("method", request.Method))

	return requestData, nil
}

// ProcessResponse processes an MCP response and applies reverse root virtualization
func (rm *RootMiddleware) ProcessResponse(ctx context.Context, tenant string, responseData []byte) ([]byte, error) {
	start := time.Now()

	// Parse the MCP response
	var response MCPResponse
	if err := json.Unmarshal(responseData, &response); err != nil {
		rm.logger.Error("Failed to parse MCP response",
			zap.Error(err),
			zap.String("tenant", tenant))
		// Return original response if we can't parse it
		return responseData, nil
	}

	correlationID := getCorrelationIDFromContext(ctx)

	rm.logger.Debug("Processing MCP response with root virtualization",
		zap.String("correlation_id", correlationID),
		zap.String("tenant", tenant),
		zap.Any("id", response.ID))

	// Apply reverse virtualization to the response (convert real paths back to virtual URIs)
	modifiedResponse, err := rm.devirtualizeResponse(ctx, tenant, &response)
	if err != nil {
		rm.logger.Warn("Response devirtualization failed, returning original",
			zap.String("correlation_id", correlationID),
			zap.String("tenant", tenant),
			zap.Error(err))
		// Return original response on devirtualization failure
		return responseData, nil
	}

	// Marshal the modified response
	modifiedData, err := json.Marshal(modifiedResponse)
	if err != nil {
		rm.logger.Error("Failed to marshal modified response",
			zap.String("correlation_id", correlationID),
			zap.Error(err))
		// Return original response on marshal failure
		return responseData, nil
	}

	duration := time.Since(start)
	rm.logger.Debug("Root devirtualization applied to response",
		zap.String("correlation_id", correlationID),
		zap.String("tenant", tenant),
		zap.Duration("duration", duration))

	return modifiedData, nil
}

// isResourceRequest determines if an MCP method involves resource access
func (rm *RootMiddleware) isResourceRequest(method string) bool {
	resourceMethods := []string{
		"resources/list",
		"resources/read",
		"resources/write",
		"resources/subscribe",
		"resources/unsubscribe",
		"tools/call", // Tools might access resources
	}

	for _, resourceMethod := range resourceMethods {
		if method == resourceMethod {
			return true
		}
	}

	return false
}

// virtualizeRequest applies root virtualization to an MCP request
func (rm *RootMiddleware) virtualizeRequest(ctx context.Context, tenant string, request *MCPRequest) (*MCPRequest, error) {
	// Create a copy of the request to avoid modifying the original
	modifiedRequest := *request

	// Extract and process parameters based on method type
	switch request.Method {
	case "resources/list":
		// For list requests, we might need to filter based on virtual roots
		// The params might contain a URI prefix to list
		if params, ok := request.Params.(map[string]interface{}); ok {
			if uri, exists := params["uri"]; exists {
				if uriStr, ok := uri.(string); ok {
					// Validate that the URI is within allowed virtual roots
					_, err := rm.mapper.MapURI(ctx, uriStr, tenant)
					if err != nil {
						return nil, fmt.Errorf("unauthorized resource access: %w", err)
					}
					// URI is valid, keep it as-is for upstream processing
				}
			}
		}

	case "resources/read":
		// For read requests, map virtual URI to real path
		if params, ok := request.Params.(map[string]interface{}); ok {
			if uri, exists := params["uri"]; exists {
				if uriStr, ok := uri.(string); ok {
					// Map virtual URI to real resource
					resource, err := rm.mapper.MapURI(ctx, uriStr, tenant)
					if err != nil {
						return nil, fmt.Errorf("failed to map resource URI: %w", err)
					}

					// Validate access for read operation
					if err := rm.mapper.ValidateAccess(ctx, resource, "read"); err != nil {
						return nil, fmt.Errorf("access denied: %w", err)
					}

					// Replace virtual URI with real path for upstream server
					params["uri"] = resource.RealPath
					modifiedRequest.Params = params

					rm.logger.Debug("Mapped virtual URI to real path",
						zap.String("virtual_uri", uriStr),
						zap.String("real_path", resource.RealPath),
						zap.String("tenant", tenant))
				}
			}
		}

	case "resources/write":
		// For write requests, map virtual URI to real path and validate write access
		if params, ok := request.Params.(map[string]interface{}); ok {
			if uri, exists := params["uri"]; exists {
				if uriStr, ok := uri.(string); ok {
					// Map virtual URI to real resource
					resource, err := rm.mapper.MapURI(ctx, uriStr, tenant)
					if err != nil {
						return nil, fmt.Errorf("failed to map resource URI: %w", err)
					}

					// Validate access for write operation
					if err := rm.mapper.ValidateAccess(ctx, resource, "write"); err != nil {
						return nil, fmt.Errorf("access denied: %w", err)
					}

					// Replace virtual URI with real path for upstream server
					params["uri"] = resource.RealPath
					modifiedRequest.Params = params

					rm.logger.Debug("Mapped virtual URI to real path for write",
						zap.String("virtual_uri", uriStr),
						zap.String("real_path", resource.RealPath),
						zap.String("tenant", tenant))
				}
			}
		}

	case "tools/call":
		// For tool calls, check if any arguments contain resource URIs
		if params, ok := request.Params.(map[string]interface{}); ok {
			if arguments, exists := params["arguments"]; exists {
				if args, ok := arguments.(map[string]interface{}); ok {
					// Look for common resource URI parameters
					modifiedArgs := make(map[string]interface{})
					for key, value := range args {
						modifiedArgs[key] = value

						// Check for URI-like parameters
						if rm.isURIParameter(key) {
							if uriStr, ok := value.(string); ok && strings.HasPrefix(uriStr, "mcp://") {
								// Map virtual URI to real path
								resource, err := rm.mapper.MapURI(ctx, uriStr, tenant)
								if err != nil {
									return nil, fmt.Errorf("failed to map tool argument URI: %w", err)
								}

								// Validate access (assume read for tools, could be configurable)
								if err := rm.mapper.ValidateAccess(ctx, resource, "read"); err != nil {
									return nil, fmt.Errorf("tool access denied: %w", err)
								}

								// Replace with real path
								modifiedArgs[key] = resource.RealPath

								rm.logger.Debug("Mapped tool argument URI",
									zap.String("parameter", key),
									zap.String("virtual_uri", uriStr),
									zap.String("real_path", resource.RealPath),
									zap.String("tenant", tenant))
							}
						}
					}
					params["arguments"] = modifiedArgs
					modifiedRequest.Params = params
				}
			}
		}
	}

	return &modifiedRequest, nil
}

// devirtualizeResponse applies reverse root virtualization to an MCP response
func (rm *RootMiddleware) devirtualizeResponse(ctx context.Context, tenant string, response *MCPResponse) (*MCPResponse, error) {
	// Create a copy of the response to avoid modifying the original
	modifiedResponse := *response

	// Only process successful responses with results
	if response.Error != nil || response.Result == nil {
		return response, nil
	}

	// Convert real paths back to virtual URIs in the response
	// This is a recursive process that looks for path-like strings in the response
	modifiedResult, err := rm.devirtualizeValue(ctx, tenant, response.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to devirtualize response: %w", err)
	}

	modifiedResponse.Result = modifiedResult
	return &modifiedResponse, nil
}

// devirtualizeValue recursively processes a value to convert real paths to virtual URIs
func (rm *RootMiddleware) devirtualizeValue(ctx context.Context, tenant string, value interface{}) (interface{}, error) {
	switch v := value.(type) {
	case string:
		// Check if this looks like a real path that should be converted to virtual URI
		return rm.convertRealPathToVirtualURI(ctx, tenant, v), nil

	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, val := range v {
			modifiedVal, err := rm.devirtualizeValue(ctx, tenant, val)
			if err != nil {
				return nil, err
			}
			result[key] = modifiedVal
		}
		return result, nil

	case []interface{}:
		result := make([]interface{}, len(v))
		for i, val := range v {
			modifiedVal, err := rm.devirtualizeValue(ctx, tenant, val)
			if err != nil {
				return nil, err
			}
			result[i] = modifiedVal
		}
		return result, nil

	default:
		// For other types, return as-is
		return value, nil
	}
}

// convertRealPathToVirtualURI attempts to convert a real path back to a virtual URI
func (rm *RootMiddleware) convertRealPathToVirtualURI(ctx context.Context, tenant string, path string) string {
	// If the path doesn't look like an absolute path that we can reverse map,
	// return it unchanged
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "s3://") {
		return path
	}

	// Use the RootMapper's ReverseMap method to convert real path to virtual URI
	if virtualURI, found := rm.mapper.ReverseMap(ctx, tenant, path); found {
		return virtualURI
	}

	// If no mapping found, return the original path
	return path
}

// isURIParameter checks if a parameter name suggests it contains a URI
func (rm *RootMiddleware) isURIParameter(paramName string) bool {
	uriParams := []string{
		"uri", "url", "path", "file", "resource", "location",
		"source", "target", "input", "output",
	}

	paramLower := strings.ToLower(paramName)
	for _, uriParam := range uriParams {
		if strings.Contains(paramLower, uriParam) {
			return true
		}
	}

	return false
}

// createErrorResponse creates a JSON-RPC error response
func (rm *RootMiddleware) createErrorResponse(id interface{}, code int, message string, data interface{}) ([]byte, error) {
	response := MCPResponse{
		ID:      id,
		JSONRPC: "2.0",
		Error: &MCPError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}

	return json.Marshal(response)
}

package policy

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// MCPRequest represents a simplified MCP request for integration testing
type MCPRequest struct {
	ID      string                 `json:"id"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params"`
	Headers map[string]string      `json:"headers"`
}

// MCPResponse represents a simplified MCP response
type MCPResponse struct {
	ID     string      `json:"id"`
	Result interface{} `json:"result,omitempty"`
	Error  *MCPError   `json:"error,omitempty"`
}

// MCPError represents an MCP protocol error
type MCPError struct {
	Code    int                    `json:"code"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// AuthContext contains authentication information extracted from the request
type AuthContext struct {
	Subject string
	Tenant  string
	Groups  []string
}

// PolicyIntegration demonstrates how to integrate policy middleware with MCP request processing
type PolicyIntegration struct {
	middleware *PolicyMiddleware
	logger     *zap.Logger
}

// NewPolicyIntegration creates a new policy integration
func NewPolicyIntegration(middleware *PolicyMiddleware, logger *zap.Logger) *PolicyIntegration {
	return &PolicyIntegration{
		middleware: middleware,
		logger:     logger,
	}
}

// ProcessRequest processes an MCP request with policy enforcement
func (pi *PolicyIntegration) ProcessRequest(ctx context.Context, req *MCPRequest, auth *AuthContext) (*MCPResponse, error) {
    requestID := req.ID
    if requestID == "" {
        requestID = fmt.Sprintf("req-%d", time.Now().UnixNano())
        req.ID = requestID  // ensure downstream code & response share the same ID
    }

    // Extract tool and resource from request
    tool, resource := pi.extractToolAndResource(req)

    // Create request context for policy evaluation
    reqCtx := &RequestContext{
        Subject:   auth.Subject,
        Tenant:    auth.Tenant,
        Groups:    auth.Groups,
        Tool:      tool,
        Resource:  resource,
        Method:    req.Method,
        Headers:   req.Headers,
        RequestID: requestID,
        Timestamp: time.Now(),
    }
    // ... rest of the function ...
}

	// Evaluate policy
	result := pi.middleware.EvaluateRequest(ctx, reqCtx)

	// Handle policy evaluation error (fail-closed)
	if result.Error != nil {
		pi.logger.Error("Policy evaluation failed, denying request",
			zap.String("request_id", requestID),
			zap.Error(result.Error))

		return &MCPResponse{
			ID: requestID,
			Error: &MCPError{
				Code:    -32603, // Internal error
				Message: "Policy evaluation failed",
				Data: map[string]interface{}{
					"correlation_id": requestID,
				},
			},
		}, nil
	}

	// Check policy decision
	if result.Decision == nil || !result.Decision.Allow {
		reason := "access denied"
		ruleID := "unknown"

		if result.Decision != nil {
			reason = result.Decision.Reason
			ruleID = result.Decision.RuleID
		}

		return &MCPResponse{
			ID: requestID,
			Error: &MCPError{
				Code:    -32602, // Invalid params (closest to forbidden)
				Message: "Access denied by policy",
				Data: map[string]interface{}{
					"reason":         reason,
					"rule_id":        ruleID,
					"correlation_id": requestID,
					"tenant":         auth.Tenant,
				},
			},
		}, nil
	}

	// Policy allows request - proceed with actual processing
	// In a real implementation, this would call the upstream MCP server
	return pi.processAllowedRequest(ctx, req, reqCtx)
}

// extractToolAndResource extracts tool and resource information from MCP request
func (pi *PolicyIntegration) extractToolAndResource(req *MCPRequest) (string, string) {
	// Extract tool from method (e.g., "tools/call" -> "call")
	tool := req.Method
	if req.Method == "tools/call" {
		if name, ok := req.Params["name"].(string); ok {
			tool = name
		}
	}

	// Extract resource from params
	resource := ""
	if uri, ok := req.Params["uri"].(string); ok {
		resource = uri
	} else if path, ok := req.Params["path"].(string); ok {
		resource = path
	}

	return tool, resource
}

// processAllowedRequest processes a request that has been allowed by policy
func (pi *PolicyIntegration) processAllowedRequest(ctx context.Context, req *MCPRequest, reqCtx *RequestContext) (*MCPResponse, error) {
	// Simulate processing the allowed request
	// In a real implementation, this would proxy to the upstream MCP server

	pi.logger.Info("Processing allowed request",
		zap.String("request_id", reqCtx.RequestID),
		zap.String("tenant", reqCtx.Tenant),
		zap.String("tool", reqCtx.Tool),
		zap.String("resource", reqCtx.Resource))

	return &MCPResponse{
		ID: req.ID,
		Result: map[string]interface{}{
			"status":   "success",
			"message":  "Request processed successfully",
			"tool":     reqCtx.Tool,
			"resource": reqCtx.Resource,
		},
	}, nil
}

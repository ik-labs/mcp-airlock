package roots

import (
	"context"
	"fmt"
	"time"

	"github.com/ik-labs/mcp-airlock/pkg/policy"
	"go.uber.org/zap"
)

// contextKey is a type for context keys to avoid collisions
type contextKey string

const (
	correlationIDKey contextKey = "correlation_id"
)

// getCorrelationIDFromContext extracts correlation ID from context
func getCorrelationIDFromContext(ctx context.Context) string {
	if id := ctx.Value(correlationIDKey); id != nil {
		if idStr, ok := id.(string); ok {
			return idStr
		}
	}
	return "unknown"
}

// PolicyIntegration provides integration between root virtualization and policy engine
type PolicyIntegration struct {
	mapper       RootMapper
	policyEngine policy.PolicyEngine
	logger       *zap.Logger
}

// NewPolicyIntegration creates a new policy integration
func NewPolicyIntegration(mapper RootMapper, policyEngine policy.PolicyEngine, logger *zap.Logger) *PolicyIntegration {
	return &PolicyIntegration{
		mapper:       mapper,
		policyEngine: policyEngine,
		logger:       logger,
	}
}

// AuthorizeResourceAccess performs comprehensive authorization for resource access
func (pi *PolicyIntegration) AuthorizeResourceAccess(ctx context.Context, req *ResourceAuthRequest) (*ResourceAuthResult, error) {
	start := time.Now()

	correlationID := getCorrelationIDFromContext(ctx)

	pi.logger.Debug("Authorizing resource access",
		zap.String("correlation_id", correlationID),
		zap.String("tenant", req.Tenant),
		zap.String("subject", req.Subject),
		zap.String("virtual_uri", req.VirtualURI),
		zap.String("operation", req.Operation))

	// Step 1: Map virtual URI to real resource
	resource, err := pi.mapper.MapURI(ctx, req.VirtualURI, req.Tenant)
	if err != nil {
		pi.logger.Warn("Resource mapping failed",
			zap.String("correlation_id", correlationID),
			zap.String("tenant", req.Tenant),
			zap.String("virtual_uri", req.VirtualURI),
			zap.Error(err))

		return &ResourceAuthResult{
			Allowed:      false,
			Reason:       "Resource mapping failed",
			RuleID:       "roots.mapping_failed",
			Duration:     time.Since(start),
			MappingError: err,
		}, nil
	}

	// Step 2: Validate basic access permissions (read-only enforcement)
	if err := pi.mapper.ValidateAccess(ctx, resource, req.Operation); err != nil {
		pi.logger.Warn("Basic access validation failed",
			zap.String("correlation_id", correlationID),
			zap.String("tenant", req.Tenant),
			zap.String("virtual_uri", req.VirtualURI),
			zap.String("operation", req.Operation),
			zap.Error(err))

		return &ResourceAuthResult{
			Allowed:     false,
			Reason:      "Access validation failed",
			RuleID:      "roots.access_denied",
			Duration:    time.Since(start),
			AccessError: err,
		}, nil
	}

	// Step 3: Policy-based authorization with root context
	policyInput := &policy.PolicyInput{
		Subject:  req.Subject,
		Tenant:   req.Tenant,
		Groups:   req.Groups,
		Tool:     req.Tool,
		Resource: req.Resource,
		Method:   req.Method,
		Headers:  req.Headers,
		// Root-based fields
		VirtualURI: req.VirtualURI,
		RealPath:   resource.RealPath,
		RootType:   resource.Type,
		ReadOnly:   resource.ReadOnly,
		Operation:  req.Operation,
	}

	decision, err := pi.policyEngine.Evaluate(ctx, policyInput)
	if err != nil {
		pi.logger.Error("Policy evaluation failed",
			zap.String("correlation_id", correlationID),
			zap.String("tenant", req.Tenant),
			zap.String("virtual_uri", req.VirtualURI),
			zap.Error(err))

		return &ResourceAuthResult{
			Allowed:     false,
			Reason:      "Policy evaluation failed",
			RuleID:      "policy.evaluation_error",
			Duration:    time.Since(start),
			PolicyError: err,
		}, nil
	}

	duration := time.Since(start)

	result := &ResourceAuthResult{
		Allowed:        decision.Allow,
		Reason:         decision.Reason,
		RuleID:         decision.RuleID,
		Duration:       duration,
		MappedResource: resource,
		PolicyDecision: decision,
	}

	if decision.Allow {
		pi.logger.Info("Resource access authorized",
			zap.String("correlation_id", correlationID),
			zap.String("tenant", req.Tenant),
			zap.String("subject", req.Subject),
			zap.String("virtual_uri", req.VirtualURI),
			zap.String("real_path", resource.RealPath),
			zap.String("operation", req.Operation),
			zap.String("rule_id", decision.RuleID),
			zap.Duration("duration", duration))
	} else {
		pi.logger.Warn("Resource access denied",
			zap.String("correlation_id", correlationID),
			zap.String("tenant", req.Tenant),
			zap.String("subject", req.Subject),
			zap.String("virtual_uri", req.VirtualURI),
			zap.String("operation", req.Operation),
			zap.String("reason", decision.Reason),
			zap.String("rule_id", decision.RuleID),
			zap.Duration("duration", duration))
	}

	return result, nil
}

// ResourceAuthRequest represents a resource authorization request
type ResourceAuthRequest struct {
	// User context
	Subject string
	Tenant  string
	Groups  []string

	// Request context
	Tool     string
	Resource string
	Method   string
	Headers  map[string]string

	// Resource-specific context
	VirtualURI string
	Operation  string
}

// ResourceAuthResult represents the result of resource authorization
type ResourceAuthResult struct {
	// Authorization result
	Allowed bool
	Reason  string
	RuleID  string

	// Performance metrics
	Duration time.Duration

	// Resource mapping result
	MappedResource *MappedResource

	// Policy decision details
	PolicyDecision *policy.PolicyDecision

	// Error details
	MappingError error
	AccessError  error
	PolicyError  error
}

// IsSuccessful returns true if authorization was successful
func (r *ResourceAuthResult) IsSuccessful() bool {
	return r.Allowed && r.MappingError == nil && r.AccessError == nil && r.PolicyError == nil
}

// GetPrimaryError returns the primary error that caused authorization failure
func (r *ResourceAuthResult) GetPrimaryError() error {
	if r.MappingError != nil {
		return r.MappingError
	}
	if r.AccessError != nil {
		return r.AccessError
	}
	if r.PolicyError != nil {
		return r.PolicyError
	}
	if !r.Allowed {
		return fmt.Errorf("access denied: %s", r.Reason)
	}
	return nil
}

// CreatePolicyInputFromResource creates a policy input from resource context
func CreatePolicyInputFromResource(req *ResourceAuthRequest, resource *MappedResource) *policy.PolicyInput {
	return &policy.PolicyInput{
		Subject:    req.Subject,
		Tenant:     req.Tenant,
		Groups:     req.Groups,
		Tool:       req.Tool,
		Resource:   req.Resource,
		Method:     req.Method,
		Headers:    req.Headers,
		VirtualURI: req.VirtualURI,
		RealPath:   resource.RealPath,
		RootType:   resource.Type,
		ReadOnly:   resource.ReadOnly,
		Operation:  req.Operation,
	}
}

// ValidateResourceRequest validates a resource request for common issues
func ValidateResourceRequest(req *ResourceAuthRequest) error {
	if req.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	if req.Tenant == "" {
		return fmt.Errorf("tenant is required")
	}
	if req.VirtualURI == "" {
		return fmt.Errorf("virtual URI is required")
	}
	if req.Operation == "" {
		return fmt.Errorf("operation is required")
	}

	// Validate operation type
	validOperations := []string{"read", "write", "list", "create", "delete", "update"}
	validOp := false
	for _, op := range validOperations {
		if req.Operation == op {
			validOp = true
			break
		}
	}
	if !validOp {
		return fmt.Errorf("invalid operation: %s", req.Operation)
	}

	return nil
}

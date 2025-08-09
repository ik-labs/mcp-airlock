package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"go.uber.org/zap"
)

// PolicyMiddleware provides policy enforcement for MCP requests
type PolicyMiddleware struct {
	engine PolicyEngine
	logger *zap.Logger
}

// NewPolicyMiddleware creates a new policy middleware
func NewPolicyMiddleware(engine PolicyEngine, logger *zap.Logger) *PolicyMiddleware {
	return &PolicyMiddleware{
		engine: engine,
		logger: logger,
	}
}

// RequestContext contains the context information for policy evaluation
type RequestContext struct {
	Subject   string
	Tenant    string
	Groups    []string
	Tool      string
	Resource  string
	Method    string
	Headers   map[string]string
	RequestID string
	Timestamp time.Time
}

// PolicyResult contains the result of policy evaluation with audit information
type PolicyResult struct {
	Decision    *PolicyDecision
	InputDigest string
	Duration    time.Duration
	Error       error
}

// EvaluateRequest evaluates a request against the policy engine
func (pm *PolicyMiddleware) EvaluateRequest(ctx context.Context, reqCtx *RequestContext) *PolicyResult {
	start := time.Now()

	// Create policy input
	input := &PolicyInput{
		Subject:  reqCtx.Subject,
		Tenant:   reqCtx.Tenant,
		Groups:   reqCtx.Groups,
		Tool:     reqCtx.Tool,
		Resource: reqCtx.Resource,
		Method:   reqCtx.Method,
		Headers:  reqCtx.Headers,
	}

	// Generate input digest for audit logging (no raw sensitive data)
	inputDigest := pm.generateInputDigest(input)

	// Evaluate policy
	decision, err := pm.engine.Evaluate(ctx, input)
	duration := time.Since(start)

	result := &PolicyResult{
		Decision:    decision,
		InputDigest: inputDigest,
		Duration:    duration,
		Error:       err,
	}

	// Log policy decision with audit information
	pm.logPolicyDecision(reqCtx, result)

	return result
}

// generateInputDigest creates a hash digest of the policy input for audit logging
// This ensures we can audit policy decisions without logging sensitive data
func (pm *PolicyMiddleware) generateInputDigest(input *PolicyInput) string {
	h := sha256.New()
	h.Write([]byte(input.Subject))
	h.Write([]byte(input.Tenant))
	h.Write([]byte(input.Tool))
	h.Write([]byte(input.Resource))
	h.Write([]byte(input.Method))

	// Include groups in sorted order for consistency
	// Sort groups for deterministic hashing
	sort.Strings(input.Groups)
	for _, group := range input.Groups {
		h.Write([]byte(group))
	}

	// Include header keys only (not values) to avoid logging sensitive data
	keys := make([]string, 0, len(input.Headers))
	for k := range input.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k))
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// logPolicyDecision logs the policy decision with audit information
func (pm *PolicyMiddleware) logPolicyDecision(reqCtx *RequestContext, result *PolicyResult) {
	fields := []zap.Field{
		zap.String("request_id", reqCtx.RequestID),
		zap.String("tenant", reqCtx.Tenant),
		zap.String("subject", reqCtx.Subject),
		zap.String("tool", reqCtx.Tool),
		zap.String("resource", reqCtx.Resource),
		zap.String("method", reqCtx.Method),
		zap.String("input_digest", result.InputDigest),
		zap.Duration("policy_duration", result.Duration),
		zap.Time("timestamp", reqCtx.Timestamp),
	}

	if result.Error != nil {
		fields = append(fields, zap.Error(result.Error))
		pm.logger.Error("Policy evaluation failed", fields...)
		return
	}

	if result.Decision != nil {
		fields = append(fields,
			zap.Bool("allow", result.Decision.Allow),
			zap.String("reason", result.Decision.Reason),
			zap.String("rule_id", result.Decision.RuleID),
		)

		// Add metadata if present
		if len(result.Decision.Metadata) > 0 {
			fields = append(fields, zap.Any("metadata", result.Decision.Metadata))
		}
	}

	if result.Decision != nil && result.Decision.Allow {
		pm.logger.Info("Policy allowed request", fields...)
	} else {
		pm.logger.Warn("Policy denied request", fields...)
	}
}

// CheckPolicyAvailable checks if the policy engine is available
func (pm *PolicyMiddleware) CheckPolicyAvailable(ctx context.Context) error {
	// Try a simple evaluation to check if policy engine is working
	testInput := &PolicyInput{
		Subject:  "health-check",
		Tenant:   "system",
		Groups:   []string{},
		Tool:     "health-check",
		Resource: "system://health",
		Method:   "GET",
	}

	_, err := pm.engine.Evaluate(ctx, testInput)
	if err != nil {
		return fmt.Errorf("policy engine unavailable: %w", err)
	}

	return nil
}

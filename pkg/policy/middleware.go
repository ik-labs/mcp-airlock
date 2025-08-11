package policy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"go.uber.org/zap"
)

// AuditLogger interface for logging policy events
type AuditLogger interface {
	LogEvent(ctx context.Context, event *PolicyAuditEvent) error
}

// PolicyAuditEvent represents a policy audit event
type PolicyAuditEvent struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	CorrelationID string                 `json:"correlation_id"`
	Tenant        string                 `json:"tenant"`
	Subject       string                 `json:"subject"`
	Action        string                 `json:"action"`
	Resource      string                 `json:"resource"`
	Decision      string                 `json:"decision"`
	Reason        string                 `json:"reason"`
	Metadata      map[string]interface{} `json:"metadata"`
	LatencyMs     int64                  `json:"latency_ms,omitempty"`
}

// PolicyMiddleware provides policy enforcement for MCP requests
type PolicyMiddleware struct {
	engine      PolicyEngine
	logger      *zap.Logger
	auditLogger AuditLogger
}

// NewPolicyMiddleware creates a new policy middleware
func NewPolicyMiddleware(engine PolicyEngine, logger *zap.Logger) *PolicyMiddleware {
	return &PolicyMiddleware{
		engine: engine,
		logger: logger,
	}
}

// SetAuditLogger sets the audit logger for policy events
func (pm *PolicyMiddleware) SetAuditLogger(auditLogger AuditLogger) {
	pm.auditLogger = auditLogger
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

	// Log audit event
	pm.logPolicyAuditEvent(ctx, reqCtx, result)

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

	// Include root-based authorization fields for audit
	h.Write([]byte(input.VirtualURI))
	h.Write([]byte(input.RootType))
	h.Write([]byte(input.Operation))
	if input.ReadOnly {
		h.Write([]byte("readonly"))
	}
	// Note: RealPath is not included in digest to avoid logging sensitive paths

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

// logPolicyAuditEvent logs a policy decision audit event
func (pm *PolicyMiddleware) logPolicyAuditEvent(ctx context.Context, reqCtx *RequestContext, result *PolicyResult) {
	if pm.auditLogger == nil {
		return // No audit logger configured
	}

	decision := "deny"
	reason := "policy_evaluation_failed"

	if result.Error == nil && result.Decision != nil {
		if result.Decision.Allow {
			decision = "allow"
		}
		reason = result.Decision.Reason
		if reason == "" {
			reason = "policy_decision"
		}
	} else if result.Error != nil {
		reason = result.Error.Error()
	}

	metadata := map[string]interface{}{
		"tool":         reqCtx.Tool,
		"method":       reqCtx.Method,
		"input_digest": result.InputDigest,
	}

	if result.Decision != nil {
		metadata["rule_id"] = result.Decision.RuleID
		if len(result.Decision.Metadata) > 0 {
			metadata["policy_metadata"] = result.Decision.Metadata
		}
	}

	event := &PolicyAuditEvent{
		ID:            generateEventID(),
		Timestamp:     time.Now().UTC(),
		CorrelationID: reqCtx.RequestID,
		Tenant:        reqCtx.Tenant,
		Subject:       reqCtx.Subject,
		Action:        "policy_evaluate",
		Resource:      reqCtx.Resource,
		Decision:      decision,
		Reason:        reason,
		Metadata:      metadata,
		LatencyMs:     result.Duration.Milliseconds(),
	}

	// Log the event (don't fail the request if audit logging fails)
	if err := pm.auditLogger.LogEvent(ctx, event); err != nil {
		pm.logger.Warn("Failed to log policy audit event",
			zap.String("correlation_id", reqCtx.RequestID),
			zap.Error(err))
	}
}

// generateEventID generates a unique event ID
func generateEventID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("evt_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

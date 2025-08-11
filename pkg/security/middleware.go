package security

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// SecurityAuditLogger interface for logging security events
type SecurityAuditLogger interface {
	LogSecurityViolationEvent(ctx context.Context, correlationID, tenant, subject, violation, resource string, metadata map[string]interface{}) error
	LogPathTraversalAttempt(ctx context.Context, correlationID, tenant, subject, attemptedPath, resource string) error
	LogRateLimitEvent(ctx context.Context, correlationID, tenant, subject string, metadata map[string]interface{}) error
}

// SecurityMiddleware provides security violation detection and logging
type SecurityMiddleware struct {
	logger      *zap.Logger
	auditLogger SecurityAuditLogger
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(logger *zap.Logger) *SecurityMiddleware {
	return &SecurityMiddleware{
		logger: logger,
	}
}

// SetAuditLogger sets the audit logger for security events
func (sm *SecurityMiddleware) SetAuditLogger(auditLogger SecurityAuditLogger) {
	sm.auditLogger = auditLogger
}

// HTTPMiddleware returns an HTTP middleware function that detects security violations
func (sm *SecurityMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		correlationID := sm.getCorrelationID(ctx)

		// Check for path traversal attempts
		if sm.detectPathTraversal(r.URL.Path) {
			sm.logPathTraversalViolation(ctx, correlationID, r.URL.Path, r)
			http.Error(w, "Path traversal attempt detected", http.StatusBadRequest)
			return
		}

		// Check for suspicious headers
		if violation := sm.detectSuspiciousHeaders(r); violation != "" {
			sm.logHeaderViolation(ctx, correlationID, violation, r)
			http.Error(w, "Suspicious request headers detected", http.StatusBadRequest)
			return
		}

		// Check for oversized requests
		if sm.detectOversizedRequest(r) {
			sm.logOversizedRequestViolation(ctx, correlationID, r)
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
			return
		}

		// Continue with the request
		next.ServeHTTP(w, r)
	})
}

// detectPathTraversal detects path traversal attempts
func (sm *SecurityMiddleware) detectPathTraversal(path string) bool {
	// Common path traversal patterns
	traversalPatterns := []string{
		"../",
		"..\\",
		"%2e%2e%2f",
		"%2e%2e%5c",
		"..%2f",
		"..%5c",
		"%2e%2e/",
		"%2e%2e\\",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range traversalPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	return false
}

// detectSuspiciousHeaders detects suspicious request headers
func (sm *SecurityMiddleware) detectSuspiciousHeaders(r *http.Request) string {
	// Check for SQL injection attempts in headers
	for name, values := range r.Header {
		for _, value := range values {
			lowerValue := strings.ToLower(value)
			if strings.Contains(lowerValue, "union select") ||
				strings.Contains(lowerValue, "drop table") ||
				strings.Contains(lowerValue, "insert into") ||
				strings.Contains(lowerValue, "delete from") {
				return fmt.Sprintf("SQL injection attempt in header %s", name)
			}

			// Check for XSS attempts
			if strings.Contains(lowerValue, "<script") ||
				strings.Contains(lowerValue, "javascript:") ||
				strings.Contains(lowerValue, "onload=") {
				return fmt.Sprintf("XSS attempt in header %s", name)
			}

			// Check for command injection
			if strings.Contains(lowerValue, "$(") ||
				strings.Contains(lowerValue, "`") ||
				(strings.Contains(lowerValue, "|") && strings.Contains(lowerValue, "sh")) ||
				strings.Contains(lowerValue, "sh -c") ||
				strings.Contains(lowerValue, "bash -c") {
				return fmt.Sprintf("Command injection attempt in header %s", name)
			}
		}
	}

	return ""
}

// detectOversizedRequest detects oversized requests
func (sm *SecurityMiddleware) detectOversizedRequest(r *http.Request) bool {
	const maxRequestSize = 10 * 1024 * 1024 // 10MB

	if r.ContentLength > maxRequestSize {
		return true
	}

	return false
}

// logPathTraversalViolation logs a path traversal security violation
func (sm *SecurityMiddleware) logPathTraversalViolation(ctx context.Context, correlationID, path string, r *http.Request) {
	if sm.auditLogger == nil {
		return
	}

	tenant := sm.getTenant(ctx)
	subject := sm.getSubject(ctx)

	sm.logger.Warn("Path traversal attempt detected",
		zap.String("correlation_id", correlationID),
		zap.String("path", path),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()))

	if err := sm.auditLogger.LogPathTraversalAttempt(ctx, correlationID, tenant, subject, path, r.URL.String()); err != nil {
		sm.logger.Error("Failed to log path traversal audit event",
			zap.String("correlation_id", correlationID),
			zap.Error(err))
	}
}

// logHeaderViolation logs a suspicious header security violation
func (sm *SecurityMiddleware) logHeaderViolation(ctx context.Context, correlationID, violation string, r *http.Request) {
	if sm.auditLogger == nil {
		return
	}

	tenant := sm.getTenant(ctx)
	subject := sm.getSubject(ctx)

	sm.logger.Warn("Suspicious headers detected",
		zap.String("correlation_id", correlationID),
		zap.String("violation", violation),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()))

	metadata := map[string]interface{}{
		"violation_type": "suspicious_headers",
		"violation":      violation,
		"remote_addr":    r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"method":         r.Method,
	}

	if err := sm.auditLogger.LogSecurityViolationEvent(ctx, correlationID, tenant, subject, violation, r.URL.String(), metadata); err != nil {
		sm.logger.Error("Failed to log header violation audit event",
			zap.String("correlation_id", correlationID),
			zap.Error(err))
	}
}

// logOversizedRequestViolation logs an oversized request security violation
func (sm *SecurityMiddleware) logOversizedRequestViolation(ctx context.Context, correlationID string, r *http.Request) {
	if sm.auditLogger == nil {
		return
	}

	tenant := sm.getTenant(ctx)
	subject := sm.getSubject(ctx)

	sm.logger.Warn("Oversized request detected",
		zap.String("correlation_id", correlationID),
		zap.Int64("content_length", r.ContentLength),
		zap.String("remote_addr", r.RemoteAddr))

	metadata := map[string]interface{}{
		"violation_type": "oversized_request",
		"content_length": r.ContentLength,
		"remote_addr":    r.RemoteAddr,
		"user_agent":     r.UserAgent(),
		"method":         r.Method,
	}

	if err := sm.auditLogger.LogSecurityViolationEvent(ctx, correlationID, tenant, subject, "Oversized request detected", r.URL.String(), metadata); err != nil {
		sm.logger.Error("Failed to log oversized request audit event",
			zap.String("correlation_id", correlationID),
			zap.Error(err))
	}
}

// Helper methods to extract context values
func (sm *SecurityMiddleware) getCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value("correlation_id").(string); ok {
		return id
	}
	return "unknown"
}

func (sm *SecurityMiddleware) getTenant(ctx context.Context) string {
	if tenant, ok := ctx.Value("tenant").(string); ok {
		return tenant
	}
	return "unknown"
}

func (sm *SecurityMiddleware) getSubject(ctx context.Context) string {
	if subject, ok := ctx.Value("subject").(string); ok {
		return subject
	}
	return "unknown"
}

// RateLimitViolation logs a rate limit violation
func (sm *SecurityMiddleware) LogRateLimitViolation(ctx context.Context, correlationID, tenant, subject string, limit int, window time.Duration) {
	if sm.auditLogger == nil {
		return
	}

	sm.logger.Warn("Rate limit exceeded",
		zap.String("correlation_id", correlationID),
		zap.String("tenant", tenant),
		zap.String("subject", subject),
		zap.Int("limit", limit),
		zap.Duration("window", window))

	metadata := map[string]interface{}{
		"violation_type": "rate_limit_exceeded",
		"limit":          limit,
		"window":         window.String(),
	}

	if err := sm.auditLogger.LogRateLimitEvent(ctx, correlationID, tenant, subject, metadata); err != nil {
		sm.logger.Error("Failed to log rate limit audit event",
			zap.String("correlation_id", correlationID),
			zap.Error(err))
	}
}

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// Context keys for request metadata
type contextKey string

const (
	correlationIDKey contextKey = "correlation_id"
	tenantKey        contextKey = "tenant"
	subjectKey       contextKey = "subject"
	toolKey          contextKey = "tool"
)

// generateCorrelationID generates a unique correlation ID for request tracking
func generateCorrelationID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if random fails
		return hex.EncodeToString([]byte("fallback"))
	}
	return hex.EncodeToString(bytes)
}

// withCorrelationID adds a correlation ID to the context
func withCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDKey, id)
}

// getCorrelationID retrieves the correlation ID from context
func getCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value(correlationIDKey).(string); ok {
		return id
	}
	return "unknown"
}

// withTenant adds tenant information to the context
func withTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey, tenant)
}

// getTenant retrieves the tenant from context
func getTenant(ctx context.Context) string {
	if tenant, ok := ctx.Value(tenantKey).(string); ok {
		return tenant
	}
	return "unknown"
}

// withSubject adds subject information to the context
func withSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, subjectKey, subject)
}

// getSubject retrieves the subject from context
func getSubject(ctx context.Context) string {
	if subject, ok := ctx.Value(subjectKey).(string); ok {
		return subject
	}
	return "unknown"
}

// withTool adds tool information to the context
func withTool(ctx context.Context, tool string) context.Context {
	return context.WithValue(ctx, toolKey, tool)
}

// getTool retrieves the tool from context
func getTool(ctx context.Context) string {
	if tool, ok := ctx.Value(toolKey).(string); ok {
		return tool
	}
	return "unknown"
}

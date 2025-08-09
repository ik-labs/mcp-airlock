package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// ContextKey is a type for context keys to avoid collisions
type ContextKey string

const (
	// ClaimsContextKey is the context key for storing JWT claims
	ClaimsContextKey ContextKey = "jwt_claims"
	// SessionContextKey is the context key for storing session information
	SessionContextKey ContextKey = "session"
)

// Session represents an authenticated session
type Session struct {
	ID            string   `json:"id"`
	Claims        *Claims  `json:"claims"`
	Tenant        string   `json:"tenant"`
	Groups        []string `json:"groups"`
	Subject       string   `json:"subject"`
	Authenticated bool     `json:"authenticated"`
}

// TokenValidator interface for validating JWT tokens
type TokenValidator interface {
	ValidateToken(ctx context.Context, tokenString string) (*Claims, error)
}

// Middleware provides authentication middleware for HTTP requests
type Middleware struct {
	authenticator TokenValidator
	logger        *zap.Logger
	skipPaths     []string // Paths to skip authentication (e.g., health checks)
}

// NewMiddleware creates a new authentication middleware
func NewMiddleware(authenticator TokenValidator, logger *zap.Logger) *Middleware {
	return &Middleware{
		authenticator: authenticator,
		logger:        logger,
		skipPaths:     []string{"/health", "/live", "/ready", "/metrics"},
	}
}

// HTTPMiddleware returns an HTTP middleware function that validates JWT tokens
func (m *Middleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for certain paths
		if m.shouldSkipAuth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from Authorization header
		token, err := m.extractToken(r)
		if err != nil {
			m.logger.Warn("Token extraction failed",
				zap.Error(err),
				zap.String("path", r.URL.Path),
				zap.String("method", r.Method))
			m.writeAuthError(w, "missing or invalid authorization header", "")
			return
		}

		// Validate token
		claims, err := m.authenticator.ValidateToken(r.Context(), token)
		if err != nil {
			m.logger.Warn("Token validation failed",
				zap.Error(err),
				zap.String("path", r.URL.Path),
				zap.String("method", r.Method))
			m.writeAuthError(w, "invalid token", "")
			return
		}

		// Create session
		session := &Session{
			ID:            generateSessionID(),
			Claims:        claims,
			Tenant:        claims.Tenant,
			Groups:        claims.Groups,
			Subject:       claims.Subject,
			Authenticated: true,
		}

		// Add claims and session to context
		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		ctx = context.WithValue(ctx, SessionContextKey, session)

		// Log successful authentication
		m.logger.Info("Request authenticated",
			zap.String("subject", claims.Subject),
			zap.String("tenant", claims.Tenant),
			zap.Strings("groups", claims.Groups),
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method),
			zap.String("session_id", session.ID))

		// Continue with authenticated request
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractToken extracts the JWT token from the Authorization header
func (m *Middleware) extractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	// Check for Bearer token format
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid authorization header format, expected 'Bearer <token>'")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", fmt.Errorf("empty token in authorization header")
	}

	return token, nil
}

// shouldSkipAuth checks if authentication should be skipped for the given path
func (m *Middleware) shouldSkipAuth(path string) bool {
	for _, skipPath := range m.skipPaths {
		if path == skipPath || strings.HasPrefix(path, skipPath+"/") {
			return true
		}
	}
	return false
}

// writeAuthError writes an HTTP 401 response with proper WWW-Authenticate headers
func (m *Middleware) writeAuthError(w http.ResponseWriter, reason, correlationID string) {
	// Set WWW-Authenticate header as per RFC 6750
	w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-airlock", error="invalid_token"`)
	w.Header().Set("Content-Type", "application/json")

	if correlationID == "" {
		correlationID = generateCorrelationID()
	}

	w.WriteHeader(http.StatusUnauthorized)

	// Write MCP-compliant JSON-RPC error response
	errorResponse := map[string]interface{}{
		"jsonrpc": "2.0",
		"error": map[string]interface{}{
			"code":    -32600, // Invalid Request per JSON-RPC spec
			"message": "Authentication failed",
			"data": map[string]interface{}{
				"reason":           reason,
				"www_authenticate": `Bearer realm="mcp-airlock"`,
				"correlation_id":   correlationID,
			},
		},
		"id": nil,
	}

	// Write JSON response (ignore encoding errors in middleware)
	_ = writeJSON(w, errorResponse)
}

// GetClaimsFromContext extracts JWT claims from the request context
func GetClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*Claims)
	return claims, ok
}

// GetSessionFromContext extracts session information from the request context
func GetSessionFromContext(ctx context.Context) (*Session, bool) {
	session, ok := ctx.Value(SessionContextKey).(*Session)
	return session, ok
}

// RequireAuthentication is a helper middleware that ensures a request is authenticated
func RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := GetSessionFromContext(r.Context())
		if !ok || !session.Authenticated {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireGroups is a helper middleware that ensures the user has one of the required groups
func RequireGroups(requiredGroups []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := GetSessionFromContext(r.Context())
			if !ok || !session.Authenticated {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Check if user has any of the required groups
			hasRequiredGroup := false
			for _, userGroup := range session.Groups {
				for _, requiredGroup := range requiredGroups {
					if userGroup == requiredGroup {
						hasRequiredGroup = true
						break
					}
				}
				if hasRequiredGroup {
					break
				}
			}

			if !hasRequiredGroup {
				http.Error(w, "Insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper functions

// generateSessionID creates a unique session ID
func generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateCorrelationID creates a unique correlation ID for error tracking
func generateCorrelationID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// writeJSON writes a JSON response to the HTTP response writer
func writeJSON(w http.ResponseWriter, data interface{}) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(data)
}

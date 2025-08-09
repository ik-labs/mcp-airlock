package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap/zaptest"
)

// mockAuthenticator for testing
type mockAuthenticator struct {
	validateFunc func(ctx context.Context, token string) (*Claims, error)
}

func (m *mockAuthenticator) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return nil, nil
}

func (m *mockAuthenticator) Close() error {
	return nil
}

func TestMiddleware_HTTPMiddleware(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name           string
		path           string
		authHeader     string
		validateFunc   func(ctx context.Context, token string) (*Claims, error)
		expectedStatus int
		expectClaims   bool
		expectSession  bool
	}{
		{
			name:       "valid_token",
			path:       "/api/test",
			authHeader: "Bearer valid-token",
			validateFunc: func(ctx context.Context, token string) (*Claims, error) {
				return &Claims{
					Subject: "user@example.com",
					Tenant:  "tenant-1",
					Groups:  []string{"mcp.users"},
				}, nil
			},
			expectedStatus: http.StatusOK,
			expectClaims:   true,
			expectSession:  true,
		},
		{
			name:           "missing_auth_header",
			path:           "/api/test",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectClaims:   false,
			expectSession:  false,
		},
		{
			name:           "invalid_auth_format",
			path:           "/api/test",
			authHeader:     "InvalidFormat token",
			expectedStatus: http.StatusUnauthorized,
			expectClaims:   false,
			expectSession:  false,
		},
		{
			name:       "invalid_token",
			path:       "/api/test",
			authHeader: "Bearer invalid-token",
			validateFunc: func(ctx context.Context, token string) (*Claims, error) {
				return nil, &AuthError{Message: "invalid token"}
			},
			expectedStatus: http.StatusUnauthorized,
			expectClaims:   false,
			expectSession:  false,
		},
		{
			name:           "skip_health_check",
			path:           "/health",
			authHeader:     "",
			expectedStatus: http.StatusOK,
			expectClaims:   false,
			expectSession:  false,
		},
		{
			name:           "skip_metrics",
			path:           "/metrics",
			authHeader:     "",
			expectedStatus: http.StatusOK,
			expectClaims:   false,
			expectSession:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock authenticator
			mockAuth := &mockAuthenticator{
				validateFunc: tt.validateFunc,
			}

			// Create middleware
			middleware := NewMiddleware(mockAuth, logger)

			// Create test handler that checks context
			var receivedClaims *Claims
			var receivedSession *Session
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedClaims, _ = GetClaimsFromContext(r.Context())
				receivedSession, _ = GetSessionFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			// Wrap handler with middleware
			handler := middleware.HTTPMiddleware(testHandler)

			// Create test request
			req := httptest.NewRequest("GET", tt.path, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Check claims in context
			if tt.expectClaims {
				if receivedClaims == nil {
					t.Errorf("Expected claims in context, got nil")
				} else {
					if receivedClaims.Subject != "user@example.com" {
						t.Errorf("Expected subject 'user@example.com', got %s", receivedClaims.Subject)
					}
				}
			} else {
				if receivedClaims != nil {
					t.Errorf("Expected no claims in context, got %+v", receivedClaims)
				}
			}

			// Check session in context
			if tt.expectSession {
				if receivedSession == nil {
					t.Errorf("Expected session in context, got nil")
				} else {
					if !receivedSession.Authenticated {
						t.Errorf("Expected authenticated session")
					}
					if receivedSession.Subject != "user@example.com" {
						t.Errorf("Expected session subject 'user@example.com', got %s", receivedSession.Subject)
					}
				}
			} else {
				if receivedSession != nil {
					t.Errorf("Expected no session in context, got %+v", receivedSession)
				}
			}

			// Check WWW-Authenticate header for 401 responses
			if rr.Code == http.StatusUnauthorized {
				wwwAuth := rr.Header().Get("WWW-Authenticate")
				if !strings.Contains(wwwAuth, "Bearer") {
					t.Errorf("Expected WWW-Authenticate header with Bearer, got %s", wwwAuth)
				}
			}
		})
	}
}

func TestMiddleware_ExtractToken(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuth := &mockAuthenticator{}
	middleware := NewMiddleware(mockAuth, logger)

	tests := []struct {
		name        string
		authHeader  string
		expectToken string
		expectError bool
	}{
		{
			name:        "valid_bearer_token",
			authHeader:  "Bearer abc123",
			expectToken: "abc123",
			expectError: false,
		},
		{
			name:        "bearer_with_extra_spaces",
			authHeader:  "Bearer   abc123   ",
			expectToken: "abc123",
			expectError: false,
		},
		{
			name:        "case_insensitive_bearer",
			authHeader:  "bearer abc123",
			expectToken: "abc123",
			expectError: false,
		},
		{
			name:        "missing_header",
			authHeader:  "",
			expectToken: "",
			expectError: true,
		},
		{
			name:        "invalid_format",
			authHeader:  "Basic abc123",
			expectToken: "",
			expectError: true,
		},
		{
			name:        "empty_token",
			authHeader:  "Bearer ",
			expectToken: "",
			expectError: true,
		},
		{
			name:        "no_space_separator",
			authHeader:  "Bearerabc123",
			expectToken: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			token, err := middleware.extractToken(req)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if token != tt.expectToken {
					t.Errorf("Expected token %s, got %s", tt.expectToken, token)
				}
			}
		})
	}
}

func TestMiddleware_ShouldSkipAuth(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuth := &mockAuthenticator{}
	middleware := NewMiddleware(mockAuth, logger)

	tests := []struct {
		path       string
		shouldSkip bool
	}{
		{"/health", true},
		{"/health/", true},
		{"/health/detailed", true},
		{"/live", true},
		{"/ready", true},
		{"/metrics", true},
		{"/api/test", false},
		{"/", false},
		{"/healthcheck", false}, // Different from /health
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := middleware.shouldSkipAuth(tt.path)
			if result != tt.shouldSkip {
				t.Errorf("Path %s: expected shouldSkip=%v, got %v", tt.path, tt.shouldSkip, result)
			}
		})
	}
}

func TestRequireAuthentication(t *testing.T) {
	tests := []struct {
		name           string
		hasSession     bool
		authenticated  bool
		expectedStatus int
	}{
		{
			name:           "authenticated_session",
			hasSession:     true,
			authenticated:  true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "unauthenticated_session",
			hasSession:     true,
			authenticated:  false,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "no_session",
			hasSession:     false,
			authenticated:  false,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := RequireAuthentication(testHandler)

			req := httptest.NewRequest("GET", "/test", nil)

			// Add session to context if needed
			if tt.hasSession {
				session := &Session{
					Authenticated: tt.authenticated,
				}
				ctx := context.WithValue(req.Context(), SessionContextKey, session)
				req = req.WithContext(ctx)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestRequireGroups(t *testing.T) {
	tests := []struct {
		name           string
		userGroups     []string
		requiredGroups []string
		hasSession     bool
		authenticated  bool
		expectedStatus int
	}{
		{
			name:           "has_required_group",
			userGroups:     []string{"mcp.users", "admin"},
			requiredGroups: []string{"mcp.users"},
			hasSession:     true,
			authenticated:  true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "has_one_of_multiple_required",
			userGroups:     []string{"mcp.users"},
			requiredGroups: []string{"admin", "mcp.users"},
			hasSession:     true,
			authenticated:  true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing_required_group",
			userGroups:     []string{"basic.user"},
			requiredGroups: []string{"admin"},
			hasSession:     true,
			authenticated:  true,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "no_session",
			userGroups:     []string{},
			requiredGroups: []string{"admin"},
			hasSession:     false,
			authenticated:  false,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "unauthenticated_session",
			userGroups:     []string{"admin"},
			requiredGroups: []string{"admin"},
			hasSession:     true,
			authenticated:  false,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := RequireGroups(tt.requiredGroups)(testHandler)

			req := httptest.NewRequest("GET", "/test", nil)

			// Add session to context if needed
			if tt.hasSession {
				session := &Session{
					Groups:        tt.userGroups,
					Authenticated: tt.authenticated,
				}
				ctx := context.WithValue(req.Context(), SessionContextKey, session)
				req = req.WithContext(ctx)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

// AuthError is a simple error type for testing
type AuthError struct {
	Message string
}

func (e *AuthError) Error() string {
	return e.Message
}

package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// MockSecurityAuditLogger implements SecurityAuditLogger for testing
type MockSecurityAuditLogger struct {
	securityViolations []SecurityViolation
	pathTraversals     []PathTraversal
	rateLimits         []RateLimit
}

type SecurityViolation struct {
	CorrelationID string
	Tenant        string
	Subject       string
	Violation     string
	Resource      string
	Metadata      map[string]interface{}
}

type PathTraversal struct {
	CorrelationID string
	Tenant        string
	Subject       string
	AttemptedPath string
	Resource      string
}

type RateLimit struct {
	CorrelationID string
	Tenant        string
	Subject       string
	Metadata      map[string]interface{}
}

func NewMockSecurityAuditLogger() *MockSecurityAuditLogger {
	return &MockSecurityAuditLogger{
		securityViolations: make([]SecurityViolation, 0),
		pathTraversals:     make([]PathTraversal, 0),
		rateLimits:         make([]RateLimit, 0),
	}
}

func (m *MockSecurityAuditLogger) LogSecurityViolationEvent(ctx context.Context, correlationID, tenant, subject, violation, resource string, metadata map[string]interface{}) error {
	m.securityViolations = append(m.securityViolations, SecurityViolation{
		CorrelationID: correlationID,
		Tenant:        tenant,
		Subject:       subject,
		Violation:     violation,
		Resource:      resource,
		Metadata:      metadata,
	})
	return nil
}

func (m *MockSecurityAuditLogger) LogPathTraversalAttempt(ctx context.Context, correlationID, tenant, subject, attemptedPath, resource string) error {
	m.pathTraversals = append(m.pathTraversals, PathTraversal{
		CorrelationID: correlationID,
		Tenant:        tenant,
		Subject:       subject,
		AttemptedPath: attemptedPath,
		Resource:      resource,
	})
	return nil
}

func (m *MockSecurityAuditLogger) LogRateLimitEvent(ctx context.Context, correlationID, tenant, subject string, metadata map[string]interface{}) error {
	m.rateLimits = append(m.rateLimits, RateLimit{
		CorrelationID: correlationID,
		Tenant:        tenant,
		Subject:       subject,
		Metadata:      metadata,
	})
	return nil
}

func (m *MockSecurityAuditLogger) Reset() {
	m.securityViolations = make([]SecurityViolation, 0)
	m.pathTraversals = make([]PathTraversal, 0)
	m.rateLimits = make([]RateLimit, 0)
}

func TestSecurityMiddleware_PathTraversalDetection(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := NewMockSecurityAuditLogger()
	middleware := NewSecurityMiddleware(logger)
	middleware.SetAuditLogger(mockAuditLogger)

	testCases := []struct {
		name              string
		path              string
		shouldBlock       bool
		expectedViolation bool
	}{
		{
			name:              "Normal path",
			path:              "/api/users/123",
			shouldBlock:       false,
			expectedViolation: false,
		},
		{
			name:              "Path traversal with ../",
			path:              "/api/../etc/passwd",
			shouldBlock:       true,
			expectedViolation: true,
		},
		{
			name:              "Path traversal with ..\\",
			path:              "/api/..\\windows\\system32",
			shouldBlock:       true,
			expectedViolation: true,
		},
		{
			name:              "URL encoded path traversal",
			path:              "/api/%2e%2e%2f/etc/passwd",
			shouldBlock:       true,
			expectedViolation: true,
		},
		{
			name:              "Mixed encoding path traversal",
			path:              "/api/..%2f/etc/passwd",
			shouldBlock:       true,
			expectedViolation: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockAuditLogger.Reset()

			req := httptest.NewRequest("GET", tc.path, nil)
			req = req.WithContext(context.WithValue(req.Context(), "correlation_id", "test-correlation-id"))

			rr := httptest.NewRecorder()

			handler := middleware.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))

			handler.ServeHTTP(rr, req)

			if tc.shouldBlock {
				if rr.Code != http.StatusBadRequest {
					t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
				}
				if !strings.Contains(rr.Body.String(), "Path traversal attempt detected") {
					t.Errorf("Expected path traversal error message, got %s", rr.Body.String())
				}
			} else {
				if rr.Code != http.StatusOK {
					t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
				}
			}

			if tc.expectedViolation {
				if len(mockAuditLogger.pathTraversals) != 1 {
					t.Errorf("Expected 1 path traversal audit event, got %d", len(mockAuditLogger.pathTraversals))
				} else {
					event := mockAuditLogger.pathTraversals[0]
					if event.CorrelationID != "test-correlation-id" {
						t.Errorf("Expected correlation ID test-correlation-id, got %s", event.CorrelationID)
					}
					// Note: URL decoding happens automatically in HTTP requests
					// so we need to check for the decoded path in some cases
					expectedPath := tc.path
					if tc.name == "URL encoded path traversal" {
						expectedPath = "/api/..//etc/passwd" // URL decoded
					} else if tc.name == "Mixed encoding path traversal" {
						expectedPath = "/api/..//etc/passwd" // URL decoded
					}
					if event.AttemptedPath != expectedPath {
						t.Errorf("Expected attempted path %s, got %s", expectedPath, event.AttemptedPath)
					}
				}
			} else {
				if len(mockAuditLogger.pathTraversals) != 0 {
					t.Errorf("Expected 0 path traversal audit events, got %d", len(mockAuditLogger.pathTraversals))
				}
			}
		})
	}
}

func TestSecurityMiddleware_SuspiciousHeaderDetection(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := NewMockSecurityAuditLogger()
	middleware := NewSecurityMiddleware(logger)
	middleware.SetAuditLogger(mockAuditLogger)

	testCases := []struct {
		name              string
		headers           map[string]string
		shouldBlock       bool
		expectedViolation string
	}{
		{
			name:              "Normal headers",
			headers:           map[string]string{"Content-Type": "application/json"},
			shouldBlock:       false,
			expectedViolation: "",
		},
		{
			name:              "SQL injection in header",
			headers:           map[string]string{"X-Custom": "'; DROP TABLE users; --"},
			shouldBlock:       true,
			expectedViolation: "SQL injection attempt in header X-Custom",
		},
		{
			name:              "XSS attempt in header",
			headers:           map[string]string{"User-Agent": "<script>alert('xss')</script>"},
			shouldBlock:       true,
			expectedViolation: "XSS attempt in header User-Agent",
		},
		{
			name:              "Command injection in header",
			headers:           map[string]string{"X-Forwarded-For": "127.0.0.1; sh -c 'cat /etc/passwd'"},
			shouldBlock:       true,
			expectedViolation: "Command injection attempt in header X-Forwarded-For",
		},
		{
			name:              "JavaScript protocol in header",
			headers:           map[string]string{"Referer": "javascript:alert('xss')"},
			shouldBlock:       true,
			expectedViolation: "XSS attempt in header Referer",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockAuditLogger.Reset()

			req := httptest.NewRequest("GET", "/api/test", nil)
			req = req.WithContext(context.WithValue(req.Context(), "correlation_id", "test-correlation-id"))

			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			rr := httptest.NewRecorder()

			handler := middleware.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))

			handler.ServeHTTP(rr, req)

			if tc.shouldBlock {
				if rr.Code != http.StatusBadRequest {
					t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
				}
				if !strings.Contains(rr.Body.String(), "Suspicious request headers detected") {
					t.Errorf("Expected suspicious headers error message, got %s", rr.Body.String())
				}

				if len(mockAuditLogger.securityViolations) != 1 {
					t.Errorf("Expected 1 security violation audit event, got %d", len(mockAuditLogger.securityViolations))
				} else {
					event := mockAuditLogger.securityViolations[0]
					if event.CorrelationID != "test-correlation-id" {
						t.Errorf("Expected correlation ID test-correlation-id, got %s", event.CorrelationID)
					}
					if event.Violation != tc.expectedViolation {
						t.Errorf("Expected violation %s, got %s", tc.expectedViolation, event.Violation)
					}
					if violationType, ok := event.Metadata["violation_type"].(string); !ok || violationType != "suspicious_headers" {
						t.Errorf("Expected violation_type suspicious_headers, got %v", event.Metadata["violation_type"])
					}
				}
			} else {
				if rr.Code != http.StatusOK {
					t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
				}
				if len(mockAuditLogger.securityViolations) != 0 {
					t.Errorf("Expected 0 security violation audit events, got %d", len(mockAuditLogger.securityViolations))
				}
			}
		})
	}
}

func TestSecurityMiddleware_OversizedRequestDetection(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := NewMockSecurityAuditLogger()
	middleware := NewSecurityMiddleware(logger)
	middleware.SetAuditLogger(mockAuditLogger)

	testCases := []struct {
		name          string
		contentLength int64
		shouldBlock   bool
	}{
		{
			name:          "Normal request size",
			contentLength: 1024,
			shouldBlock:   false,
		},
		{
			name:          "Large but acceptable request",
			contentLength: 5 * 1024 * 1024, // 5MB
			shouldBlock:   false,
		},
		{
			name:          "Oversized request",
			contentLength: 15 * 1024 * 1024, // 15MB (over 10MB limit)
			shouldBlock:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockAuditLogger.Reset()

			req := httptest.NewRequest("POST", "/api/upload", strings.NewReader("test data"))
			req = req.WithContext(context.WithValue(req.Context(), "correlation_id", "test-correlation-id"))
			req.ContentLength = tc.contentLength

			rr := httptest.NewRecorder()

			handler := middleware.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))

			handler.ServeHTTP(rr, req)

			if tc.shouldBlock {
				if rr.Code != http.StatusRequestEntityTooLarge {
					t.Errorf("Expected status %d, got %d", http.StatusRequestEntityTooLarge, rr.Code)
				}
				if !strings.Contains(rr.Body.String(), "Request too large") {
					t.Errorf("Expected request too large error message, got %s", rr.Body.String())
				}

				if len(mockAuditLogger.securityViolations) != 1 {
					t.Errorf("Expected 1 security violation audit event, got %d", len(mockAuditLogger.securityViolations))
				} else {
					event := mockAuditLogger.securityViolations[0]
					if event.CorrelationID != "test-correlation-id" {
						t.Errorf("Expected correlation ID test-correlation-id, got %s", event.CorrelationID)
					}
					if event.Violation != "Oversized request detected" {
						t.Errorf("Expected violation 'Oversized request detected', got %s", event.Violation)
					}
					if contentLength, ok := event.Metadata["content_length"].(int64); !ok || contentLength != tc.contentLength {
						t.Errorf("Expected content_length %d, got %v", tc.contentLength, event.Metadata["content_length"])
					}
				}
			} else {
				if rr.Code != http.StatusOK {
					t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
				}
				if len(mockAuditLogger.securityViolations) != 0 {
					t.Errorf("Expected 0 security violation audit events, got %d", len(mockAuditLogger.securityViolations))
				}
			}
		})
	}
}

func TestSecurityMiddleware_RateLimitViolation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockAuditLogger := NewMockSecurityAuditLogger()
	middleware := NewSecurityMiddleware(logger)
	middleware.SetAuditLogger(mockAuditLogger)

	ctx := context.Background()
	correlationID := "test-correlation-id"
	tenant := "test-tenant"
	subject := "test-user"
	limit := 100
	window := 1 * time.Minute

	middleware.LogRateLimitViolation(ctx, correlationID, tenant, subject, limit, window)

	if len(mockAuditLogger.rateLimits) != 1 {
		t.Errorf("Expected 1 rate limit audit event, got %d", len(mockAuditLogger.rateLimits))
	} else {
		event := mockAuditLogger.rateLimits[0]
		if event.CorrelationID != correlationID {
			t.Errorf("Expected correlation ID %s, got %s", correlationID, event.CorrelationID)
		}
		if event.Tenant != tenant {
			t.Errorf("Expected tenant %s, got %s", tenant, event.Tenant)
		}
		if event.Subject != subject {
			t.Errorf("Expected subject %s, got %s", subject, event.Subject)
		}
		if limitValue, ok := event.Metadata["limit"].(int); !ok || limitValue != limit {
			t.Errorf("Expected limit %d, got %v", limit, event.Metadata["limit"])
		}
		if windowValue, ok := event.Metadata["window"].(string); !ok || windowValue != window.String() {
			t.Errorf("Expected window %s, got %v", window.String(), event.Metadata["window"])
		}
	}
}

func TestSecurityMiddleware_ContextExtraction(t *testing.T) {
	logger := zaptest.NewLogger(t)
	middleware := NewSecurityMiddleware(logger)

	// Test context value extraction
	ctx := context.Background()
	ctx = context.WithValue(ctx, "correlation_id", "test-correlation-id")
	ctx = context.WithValue(ctx, "tenant", "test-tenant")
	ctx = context.WithValue(ctx, "subject", "test-user")

	correlationID := middleware.getCorrelationID(ctx)
	if correlationID != "test-correlation-id" {
		t.Errorf("Expected correlation ID test-correlation-id, got %s", correlationID)
	}

	tenant := middleware.getTenant(ctx)
	if tenant != "test-tenant" {
		t.Errorf("Expected tenant test-tenant, got %s", tenant)
	}

	subject := middleware.getSubject(ctx)
	if subject != "test-user" {
		t.Errorf("Expected subject test-user, got %s", subject)
	}

	// Test with missing values
	emptyCtx := context.Background()

	correlationID = middleware.getCorrelationID(emptyCtx)
	if correlationID != "unknown" {
		t.Errorf("Expected correlation ID unknown, got %s", correlationID)
	}

	tenant = middleware.getTenant(emptyCtx)
	if tenant != "unknown" {
		t.Errorf("Expected tenant unknown, got %s", tenant)
	}

	subject = middleware.getSubject(emptyCtx)
	if subject != "unknown" {
		t.Errorf("Expected subject unknown, got %s", subject)
	}
}

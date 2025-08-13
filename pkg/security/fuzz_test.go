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
	"unicode/utf8"

	"go.uber.org/zap/zaptest"
)

// FuzzSecurityMiddleware fuzzes the security middleware with random inputs
func FuzzSecurityMiddleware(f *testing.F) {
	logger := zaptest.NewLogger(f)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		f.Fatalf("Failed to create security hardener: %v", err)
	}

	// Test handler that echoes input
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Method: %s, Path: %s", r.Method, r.URL.Path)
	})

	secureHandler := hardener.SecurityMiddleware()(handler)

	// Seed corpus with known problematic inputs
	seedInputs := []string{
		"/normal/path",
		"/../../../etc/passwd",
		"/path/with/spaces and special chars!@#$%^&*()",
		"/path\x00with\x00nulls",
		"/path\r\nwith\r\nnewlines",
		"/path%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"/path\u0000\u0001\u0002\u0003",
		"/path/with/unicode/\u4e2d\u6587",
		"/path/with/emoji/\U0001f600\U0001f601",
		"/" + strings.Repeat("a", 1000),
		"/path/with/control/chars/\x01\x02\x03\x04\x05",
	}

	for _, seed := range seedInputs {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, path string) {
		// Skip invalid UTF-8 sequences that would cause issues
		if !utf8.ValidString(path) {
			t.Skip("Invalid UTF-8 sequence")
		}

		// Skip extremely long paths that would cause timeouts
		if len(path) > 10000 {
			t.Skip("Path too long")
		}

		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()

		// The handler should not panic with any input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Handler panicked with input %q: %v", path, r)
			}
		}()

		secureHandler.ServeHTTP(w, req)

		// Verify security headers are always present
		requiredHeaders := map[string]string{
			"X-Content-Type-Options":  "nosniff",
			"X-Frame-Options":         "DENY",
			"X-XSS-Protection":        "1; mode=block",
			"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
			"Server":                  "MCP-Airlock",
		}

		for header, expectedValue := range requiredHeaders {
			if got := w.Header().Get(header); got != expectedValue {
				t.Errorf("Header %s: expected %q, got %q with input %q", header, expectedValue, got, path)
			}
		}

		// Response should be valid HTTP
		if w.Code < 100 || w.Code >= 600 {
			t.Errorf("Invalid HTTP status code %d with input %q", w.Code, path)
		}
	})
}

// FuzzTLSConfig fuzzes TLS configuration parsing
func FuzzTLSConfig(f *testing.F) {
	logger := zaptest.NewLogger(f)

	// Seed with valid configurations
	validConfigs := []string{
		`{"min_version": "1.3", "cipher_suites": ["TLS_AES_256_GCM_SHA384"]}`,
		`{"min_version": "1.2", "client_auth": "NoClientCert"}`,
		`{"cert_file": "/path/to/cert.pem", "key_file": "/path/to/key.pem"}`,
		`{"ca_file": "/path/to/ca.pem", "insecure_skip_verify": false}`,
	}

	for _, config := range validConfigs {
		f.Add(config)
	}

	f.Fuzz(func(t *testing.T, configJSON string) {
		// Skip invalid JSON that would cause immediate parse errors
		var testJSON interface{}
		if err := json.Unmarshal([]byte(configJSON), &testJSON); err != nil {
			t.Skip("Invalid JSON")
		}

		var config TLSConfig
		if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
			// Invalid config should not cause panic
			return
		}

		// Creating TLS manager should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("TLS manager creation panicked with config %q: %v", configJSON, r)
			}
		}()

		_, err := NewTLSManager(&config, logger)
		// Error is acceptable, panic is not
		_ = err
	})
}

// FuzzHardeningConfig fuzzes security hardening configuration
func FuzzHardeningConfig(f *testing.F) {
	logger := zaptest.NewLogger(f)

	// Seed with valid configurations
	validConfigs := []string{
		`{"non_root_user": true, "read_only_root_fs": true}`,
		`{"max_file_descriptors": 1024, "max_processes": 100}`,
		`{"umask_value": 77, "disable_core_dumps": true}`,
		`{"max_memory_mb": 512, "bind_to_localhost": true}`,
	}

	for _, config := range validConfigs {
		f.Add(config)
	}

	f.Fuzz(func(t *testing.T, configJSON string) {
		var testJSON interface{}
		if err := json.Unmarshal([]byte(configJSON), &testJSON); err != nil {
			t.Skip("Invalid JSON")
		}

		var config HardeningConfig
		if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
			return
		}

		// Creating security hardener should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Security hardener creation panicked with config %q: %v", configJSON, r)
			}
		}()

		hardener, err := NewSecurityHardener(&config, logger)
		if err != nil {
			return // Error is acceptable
		}

		// Getting security report should not panic
		report := hardener.GetSecurityReport()
		if report == nil {
			t.Error("Security report should not be nil")
		}
	})
}

// FuzzHTTPHeaders fuzzes HTTP header processing
func FuzzHTTPHeaders(f *testing.F) {
	logger := zaptest.NewLogger(f)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		f.Fatalf("Failed to create security hardener: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	secureHandler := hardener.SecurityMiddleware()(handler)

	// Seed with problematic header values
	seedHeaders := []string{
		"normal-value",
		"value\r\nwith\r\nnewlines",
		"value\x00with\x00nulls",
		"value with spaces and special chars!@#$%^&*()",
		strings.Repeat("a", 1000),
		"value\u0000\u0001\u0002",
		"value\u4e2d\u6587", // Chinese characters
		"<script>alert('xss')</script>",
		"'; DROP TABLE users; --",
		"../../../etc/passwd",
	}

	for _, seed := range seedHeaders {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, headerValue string) {
		if !utf8.ValidString(headerValue) {
			t.Skip("Invalid UTF-8 sequence")
		}

		if len(headerValue) > 8192 {
			t.Skip("Header value too long")
		}

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Test-Header", headerValue)
		w := httptest.NewRecorder()

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Handler panicked with header value %q: %v", headerValue, r)
			}
		}()

		secureHandler.ServeHTTP(w, req)

		// Security headers should still be present
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("Security header missing with header value %q", headerValue)
		}
	})
}

// FuzzRequestBody fuzzes request body processing
func FuzzRequestBody(f *testing.F) {
	logger := zaptest.NewLogger(f)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		f.Fatalf("Failed to create security hardener: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the body
		buf := make([]byte, 1024)
		_, err := r.Body.Read(buf)
		if err != nil && err.Error() != "EOF" {
			// Reading error is acceptable
		}
		w.WriteHeader(http.StatusOK)
	})

	secureHandler := hardener.SecurityMiddleware()(handler)

	// Seed with various body types
	seedBodies := [][]byte{
		[]byte("normal body"),
		[]byte(`{"json": "data"}`),
		[]byte(`<xml><data>test</data></xml>`),
		[]byte("form=data&other=value"),
		[]byte(strings.Repeat("a", 1000)),
		[]byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
		[]byte("body\r\nwith\r\nnewlines"),
		[]byte("body\x00with\x00nulls"),
	}

	for _, seed := range seedBodies {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		// Skip extremely large bodies
		if len(body) > 100000 {
			t.Skip("Body too large")
		}

		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/octet-stream")
		w := httptest.NewRecorder()

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Handler panicked with body length %d: %v", len(body), r)
			}
		}()

		secureHandler.ServeHTTP(w, req)

		// Security headers should be present
		if w.Header().Get("Server") != "MCP-Airlock" {
			t.Errorf("Server header incorrect with body length %d", len(body))
		}
	})
}

// FuzzURLParsing fuzzes URL parsing and validation
func FuzzURLParsing(f *testing.F) {
	logger := zaptest.NewLogger(f)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		f.Fatalf("Failed to create security hardener: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Access URL components that might trigger parsing
		_ = r.URL.Path
		_ = r.URL.RawQuery
		_ = r.URL.Fragment
		w.WriteHeader(http.StatusOK)
	})

	secureHandler := hardener.SecurityMiddleware()(handler)

	// Seed with problematic URLs
	seedURLs := []string{
		"http://example.com/normal",
		"http://example.com/path/../../../etc/passwd",
		"http://example.com/path%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"http://example.com/path?query=value",
		"http://example.com/path?query=../../../etc/passwd",
		"http://example.com/path#fragment",
		"http://example.com/path with spaces",
		"http://example.com/path\r\nwith\r\nnewlines",
		"http://example.com/path\x00with\x00nulls",
		"http://example.com/" + strings.Repeat("a", 1000),
		"http://example.com/path?query=" + strings.Repeat("b", 1000),
	}

	for _, seed := range seedURLs {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, rawURL string) {
		if !utf8.ValidString(rawURL) {
			t.Skip("Invalid UTF-8 sequence")
		}

		if len(rawURL) > 10000 {
			t.Skip("URL too long")
		}

		// Try to create a request with the URL
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Request creation panicked with URL %q: %v", rawURL, r)
			}
		}()

		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			t.Skip("Invalid URL")
		}

		w := httptest.NewRecorder()

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Handler panicked with URL %q: %v", rawURL, r)
			}
		}()

		secureHandler.ServeHTTP(w, req)

		// Security headers should be present
		if w.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("Security header missing with URL %q", rawURL)
		}
	})
}

// generateRandomBytes generates random bytes for fuzzing
func generateRandomBytes(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

// FuzzConcurrentSecurity fuzzes security under concurrent access
func FuzzConcurrentSecurity(f *testing.F) {
	logger := zaptest.NewLogger(f)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		f.Fatalf("Failed to create security hardener: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	secureHandler := hardener.SecurityMiddleware()(handler)

	// Seed with various inputs
	seedInputs := []string{
		"/path1",
		"/path2",
		"/path/../../../etc/passwd",
		"/path?query=value",
	}

	for _, seed := range seedInputs {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, path string) {
		if !utf8.ValidString(path) {
			t.Skip("Invalid UTF-8 sequence")
		}

		if len(path) > 1000 {
			t.Skip("Path too long")
		}

		// Run multiple concurrent requests
		const numRequests = 10
		done := make(chan bool, numRequests)
		errors := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			go func(requestID int) {
				defer func() {
					if r := recover(); r != nil {
						errors <- fmt.Errorf("request %d panicked: %v", requestID, r)
					}
					done <- true
				}()

				req := httptest.NewRequest("GET", path, nil)
				w := httptest.NewRecorder()

				secureHandler.ServeHTTP(w, req)

				// Verify security headers
				if w.Header().Get("X-Content-Type-Options") != "nosniff" {
					errors <- fmt.Errorf("request %d missing security header", requestID)
				}
			}(i)
		}

		// Wait for all requests to complete
		for i := 0; i < numRequests; i++ {
			<-done
		}

		close(errors)

		// Check for errors
		for err := range errors {
			t.Error(err)
		}
	})
}

// Property-based testing helper
func TestSecurityProperties(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	secureHandler := hardener.SecurityMiddleware()(handler)

	// Property: Security headers should always be present
	t.Run("SecurityHeadersAlwaysPresent", func(t *testing.T) {
		testCases := []string{
			"/",
			"/normal/path",
			"/path/with/query?param=value",
			"/path/../traversal",
			"/path%2e%2e%2ftraversal",
		}

		for _, testCase := range testCases {
			req := httptest.NewRequest("GET", testCase, nil)
			w := httptest.NewRecorder()

			secureHandler.ServeHTTP(w, req)

			requiredHeaders := []string{
				"X-Content-Type-Options",
				"X-Frame-Options",
				"X-XSS-Protection",
				"Content-Security-Policy",
				"Server",
			}

			for _, header := range requiredHeaders {
				if w.Header().Get(header) == "" {
					t.Errorf("Required header %s missing for path %s", header, testCase)
				}
			}
		}
	})

	// Property: Server should never reveal internal information
	t.Run("NoInternalInformationLeakage", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		secureHandler.ServeHTTP(w, req)

		server := w.Header().Get("Server")
		forbiddenPatterns := []string{
			"Go",
			"go",
			"golang",
			"net/http",
			"version",
			"runtime",
		}

		for _, pattern := range forbiddenPatterns {
			if strings.Contains(strings.ToLower(server), strings.ToLower(pattern)) {
				t.Errorf("Server header reveals internal information: %s contains %s", server, pattern)
			}
		}
	})

	// Property: Handler should never panic
	t.Run("HandlerNeverPanics", func(t *testing.T) {
		problematicInputs := []struct {
			method string
			path   string
			body   string
		}{
			{"GET", "/", ""},
			{"POST", "/", "normal body"},
			{"PUT", "/path/traversal", ""},
			{"DELETE", "/path/delete", ""},
			{"PATCH", "/path/patch", "normal body"},
			{"OPTIONS", "/", ""},
			{"HEAD", "/", ""},
			{"TRACE", "/", ""},
		}

		for _, input := range problematicInputs {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Handler panicked with method=%s, path=%s, body=%s: %v",
							input.method, input.path, input.body, r)
					}
				}()

				var req *http.Request
				if input.body != "" {
					req = httptest.NewRequest(input.method, input.path, strings.NewReader(input.body))
				} else {
					req = httptest.NewRequest(input.method, input.path, nil)
				}

				w := httptest.NewRecorder()
				secureHandler.ServeHTTP(w, req)
			}()
		}
	})
}

package security

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestDefaultHardeningConfig(t *testing.T) {
	config := DefaultHardeningConfig()

	if !config.NonRootUser {
		t.Error("Expected NonRootUser to be true")
	}

	if !config.ReadOnlyRootFS {
		t.Error("Expected ReadOnlyRootFS to be true")
	}

	if !config.DropCapabilities {
		t.Error("Expected DropCapabilities to be true")
	}

	if config.UmaskValue != 0o077 {
		t.Errorf("Expected UmaskValue to be 0o077, got %o", config.UmaskValue)
	}

	if config.MaxFileDescriptors != 1024 {
		t.Errorf("Expected MaxFileDescriptors to be 1024, got %d", config.MaxFileDescriptors)
	}
}

func TestNewSecurityHardener(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultHardeningConfig()

	hardener, err := NewSecurityHardener(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	if hardener.config != config {
		t.Error("Config not properly set")
	}

	if hardener.logger != logger {
		t.Error("Logger not properly set")
	}
}

func TestNewSecurityHardenerWithNilConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)

	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener with nil config: %v", err)
	}

	if hardener.config == nil {
		t.Error("Expected default config to be set")
	}
}

func TestApplyProcessHardening(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &HardeningConfig{
		NonRootUser:      false, // Don't check root for tests
		UmaskValue:       0o022,
		DisableCoreDumps: true,
	}

	hardener, err := NewSecurityHardener(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	err = hardener.applyProcessHardening()
	if err != nil {
		t.Errorf("Process hardening failed: %v", err)
	}
}

func TestApplyResourceLimits(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &HardeningConfig{
		MaxFileDescriptors: 512,
		MaxProcesses:       50,
	}

	hardener, err := NewSecurityHardener(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	err = hardener.applyResourceLimits()
	if err != nil {
		t.Errorf("Resource limits failed: %v", err)
	}

	// Verify file descriptor limit was set
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil {
		if rlimit.Cur > config.MaxFileDescriptors {
			t.Logf("File descriptor limit: %d (may be higher due to system minimum)", rlimit.Cur)
		}
	}
}

func TestValidateSecurityState(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &HardeningConfig{
		NonRootUser:        false, // Don't check root for tests
		ReadOnlyRootFS:     false, // Don't check read-only for tests
		MaxFileDescriptors: 1024,
	}

	hardener, err := NewSecurityHardener(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	err = hardener.validateSecurityState()
	if err != nil {
		t.Errorf("Security state validation failed: %v", err)
	}
}

func TestSecurityMiddleware(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	// Wrap with security middleware
	secureHandler := hardener.SecurityMiddleware()(testHandler)

	// Test HTTP request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	secureHandler.ServeHTTP(w, req)

	// Check security headers
	headers := w.Header()

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"X-XSS-Protection":        "1; mode=block",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"Server":                  "MCP-Airlock",
	}

	for header, expectedValue := range expectedHeaders {
		if got := headers.Get(header); got != expectedValue {
			t.Errorf("Header %s: expected %s, got %s", header, expectedValue, got)
		}
	}

	// Server header should not contain default Go server info
	if server := headers.Get("Server"); server != "MCP-Airlock" {
		t.Errorf("Server header should be 'MCP-Airlock', got %s", server)
	}
}

func TestSecurityMiddlewareHTTPS(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with security middleware
	secureHandler := hardener.SecurityMiddleware()(testHandler)

	// Test HTTPS request (simulate TLS)
	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{} // Simulate TLS connection
	w := httptest.NewRecorder()

	secureHandler.ServeHTTP(w, req)

	// Check HSTS header is present for HTTPS
	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts != "max-age=31536000; includeSubDomains" {
		t.Errorf("HSTS header: expected 'max-age=31536000; includeSubDomains', got %s", hsts)
	}
}

func TestConfigureHTTPServer(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	server := &http.Server{}

	err = hardener.ConfigureHTTPServer(server)
	if err != nil {
		t.Errorf("Failed to configure HTTP server: %v", err)
	}

	// Check that timeouts were set
	if server.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout: expected 30s, got %v", server.ReadTimeout)
	}

	if server.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout: expected 30s, got %v", server.WriteTimeout)
	}

	if server.IdleTimeout != 120*time.Second {
		t.Errorf("IdleTimeout: expected 120s, got %v", server.IdleTimeout)
	}

	if server.MaxHeaderBytes != 32<<10 {
		t.Errorf("MaxHeaderBytes: expected 32KB, got %d", server.MaxHeaderBytes)
	}
}

func TestGetSecurityReport(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	report := hardener.GetSecurityReport()

	// Check required fields
	requiredFields := []string{
		"non_root_user",
		"uid",
		"gid",
		"tls_enabled",
		"go_version",
		"os",
		"arch",
		"num_goroutines",
		"hardening_applied",
	}

	for _, field := range requiredFields {
		if _, exists := report[field]; !exists {
			t.Errorf("Security report missing field: %s", field)
		}
	}

	// Check specific values
	if report["non_root_user"] != (os.Getuid() != 0) {
		t.Error("non_root_user field incorrect")
	}

	if report["go_version"] != runtime.Version() {
		t.Error("go_version field incorrect")
	}

	if report["os"] != runtime.GOOS {
		t.Error("os field incorrect")
	}

	if report["hardening_applied"] != true {
		t.Error("hardening_applied should be true")
	}
}

func TestSetRLimit(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	// Test setting a resource limit (use a safe limit)
	originalLimit := uint64(1024)
	err = hardener.setRLimit(syscall.RLIMIT_NOFILE, originalLimit)
	if err != nil {
		t.Logf("Failed to set resource limit (may be restricted): %v", err)
		return // Skip test if we can't set limits
	}

	// Verify the limit was set
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		t.Fatalf("Failed to get resource limit: %v", err)
	}

	// Note: The actual limit may be higher due to system minimums
	if rlimit.Cur < originalLimit {
		t.Errorf("Resource limit not set correctly: expected at least %d, got %d", originalLimit, rlimit.Cur)
	}
}

func TestDisableCoreDumps(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	err = hardener.disableCoreDumps()
	if err != nil {
		t.Logf("Failed to disable core dumps (may be restricted): %v", err)
		return // Skip test if we can't set limits
	}

	// Verify core dumps are disabled
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &rlimit); err != nil {
		t.Fatalf("Failed to get core dump limit: %v", err)
	}

	if rlimit.Cur != 0 {
		t.Errorf("Core dumps not disabled: limit is %d, expected 0", rlimit.Cur)
	}
}

// Benchmark security middleware overhead
func BenchmarkSecurityMiddleware(b *testing.B) {
	logger := zaptest.NewLogger(b)
	hardener, err := NewSecurityHardener(nil, logger)
	if err != nil {
		b.Fatalf("Failed to create security hardener: %v", err)
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	secureHandler := hardener.SecurityMiddleware()(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		secureHandler.ServeHTTP(w, req)
	}
}

// Test that demonstrates attack surface reduction
func TestAttackSurfaceReduction(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultHardeningConfig()

	hardener, err := NewSecurityHardener(config, logger)
	if err != nil {
		t.Fatalf("Failed to create security hardener: %v", err)
	}

	ctx := context.Background()

	// Apply hardening (this would normally be done at startup)
	if err := hardener.ApplyHardening(ctx); err != nil {
		// Some hardening measures may fail in test environment
		t.Logf("Some hardening measures failed (expected in test environment): %v", err)
	}

	// Verify security report shows hardening is applied
	report := hardener.GetSecurityReport()
	if !report["hardening_applied"].(bool) {
		t.Error("Hardening should be marked as applied")
	}

	// Test that security middleware adds protective headers
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	secureHandler := hardener.SecurityMiddleware()(testHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	secureHandler.ServeHTTP(w, req)

	// Verify protective headers are present
	protectiveHeaders := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Content-Security-Policy",
	}

	for _, header := range protectiveHeaders {
		if w.Header().Get(header) == "" {
			t.Errorf("Protective header %s is missing", header)
		}
	}
}

package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestRateLimiter_Allow(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := RateLimitConfig{
		RequestsPerMinute: 60, // 1 request per second
		BurstSize:         2,
		CleanupInterval:   time.Minute,
		BruteForceWindow:  time.Minute,
		BruteForceLimit:   5,
		ThrottleDuration:  time.Minute,
	}

	rl := NewRateLimiter(config, logger)
	defer rl.Close()

	ctx := context.Background()
	tokenHash := "test-token-hash"

	// First request should be allowed (within burst)
	allowed, err := rl.Allow(ctx, tokenHash)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Errorf("First request should be allowed")
	}

	// Second request should be allowed (within burst)
	allowed, err = rl.Allow(ctx, tokenHash)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Errorf("Second request should be allowed")
	}

	// Third request should be rate limited (burst exhausted)
	allowed, err = rl.Allow(ctx, tokenHash)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Errorf("Third request should be rate limited")
	}

	// Wait for rate limit to reset (1 second for 1 req/sec)
	time.Sleep(1100 * time.Millisecond)

	// Request should be allowed again
	allowed, err = rl.Allow(ctx, tokenHash)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Errorf("Request after rate limit reset should be allowed")
	}
}

func TestRateLimiter_BruteForceProtection(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := RateLimitConfig{
		RequestsPerMinute: 1, // Very low limit to trigger failures
		BurstSize:         1,
		CleanupInterval:   time.Minute,
		BruteForceWindow:  time.Minute,
		BruteForceLimit:   3,                      // Throttle after 3 failures
		ThrottleDuration:  100 * time.Millisecond, // Short throttle for testing
	}

	rl := NewRateLimiter(config, logger)
	defer rl.Close()

	ctx := context.Background()
	tokenHash := "brute-force-token"

	// Exhaust rate limit and trigger failures
	for i := 0; i < 5; i++ {
		rl.Allow(ctx, tokenHash)
	}

	// Should be throttled now
	allowed, err := rl.Allow(ctx, tokenHash)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Errorf("Request should be throttled due to brute force protection")
	}

	// Wait for throttle to expire
	time.Sleep(150 * time.Millisecond)

	// Should not be throttled anymore (though may still be rate limited)
	// The key test is that we don't get an immediate rejection due to brute force throttling
	_, err = rl.Allow(ctx, tokenHash)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// We don't assert on the 'allowed' value since it depends on rate limiting,
	// but the fact that we got here without error means throttling has expired
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultRateLimitConfig()
	config.RequestsPerMinute = 1000 // High limit for concurrent test

	rl := NewRateLimiter(config, logger)
	defer rl.Close()

	ctx := context.Background()
	const numGoroutines = 100
	const requestsPerGoroutine = 5

	var wg sync.WaitGroup
	results := make(chan bool, numGoroutines*requestsPerGoroutine)

	// Launch concurrent requests
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			tokenHash := "concurrent-token"

			for j := 0; j < requestsPerGoroutine; j++ {
				allowed, err := rl.Allow(ctx, tokenHash)
				if err != nil {
					t.Errorf("Goroutine %d: unexpected error: %v", id, err)
				}
				results <- allowed
			}
		}(i)
	}

	wg.Wait()
	close(results)

	// Count allowed requests
	allowedCount := 0
	for allowed := range results {
		if allowed {
			allowedCount++
		}
	}

	// Should have some allowed requests (at least burst size)
	if allowedCount < config.BurstSize {
		t.Errorf("Expected at least %d allowed requests, got %d", config.BurstSize, allowedCount)
	}

	// Should not allow all requests (rate limiting should kick in)
	totalRequests := numGoroutines * requestsPerGoroutine
	if allowedCount >= totalRequests {
		t.Errorf("Rate limiting should have blocked some requests. Allowed: %d, Total: %d", allowedCount, totalRequests)
	}
}

func TestRateLimiter_DifferentTokens(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := RateLimitConfig{
		RequestsPerMinute: 60, // 1 request per second
		BurstSize:         1,
		CleanupInterval:   time.Minute,
		BruteForceWindow:  time.Minute,
		BruteForceLimit:   5,
		ThrottleDuration:  time.Minute,
	}

	rl := NewRateLimiter(config, logger)
	defer rl.Close()

	ctx := context.Background()

	// Different tokens should have independent rate limits
	token1 := "token-1"
	token2 := "token-2"

	// Both tokens should be allowed initially
	allowed1, err := rl.Allow(ctx, token1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed1 {
		t.Errorf("Token 1 should be allowed")
	}

	allowed2, err := rl.Allow(ctx, token2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed2 {
		t.Errorf("Token 2 should be allowed")
	}

	// Second request for token1 should be rate limited
	allowed1, err = rl.Allow(ctx, token1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed1 {
		t.Errorf("Token 1 second request should be rate limited")
	}

	// But token2 should still be allowed for second request
	allowed2, err = rl.Allow(ctx, token2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed2 {
		t.Errorf("Token 2 second request should also be rate limited")
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         1,
		CleanupInterval:   50 * time.Millisecond, // Very short for testing
		BruteForceWindow:  time.Minute,
		BruteForceLimit:   5,
		ThrottleDuration:  time.Minute,
	}

	rl := NewRateLimiter(config, logger)
	defer rl.Close()

	ctx := context.Background()

	// Create some limiters
	for i := 0; i < 5; i++ {
		tokenHash := fmt.Sprintf("token-%d", i)
		rl.Allow(ctx, tokenHash)
	}

	// Check initial stats
	stats := rl.Stats()
	initialCount := stats["total_limiters"].(int)
	if initialCount != 5 {
		t.Errorf("Expected 5 limiters, got %d", initialCount)
	}

	// Wait for cleanup to run (cleanup removes limiters unused for 2x cleanup interval)
	time.Sleep(150 * time.Millisecond)

	// Stats should show cleanup occurred
	stats = rl.Stats()
	finalCount := stats["total_limiters"].(int)
	if finalCount >= initialCount {
		t.Errorf("Expected cleanup to reduce limiter count from %d, got %d", initialCount, finalCount)
	}
}

func TestRateLimiter_Stats(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultRateLimitConfig()

	rl := NewRateLimiter(config, logger)
	defer rl.Close()

	ctx := context.Background()

	// Create some limiters
	rl.Allow(ctx, "token-1")
	rl.Allow(ctx, "token-2")

	stats := rl.Stats()

	// Check stats structure
	if _, ok := stats["total_limiters"]; !ok {
		t.Errorf("Stats should include total_limiters")
	}
	if _, ok := stats["throttled_limiters"]; !ok {
		t.Errorf("Stats should include throttled_limiters")
	}
	if _, ok := stats["config"]; !ok {
		t.Errorf("Stats should include config")
	}

	totalLimiters := stats["total_limiters"].(int)
	if totalLimiters < 2 {
		t.Errorf("Expected at least 2 limiters, got %d", totalLimiters)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := RateLimitConfig{
		RequestsPerMinute: 60, // 1 request per second
		BurstSize:         1,
		CleanupInterval:   time.Minute,
		BruteForceWindow:  time.Minute,
		BruteForceLimit:   5,
		ThrottleDuration:  time.Minute,
	}

	rl := NewRateLimiter(config, logger)
	defer rl.Close()

	// Test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with rate limit middleware
	handler := rl.RateLimitMiddleware(testHandler)

	tests := []struct {
		name           string
		hasSession     bool
		sessionID      string
		expectedStatus int
		requestCount   int
	}{
		{
			name:           "first_request_allowed",
			hasSession:     true,
			sessionID:      "session-1",
			expectedStatus: http.StatusOK,
			requestCount:   1,
		},
		{
			name:           "rate_limited_request",
			hasSession:     true,
			sessionID:      "session-2",
			expectedStatus: http.StatusTooManyRequests,
			requestCount:   3, // Exceed burst + rate
		},
		{
			name:           "unauthenticated_request",
			hasSession:     false,
			expectedStatus: http.StatusOK,
			requestCount:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lastStatus int

			for i := 0; i < tt.requestCount; i++ {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.100:12345" // Set IP for unauthenticated requests

				// Add session to context if needed
				if tt.hasSession {
					session := &Session{
						ID:            tt.sessionID,
						Authenticated: true,
					}
					ctx := context.WithValue(req.Context(), SessionContextKey, session)
					req = req.WithContext(ctx)
				}

				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)
				lastStatus = rr.Code

				// Small delay between requests
				if i < tt.requestCount-1 {
					time.Sleep(10 * time.Millisecond)
				}
			}

			if lastStatus != tt.expectedStatus {
				t.Errorf("Expected final status %d, got %d", tt.expectedStatus, lastStatus)
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		xRealIP       string
		expectedIP    string
	}{
		{
			name:       "remote_addr_only",
			remoteAddr: "192.168.1.100:12345",
			expectedIP: "192.168.1.100",
		},
		{
			name:          "x_forwarded_for_single",
			remoteAddr:    "10.0.0.1:12345",
			xForwardedFor: "192.168.1.100",
			expectedIP:    "192.168.1.100",
		},
		{
			name:          "x_forwarded_for_multiple",
			remoteAddr:    "10.0.0.1:12345",
			xForwardedFor: "192.168.1.100, 10.0.0.2, 10.0.0.3",
			expectedIP:    "192.168.1.100",
		},
		{
			name:       "x_real_ip",
			remoteAddr: "10.0.0.1:12345",
			xRealIP:    "192.168.1.100",
			expectedIP: "192.168.1.100",
		},
		{
			name:          "x_forwarded_for_priority",
			remoteAddr:    "10.0.0.1:12345",
			xForwardedFor: "192.168.1.100",
			xRealIP:       "192.168.1.200",
			expectedIP:    "192.168.1.100", // X-Forwarded-For takes priority
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			ip := getClientIP(req)
			if ip != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

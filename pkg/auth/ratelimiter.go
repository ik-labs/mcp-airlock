package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

// RateLimitConfig holds the configuration for rate limiting
type RateLimitConfig struct {
	RequestsPerMinute int           `yaml:"requests_per_minute"`
	BurstSize         int           `yaml:"burst_size"`
	CleanupInterval   time.Duration `yaml:"cleanup_interval"`
	BruteForceWindow  time.Duration `yaml:"brute_force_window"`
	BruteForceLimit   int           `yaml:"brute_force_limit"`
	ThrottleDuration  time.Duration `yaml:"throttle_duration"`
}

// DefaultRateLimitConfig returns default rate limiting configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerMinute: 200,             // 200 requests per minute (~3.33 req/sec)
		BurstSize:         10,              // Allow burst of 10 requests
		CleanupInterval:   5 * time.Minute, // Clean up old limiters every 5 minutes
		BruteForceWindow:  time.Minute,     // Track failures over 1 minute window
		BruteForceLimit:   10,              // Max 10 failures per minute
		ThrottleDuration:  5 * time.Minute, // Throttle for 5 minutes after brute force
	}
}

// tokenLimiter holds rate limiter and metadata for a specific token
type tokenLimiter struct {
	limiter        *rate.Limiter
	mu             sync.RWMutex
	lastAccess     time.Time
	failureCount   int
	failureWindow  time.Time
	throttledUntil time.Time
}

// RateLimiter provides per-token rate limiting with brute-force protection
type RateLimiter struct {
	config        RateLimitConfig
	limiters      sync.Map // map[string]*tokenLimiter
	logger        *zap.Logger
	sf            singleflight.Group
	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc
	cleanupDone   chan struct{}
}

// NewRateLimiter creates a new rate limiter with the given configuration
func NewRateLimiter(config RateLimitConfig, logger *zap.Logger) *RateLimiter {
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())

	rl := &RateLimiter{
		config:        config,
		logger:        logger,
		cleanupCtx:    cleanupCtx,
		cleanupCancel: cleanupCancel,
		cleanupDone:   make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.startCleanup()

	return rl
}

// Allow checks if a request should be allowed for the given token
func (rl *RateLimiter) Allow(ctx context.Context, tokenHash string) (bool, error) {
	// Use singleflight to prevent thundering herd when creating new limiters
	limiterInterface, err, _ := rl.sf.Do(tokenHash, func() (interface{}, error) {
		return rl.getLimiter(tokenHash), nil
	})
	if err != nil {
		return false, fmt.Errorf("failed to get limiter: %w", err)
	}

	limiter := limiterInterface.(*tokenLimiter)

	// Check if currently throttled due to brute force
	now := time.Now()

	limiter.mu.RLock()
	throttledUntil := limiter.throttledUntil
	limiter.mu.RUnlock()

	if now.Before(throttledUntil) {
		rl.logger.Warn("Request blocked due to throttling",
			zap.String("token_hash", tokenHash),
			zap.Time("throttled_until", throttledUntil))
		return false, nil
	}

	// Check rate limit
	allowed := limiter.limiter.AllowN(now, 1)

	limiter.mu.Lock()
	limiter.lastAccess = now
	if allowed {
		// Reset failure count on successful request
		limiter.failureCount = 0
		limiter.failureWindow = time.Time{}
	}
	limiter.mu.Unlock()

	if !allowed {
		// Track failure for brute force protection
		rl.trackFailure(limiter, now, tokenHash)
	}

	return allowed, nil
}

// getLimiter gets or creates a rate limiter for the given token
func (rl *RateLimiter) getLimiter(tokenHash string) *tokenLimiter {
	if limiterInterface, exists := rl.limiters.Load(tokenHash); exists {
		return limiterInterface.(*tokenLimiter)
	}

	// Create new limiter
	// Convert requests per minute to requests per second
	rps := rate.Limit(float64(rl.config.RequestsPerMinute) / 60.0)
	limiter := &tokenLimiter{
		limiter:    rate.NewLimiter(rps, rl.config.BurstSize),
		lastAccess: time.Now(),
	}

	// Store in map (may overwrite if another goroutine created one)
	rl.limiters.Store(tokenHash, limiter)

	rl.logger.Debug("Created new rate limiter",
		zap.String("token_hash", tokenHash),
		zap.Float64("rate_per_second", float64(rps)),
		zap.Int("burst_size", rl.config.BurstSize))

	return limiter
}

// trackFailure tracks authentication/rate limit failures for brute force protection
func (rl *RateLimiter) trackFailure(limiter *tokenLimiter, now time.Time, tokenHash string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	// Reset failure window if it's been too long
	if now.Sub(limiter.failureWindow) > rl.config.BruteForceWindow {
		limiter.failureCount = 0
		limiter.failureWindow = now
	}

	limiter.failureCount++

	// Check if we've exceeded the brute force limit
	if limiter.failureCount >= rl.config.BruteForceLimit {
		// Apply exponential backoff based on failure count
		backoffMultiplier := 1
		if limiter.failureCount > rl.config.BruteForceLimit {
			backoffMultiplier = limiter.failureCount - rl.config.BruteForceLimit + 1
		}

		throttleDuration := time.Duration(backoffMultiplier) * rl.config.ThrottleDuration
		limiter.throttledUntil = now.Add(throttleDuration)

		rl.logger.Warn("Token throttled due to brute force attempts",
			zap.String("token_hash", tokenHash),
			zap.Int("failure_count", limiter.failureCount),
			zap.Duration("throttle_duration", throttleDuration),
			zap.Time("throttled_until", limiter.throttledUntil))
	}
}

// startCleanup runs the background cleanup goroutine
func (rl *RateLimiter) startCleanup() {
	defer close(rl.cleanupDone)

	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()

		case <-rl.cleanupCtx.Done():
			rl.logger.Info("Rate limiter cleanup goroutine stopping")
			return
		}
	}
}

// cleanup removes old, unused rate limiters
func (rl *RateLimiter) cleanup() {
	now := time.Now()
	cleanupThreshold := rl.config.CleanupInterval * 2 // Clean up limiters unused for 2x cleanup interval

	var removedCount int

	rl.limiters.Range(func(key, value interface{}) bool {
		limiter := value.(*tokenLimiter)

		limiter.mu.RLock()
		lastAccess := limiter.lastAccess
		throttledUntil := limiter.throttledUntil
		limiter.mu.RUnlock()

		// Remove if not accessed recently and not currently throttled
		if now.Sub(lastAccess) > cleanupThreshold && now.After(throttledUntil) {
			rl.limiters.Delete(key)
			removedCount++
		}

		return true // Continue iteration
	})

	if removedCount > 0 {
		rl.logger.Info("Cleaned up old rate limiters",
			zap.Int("removed_count", removedCount))
	}
}

// Close stops the cleanup goroutine and cleans up resources
func (rl *RateLimiter) Close() error {
	rl.cleanupCancel()

	// Wait for cleanup goroutine to finish with timeout
	select {
	case <-rl.cleanupDone:
		rl.logger.Info("Rate limiter closed successfully")
	case <-time.After(5 * time.Second):
		rl.logger.Warn("Timeout waiting for rate limiter cleanup goroutine to stop")
	}

	return nil
}

// Stats returns statistics about the rate limiter
func (rl *RateLimiter) Stats() map[string]interface{} {
	var totalLimiters int
	var throttledLimiters int
	now := time.Now()

	rl.limiters.Range(func(key, value interface{}) bool {
		totalLimiters++
		limiter := value.(*tokenLimiter)

		limiter.mu.RLock()
		throttledUntil := limiter.throttledUntil
		limiter.mu.RUnlock()

		if now.Before(throttledUntil) {
			throttledLimiters++
		}
		return true
	})

	return map[string]interface{}{
		"total_limiters":     totalLimiters,
		"throttled_limiters": throttledLimiters,
		"config":             rl.config,
	}
}

// RateLimitMiddleware creates HTTP middleware for rate limiting
func (rl *RateLimiter) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token hash from context (set by auth middleware)
		var tokenHash string
		if session, ok := GetSessionFromContext(r.Context()); ok {
			tokenHash = session.ID // Use session ID as token hash
		} else {
			// Fallback to IP-based limiting for unauthenticated requests
			tokenHash = getClientIP(r)
		}

		// Check rate limit
		allowed, err := rl.Allow(r.Context(), tokenHash)
		if err != nil {
			rl.logger.Error("Rate limit check failed", zap.Error(err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if !allowed {
			rl.logger.Warn("Request rate limited",
				zap.String("token_hash", tokenHash),
				zap.String("path", r.URL.Path),
				zap.String("method", r.Method),
				zap.String("client_ip", getClientIP(r)))

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.config.RequestsPerMinute))
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("Retry-After", "60") // Suggest retry after 1 minute

			// Write JSON-RPC error response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)

			errorResponse := map[string]interface{}{
				"jsonrpc": "2.0",
				"error": map[string]interface{}{
					"code":    -32000, // Server error per JSON-RPC spec
					"message": "Rate limit exceeded",
					"data": map[string]interface{}{
						"retry_after": 60,
						"limit":       rl.config.RequestsPerMinute,
					},
				},
				"id": nil,
			}

			if err := writeJSON(w, errorResponse); err != nil {
				rl.logger.Error("Failed to write rate limit error response", zap.Error(err))
			}
			return
		}

		// Request allowed, continue
		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}

	return r.RemoteAddr
}

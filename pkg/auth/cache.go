package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// TokenCache provides high-performance caching for JWT validation results
type TokenCache struct {
	shards [16]*sync.Map // 16 shards to reduce contention
	ttl    time.Duration
	sf     singleflight.Group // Prevent thundering herd on cache misses
}

// CacheEntry represents a cached token validation result
type CacheEntry struct {
	claims    *Claims
	timestamp time.Time
	hash      string // Token hash for validation
}

// NewTokenCache creates a new token cache with the specified TTL
func NewTokenCache(ttl time.Duration) *TokenCache {
	tc := &TokenCache{
		ttl: ttl,
	}
	for i := range tc.shards {
		tc.shards[i] = &sync.Map{}
	}
	return tc
}

// Get retrieves a cached token validation result
func (tc *TokenCache) Get(ctx context.Context, tokenHash string) (*Claims, bool) {
	select {
	case <-ctx.Done():
		return nil, false
	default:
	}

	shard := tc.getShard(tokenHash)
	if entry, ok := shard.Load(tokenHash); ok {
		cached := entry.(*CacheEntry)
		if time.Since(cached.timestamp) < tc.ttl {
			return cached.claims, true
		}
		shard.Delete(tokenHash) // expired
	}
	return nil, false
}

// Set stores a token validation result in the cache
func (tc *TokenCache) Set(ctx context.Context, tokenHash string, claims *Claims) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	shard := tc.getShard(tokenHash)
	entry := &CacheEntry{
		claims:    claims,
		timestamp: time.Now(),
		hash:      tokenHash,
	}
	shard.Store(tokenHash, entry)
}

// GetOrValidate gets a cached result or validates the token using singleflight
func (tc *TokenCache) GetOrValidate(ctx context.Context, token string, validator func(context.Context, string) (*Claims, error)) (*Claims, error) {
	tokenHash := tc.hashToken(token)

	// Try cache first
	if claims, found := tc.Get(ctx, tokenHash); found {
		return claims, nil
	}

	// Use singleflight to prevent multiple validations of the same token
	result, err, _ := tc.sf.Do(tokenHash, func() (interface{}, error) {
		// Double-check cache after acquiring singleflight lock
		if claims, found := tc.Get(ctx, tokenHash); found {
			return claims, nil
		}

		// Validate token
		claims, err := validator(ctx, token)
		if err != nil {
			return nil, err
		}

		// Cache successful validation
		tc.Set(ctx, tokenHash, claims)
		return claims, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*Claims), nil
}

// getShard returns the appropriate shard for a token hash
func (tc *TokenCache) getShard(tokenHash string) *sync.Map {
	// Use first 4 bits of hash for shard selection
	if len(tokenHash) > 0 {
		return tc.shards[int(tokenHash[0])&0xF]
	}
	return tc.shards[0]
}

// hashToken creates a SHA256 hash of the token for cache key
func (tc *TokenCache) hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])[:16] // Use first 16 chars for cache key
}

// Stats returns cache statistics
func (tc *TokenCache) Stats() map[string]interface{} {
	totalEntries := 0
	for i := range tc.shards {
		tc.shards[i].Range(func(_, _ interface{}) bool {
			totalEntries++
			return true
		})
	}

	return map[string]interface{}{
		"total_entries": totalEntries,
		"shard_count":   len(tc.shards),
		"ttl_seconds":   tc.ttl.Seconds(),
	}
}

// Cleanup removes expired entries from all shards
func (tc *TokenCache) Cleanup() {
	now := time.Now()
	expiredCount := 0

	for i := range tc.shards {
		shard := tc.shards[i]
		var expiredKeys []interface{}

		shard.Range(func(key, value interface{}) bool {
			entry := value.(*CacheEntry)
			if now.Sub(entry.timestamp) > tc.ttl {
				expiredKeys = append(expiredKeys, key)
			}
			return true
		})

		for _, key := range expiredKeys {
			shard.Delete(key)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		// Could log cleanup stats if needed
	}
}

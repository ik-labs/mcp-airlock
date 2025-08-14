package auth

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

// JWKSCache provides high-performance caching for benchmarking
type JWKSCache struct {
	provider        *oidc.Provider
	cachedKeys      atomic.Value
	lastRefresh     atomic.Value
	refreshMutex    sync.Mutex
	sf              singleflight.Group
	logger          *zap.Logger
	refreshInterval time.Duration
	refreshTimeout  time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	refreshCount    int64
	refreshErrors   int64
	cacheHits       int64
	cacheMisses     int64
}

// NewJWKSCache creates a new JWKS cache
func NewJWKSCache(provider *oidc.Provider, refreshInterval time.Duration, logger *zap.Logger) *JWKSCache {
	ctx, cancel := context.WithCancel(context.Background())
	cache := &JWKSCache{
		provider:        provider,
		refreshInterval: refreshInterval,
		refreshTimeout:  10 * time.Second,
		logger:          logger,
		ctx:             ctx,
		cancel:          cancel,
	}
	cache.lastRefresh.Store(time.Time{})
	return cache
}

// Start begins the background refresh
func (jc *JWKSCache) Start() error {
	jc.refreshJWKS(context.Background())
	jc.wg.Add(1)
	go jc.backgroundRefresh()
	return nil
}

// Stop stops the background refresh
func (jc *JWKSCache) Stop() {
	jc.cancel()
	jc.wg.Wait()
}

// GetKeySet returns cached keys
func (jc *JWKSCache) GetKeySet(ctx context.Context) (interface{}, error) {
	if keySet := jc.cachedKeys.Load(); keySet != nil {
		atomic.AddInt64(&jc.cacheHits, 1)
		return keySet, nil
	}
	atomic.AddInt64(&jc.cacheMisses, 1)
	result, err, _ := jc.sf.Do("jwks", func() (interface{}, error) {
		if keySet := jc.cachedKeys.Load(); keySet != nil {
			return keySet, nil
		}
		return jc.fetchJWKS(ctx)
	})
	return result, err
}

// GetStats returns statistics
func (jc *JWKSCache) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"refresh_count":  atomic.LoadInt64(&jc.refreshCount),
		"refresh_errors": atomic.LoadInt64(&jc.refreshErrors),
		"cache_hits":     atomic.LoadInt64(&jc.cacheHits),
		"cache_misses":   atomic.LoadInt64(&jc.cacheMisses),
	}
}

// backgroundRefresh runs refresh loop
func (jc *JWKSCache) backgroundRefresh() {
	defer jc.wg.Done()
	ticker := time.NewTicker(jc.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			jc.refreshJWKS(jc.ctx)
		case <-jc.ctx.Done():
			return
		}
	}
}

// refreshJWKS performs refresh
func (jc *JWKSCache) refreshJWKS(ctx context.Context) error {
	jc.refreshMutex.Lock()
	defer jc.refreshMutex.Unlock()
	keySet, err := jc.fetchJWKS(ctx)
	if err != nil {
		atomic.AddInt64(&jc.refreshErrors, 1)
		return err
	}
	jc.cachedKeys.Store(keySet)
	jc.lastRefresh.Store(time.Now())
	atomic.AddInt64(&jc.refreshCount, 1)
	return nil
}

// fetchJWKS mock implementation
func (jc *JWKSCache) fetchJWKS(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"keys": []interface{}{"mock-key"}}, nil
}

// HealthCheck performs health check
func (jc *JWKSCache) HealthCheck(ctx context.Context) (string, string) {
	if jc.cachedKeys.Load() == nil {
		return "unhealthy", "No JWKS cached"
	}
	return "healthy", "JWKS healthy"
}

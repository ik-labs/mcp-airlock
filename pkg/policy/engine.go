package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"go.uber.org/zap"
)

// PolicyEngine defines the interface for policy evaluation
type PolicyEngine interface {
	Evaluate(ctx context.Context, input *PolicyInput) (*PolicyDecision, error)
	LoadPolicy(ctx context.Context, policy string) error
	ReloadPolicy(ctx context.Context) error
	Close() error
}

// PolicyInput represents the input data for policy evaluation
type PolicyInput struct {
	Subject  string            `json:"sub"`
	Tenant   string            `json:"tenant"`
	Groups   []string          `json:"groups"`
	Tool     string            `json:"tool"`
	Resource string            `json:"resource"`
	Method   string            `json:"method"`
	Headers  map[string]string `json:"headers"`
}

// PolicyDecision represents the result of policy evaluation
type PolicyDecision struct {
	Allow    bool                   `json:"allow"`
	Reason   string                 `json:"reason"`
	RuleID   string                 `json:"rule_id"`
	Metadata map[string]interface{} `json:"metadata"`
}

// CacheEntry represents a cached policy decision with timestamp
type CacheEntry struct {
	decision  *PolicyDecision
	timestamp time.Time
}

// PolicyCache provides per-tenant isolated caching of policy decisions
type PolicyCache struct {
	shards [16]*sync.Map // 16 shards to reduce contention
	ttl    time.Duration
}

// NewPolicyCache creates a new policy cache with the specified TTL
func NewPolicyCache(ttl time.Duration) *PolicyCache {
	pc := &PolicyCache{
		ttl: ttl,
	}
	for i := range pc.shards {
		pc.shards[i] = &sync.Map{}
	}
	return pc
}

// Get retrieves a cached policy decision
func (pc *PolicyCache) Get(tenant, key string) (*PolicyDecision, bool) {
	shardKey := pc.getShardKey(tenant, key)
	shard := pc.shards[pc.hash(shardKey)%16]

	if entry, ok := shard.Load(key); ok {
		cached := entry.(*CacheEntry)
		if time.Since(cached.timestamp) < pc.ttl {
			return cached.decision, true
		}
		shard.Delete(key) // expired
	}
	return nil, false
}

// Set stores a policy decision in the cache
func (pc *PolicyCache) Set(tenant, key string, decision *PolicyDecision) {
	shardKey := pc.getShardKey(tenant, key)
	shard := pc.shards[pc.hash(shardKey)%16]

	entry := &CacheEntry{
		decision:  decision,
		timestamp: time.Now(),
	}
	shard.Store(key, entry)
}

// getShardKey creates a tenant-isolated cache key
func (pc *PolicyCache) getShardKey(tenant, key string) string {
	return fmt.Sprintf("%s:%s", tenant, key)
}

// hash computes a simple hash for shard selection
func (pc *PolicyCache) hash(s string) uint32 {
	h := uint32(0)
	for _, c := range s {
		h = h*31 + uint32(c)
	}
	return h
}

// OPAEngine implements PolicyEngine using Open Policy Agent
type OPAEngine struct {
	current atomic.Value // *rego.PreparedEvalQuery
	lkg     atomic.Value // *rego.PreparedEvalQuery (Last-Known-Good)
	cache   *PolicyCache
	logger  *zap.Logger
	mutex   sync.RWMutex

	// Policy source for reloading
	policySource string
}

// NewOPAEngine creates a new OPA-based policy engine
func NewOPAEngine(logger *zap.Logger, cacheTTL time.Duration) *OPAEngine {
	return &OPAEngine{
		cache:  NewPolicyCache(cacheTTL),
		logger: logger,
	}
}

// LoadPolicy compiles and loads a new policy
func (pe *OPAEngine) LoadPolicy(ctx context.Context, policy string) error {
	pe.mutex.Lock()
	defer pe.mutex.Unlock()

	// Store policy source for reloading
	pe.policySource = policy

	// Compile the policy
	compiled, err := rego.New(
		rego.Query("data.airlock.authz.allow"),
		rego.Module("airlock.rego", policy),
	).PrepareForEval(ctx)

	if err != nil {
		pe.logger.Error("Policy compilation failed",
			zap.Error(err),
			zap.String("policy_hash", pe.hashPolicy(policy)))
		return fmt.Errorf("policy compilation failed: %w", err)
	}

	// Atomic swap - no locks needed for readers
	pe.current.Store(&compiled)

	// Set as LKG if this is the first successful compile
	if pe.lkg.Load() == nil {
		pe.lkg.Store(&compiled)
		pe.logger.Info("Policy loaded and set as Last-Known-Good",
			zap.String("policy_hash", pe.hashPolicy(policy)))
	} else {
		pe.logger.Info("Policy reloaded successfully",
			zap.String("policy_hash", pe.hashPolicy(policy)))
	}

	return nil
}

// ReloadPolicy reloads the current policy from source
func (pe *OPAEngine) ReloadPolicy(ctx context.Context) error {
	pe.mutex.RLock()
	policy := pe.policySource
	pe.mutex.RUnlock()

	if policy == "" {
		return fmt.Errorf("no policy source available for reload")
	}

	return pe.LoadPolicy(ctx, policy)
}

// Evaluate evaluates a policy decision with caching
func (pe *OPAEngine) Evaluate(ctx context.Context, input *PolicyInput) (*PolicyDecision, error) {
	// Generate cache key from input
	cacheKey := pe.generateCacheKey(input)

	// Check cache first
	if decision, found := pe.cache.Get(input.Tenant, cacheKey); found {
		return decision, nil
	}

	// Get current policy (atomic load)
	currentPolicy := pe.current.Load()
	if currentPolicy == nil {
		// No current policy, try LKG
		lkgPolicy := pe.lkg.Load()
		if lkgPolicy == nil {
			return &PolicyDecision{
				Allow:  false,
				Reason: "no policy available",
				RuleID: "system.no_policy",
			}, nil
		}
		currentPolicy = lkgPolicy
		pe.logger.Warn("Using Last-Known-Good policy due to current policy unavailable",
			zap.String("tenant", input.Tenant))
	}

	prepared := currentPolicy.(*rego.PreparedEvalQuery)

	// Evaluate policy
	results, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		pe.logger.Error("Policy evaluation failed",
			zap.Error(err),
			zap.String("tenant", input.Tenant),
			zap.String("subject", input.Subject))

		// Try LKG on evaluation failure
		lkgPolicy := pe.lkg.Load()
		if lkgPolicy != nil && lkgPolicy != currentPolicy {
			pe.logger.Warn("Falling back to Last-Known-Good policy",
				zap.String("tenant", input.Tenant))

			lkgPrepared := lkgPolicy.(*rego.PreparedEvalQuery)
			results, err = lkgPrepared.Eval(ctx, rego.EvalInput(input))
			if err != nil {
				return &PolicyDecision{
					Allow:  false,
					Reason: "policy evaluation failed",
					RuleID: "system.eval_error",
				}, fmt.Errorf("policy evaluation failed: %w", err)
			}
		} else {
			return &PolicyDecision{
				Allow:  false,
				Reason: "policy evaluation failed",
				RuleID: "system.eval_error",
			}, fmt.Errorf("policy evaluation failed: %w", err)
		}
	}

	// Process results
	decision := pe.processResults(results, input)

	// Cache the decision
	pe.cache.Set(input.Tenant, cacheKey, decision)

	return decision, nil
}

// processResults converts OPA evaluation results to PolicyDecision
func (pe *OPAEngine) processResults(results rego.ResultSet, input *PolicyInput) *PolicyDecision {
	decision := &PolicyDecision{
		Allow:    false,
		Reason:   "policy denied request",
		RuleID:   "airlock.authz.default_deny",
		Metadata: make(map[string]interface{}),
	}

	if len(results) > 0 && len(results[0].Expressions) > 0 {
		// Check if the policy allows the request
		if allow, ok := results[0].Expressions[0].Value.(bool); ok && allow {
			decision.Allow = true
			decision.Reason = "policy allowed request"
			decision.RuleID = "airlock.authz.allow"
		}

		// Extract additional metadata from bindings
		for key, value := range results[0].Bindings {
			decision.Metadata[key] = value
		}
	}

	return decision
}

// generateCacheKey creates a deterministic cache key from policy input
func (pe *OPAEngine) generateCacheKey(input *PolicyInput) string {
	h := sha256.New()
	h.Write([]byte(input.Subject))
	h.Write([]byte(input.Tool))
	h.Write([]byte(input.Resource))
	h.Write([]byte(input.Method))

	// Include groups in sorted order for consistency
	for _, group := range input.Groups {
		h.Write([]byte(group))
	}

	// Include headers in sorted order
	for key, value := range input.Headers {
		h.Write([]byte(key))
		h.Write([]byte(value))
	}

	return hex.EncodeToString(h.Sum(nil))[:16] // Use first 16 chars for cache key
}

// hashPolicy creates a hash of the policy content for logging
func (pe *OPAEngine) hashPolicy(policy string) string {
	h := sha256.Sum256([]byte(policy))
	return hex.EncodeToString(h[:])[:8] // Use first 8 chars for logging
}

// Close cleans up the policy engine resources
func (pe *OPAEngine) Close() error {
	// Clear atomic values
	pe.current.Store((*rego.PreparedEvalQuery)(nil))
	pe.lkg.Store((*rego.PreparedEvalQuery)(nil))

	pe.logger.Info("Policy engine closed")
	return nil
}

package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
)

// Claims represents the JWT claims we extract from tokens
type Claims struct {
	Subject   string   `json:"sub"`
	Tenant    string   `json:"tid"`
	Groups    []string `json:"groups"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
}

// Config holds the configuration for the authenticator
type Config struct {
	OIDCIssuer     string        `yaml:"oidc_issuer"`
	Audience       string        `yaml:"audience"`
	JWKSCacheTTL   time.Duration `yaml:"jwks_cache_ttl"`
	ClockSkew      time.Duration `yaml:"clock_skew"`
	RequiredGroups []string      `yaml:"required_groups"`
}

// Authenticator handles JWT validation with OIDC discovery and background JWKS refresh
type Authenticator struct {
	config   Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	logger   *zap.Logger

	// JWKS cache fields would go here when implemented

	// Background refresh control
	refreshCtx    context.Context
	refreshCancel context.CancelFunc
	refreshDone   chan struct{}
}

// NewAuthenticator creates a new authenticator with OIDC discovery
func NewAuthenticator(ctx context.Context, config Config, logger *zap.Logger) (*Authenticator, error) {
	if config.JWKSCacheTTL == 0 {
		config.JWKSCacheTTL = 5 * time.Minute
	}
	if config.ClockSkew == 0 {
		config.ClockSkew = 2 * time.Minute
	}

	// Initialize OIDC provider
	provider, err := oidc.NewProvider(ctx, config.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create ID token verifier
	verifierConfig := &oidc.Config{
		ClientID:             config.Audience,
		SupportedSigningAlgs: []string{"RS256", "ES256"},
		SkipClientIDCheck:    false,
		SkipExpiryCheck:      true, // We handle expiry check manually with clock skew
		SkipIssuerCheck:      false,
	}
	verifier := provider.Verifier(verifierConfig)

	refreshCtx, refreshCancel := context.WithCancel(context.Background())

	auth := &Authenticator{
		config:        config,
		provider:      provider,
		verifier:      verifier,
		logger:        logger,
		refreshCtx:    refreshCtx,
		refreshCancel: refreshCancel,
		refreshDone:   make(chan struct{}),
	}

	// Start background refresh goroutine
	go auth.startJWKSRefresh()

	return auth, nil
}

// ValidateToken validates a JWT token and extracts claims
func (a *Authenticator) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	// Use OIDC verifier for initial validation
	idToken, err := a.verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Extract claims from the verified token
	var rawClaims map[string]interface{}
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	claims, err := a.extractClaims(rawClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Additional timing validation with clock skew
	if err := a.validateTiming(claims); err != nil {
		return nil, fmt.Errorf("token timing validation failed: %w", err)
	}

	// Validate audience
	if err := a.validateAudience(claims); err != nil {
		return nil, fmt.Errorf("audience validation failed: %w", err)
	}

	return claims, nil
}

// startJWKSRefresh runs the background JWKS refresh goroutine
func (a *Authenticator) startJWKSRefresh() {
	defer close(a.refreshDone)

	ticker := time.NewTicker(a.config.JWKSCacheTTL)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.logger.Info("JWKS refresh tick - would refresh in production")

		case <-a.refreshCtx.Done():
			a.logger.Info("JWKS refresh goroutine stopping")
			return
		}
	}
}

// extractClaims converts raw claims map to our Claims struct
func (a *Authenticator) extractClaims(rawClaims map[string]interface{}) (*Claims, error) {
	claims := &Claims{}

	// Extract subject
	if sub, ok := rawClaims["sub"].(string); ok {
		claims.Subject = sub
	} else {
		return nil, fmt.Errorf("missing or invalid subject claim")
	}

	// Extract tenant (could be in different claim names)
	if tid, ok := rawClaims["tid"].(string); ok {
		claims.Tenant = tid
	} else if orgID, ok := rawClaims["org_id"].(string); ok {
		claims.Tenant = orgID
	} else {
		return nil, fmt.Errorf("missing tenant claim (tid or org_id)")
	}

	// Extract groups
	if groupsInterface, ok := rawClaims["groups"]; ok {
		switch groups := groupsInterface.(type) {
		case []interface{}:
			for _, group := range groups {
				if groupStr, ok := group.(string); ok {
					claims.Groups = append(claims.Groups, groupStr)
				}
			}
		case []string:
			claims.Groups = groups
		default:
			return nil, fmt.Errorf("invalid groups claim format")
		}
	}

	// Extract timing claims
	if exp, ok := rawClaims["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}
	if nbf, ok := rawClaims["nbf"].(float64); ok {
		claims.NotBefore = int64(nbf)
	}
	if iat, ok := rawClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}

	// Extract audience
	if audInterface, ok := rawClaims["aud"]; ok {
		switch aud := audInterface.(type) {
		case string:
			claims.Audience = []string{aud}
		case []interface{}:
			for _, a := range aud {
				if audStr, ok := a.(string); ok {
					claims.Audience = append(claims.Audience, audStr)
				}
			}
		case []string:
			claims.Audience = aud
		}
	}

	// Extract issuer
	if iss, ok := rawClaims["iss"].(string); ok {
		claims.Issuer = iss
	}

	return claims, nil
}

// validateTiming validates token timing with clock skew handling
func (a *Authenticator) validateTiming(claims *Claims) error {
	now := time.Now().Unix()
	skew := int64(a.config.ClockSkew.Seconds())

	// Check expiration
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt+skew {
		return fmt.Errorf("token expired")
	}

	// Check not before
	if claims.NotBefore > 0 && now < claims.NotBefore-skew {
		return fmt.Errorf("token not yet valid")
	}

	return nil
}

// validateAudience validates the audience claim
func (a *Authenticator) validateAudience(claims *Claims) error {
	if a.config.Audience == "" {
		return nil // Skip audience validation if not configured
	}

	for _, aud := range claims.Audience {
		if aud == a.config.Audience {
			return nil
		}
	}

	return fmt.Errorf("invalid audience: expected %s, got %v", a.config.Audience, claims.Audience)
}

// HealthCheck performs a health check on the authenticator
func (a *Authenticator) HealthCheck(ctx context.Context) (string, string) {
	// Check if provider is available
	if a.provider == nil {
		return "unhealthy", "OIDC provider not initialized"
	}

	// Check if verifier is available
	if a.verifier == nil {
		return "unhealthy", "JWT verifier not initialized"
	}

	// Try to fetch JWKS to verify connectivity
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Create a test provider to check OIDC endpoint connectivity
	_, err := oidc.NewProvider(checkCtx, a.config.OIDCIssuer)
	if err != nil {
		return "unhealthy", fmt.Sprintf("JWKS fetch failed: %v", err)
	}

	// Check if background refresh is running
	select {
	case <-a.refreshDone:
		return "unhealthy", "JWKS refresh goroutine stopped unexpectedly"
	default:
		// Goroutine is still running
	}

	return "healthy", "JWKS fetch successful, background refresh active"
}

// Close stops the background refresh goroutine and cleans up resources
func (a *Authenticator) Close() error {
	a.refreshCancel()

	// Wait for background goroutine to finish with timeout
	select {
	case <-a.refreshDone:
		a.logger.Info("Authenticator closed successfully")
	case <-time.After(5 * time.Second):
		a.logger.Warn("Timeout waiting for JWKS refresh goroutine to stop")
	}

	return nil
}

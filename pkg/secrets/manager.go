package secrets

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SecretManager handles secure secret loading and management
type SecretManager struct {
	mu              sync.RWMutex
	secrets         map[string]string
	secretPaths     map[string]string
	watchers        []SecretWatcher
	refreshInterval time.Duration
}

// SecretWatcher is called when a secret is updated
type SecretWatcher func(key, oldValue, newValue string) error

// JWKSManager handles JWKS key rotation and caching
type JWKSManager struct {
	mu         sync.RWMutex
	jwksURL    string
	keys       map[string]*rsa.PublicKey
	lastFetch  time.Time
	cacheTTL   time.Duration
	httpClient *http.Client
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewSecretManager creates a new secret manager
func NewSecretManager() *SecretManager {
	return &SecretManager{
		secrets:         make(map[string]string),
		secretPaths:     make(map[string]string),
		watchers:        make([]SecretWatcher, 0),
		refreshInterval: 30 * time.Second,
	}
}

// RegisterSecretPath registers a path where a secret should be loaded from
func (sm *SecretManager) RegisterSecretPath(key, path string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.secretPaths[key] = path
}

// AddWatcher adds a watcher for secret changes
func (sm *SecretManager) AddWatcher(watcher SecretWatcher) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.watchers = append(sm.watchers, watcher)
}

// LoadSecrets loads all registered secrets from their paths
func (sm *SecretManager) LoadSecrets() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for key, path := range sm.secretPaths {
		if err := sm.loadSecret(key, path); err != nil {
			return fmt.Errorf("failed to load secret %s from %s: %w", key, path, err)
		}
	}

	return nil
}

// loadSecret loads a single secret from a file or environment variable
func (sm *SecretManager) loadSecret(key, path string) error {
	var value string

	if strings.HasPrefix(path, "env:") {
		// Load from environment variable
		envVar := strings.TrimPrefix(path, "env:")
		value = os.Getenv(envVar)
		if value == "" {
			return fmt.Errorf("environment variable %s is not set", envVar)
		}
	} else {
		// Load from file
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				// Secret file doesn't exist, skip
				return nil
			}
			return err
		}
		value = strings.TrimSpace(string(data))
	}

	// Check if value changed
	oldValue := sm.secrets[key]
	if oldValue != value {
		sm.secrets[key] = value

		// Notify watchers
		for _, watcher := range sm.watchers {
			if err := watcher(key, oldValue, value); err != nil {
				return fmt.Errorf("watcher failed for secret %s: %w", key, err)
			}
		}
	}

	return nil
}

// GetSecret returns a secret value
func (sm *SecretManager) GetSecret(key string) (string, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	value, exists := sm.secrets[key]
	return value, exists
}

// StartWatching starts watching for secret changes
func (sm *SecretManager) StartWatching(ctx context.Context) error {
	ticker := time.NewTicker(sm.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := sm.LoadSecrets(); err != nil {
				// Log error but continue watching
				fmt.Printf("Error refreshing secrets: %v\n", err)
			}
		}
	}
}

// NewJWKSManager creates a new JWKS manager
func NewJWKSManager(jwksURL string, cacheTTL time.Duration) *JWKSManager {
	return &JWKSManager{
		jwksURL:    jwksURL,
		keys:       make(map[string]*rsa.PublicKey),
		cacheTTL:   cacheTTL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// GetPublicKey returns a public key by kid (key ID)
func (jm *JWKSManager) GetPublicKey(kid string) (*rsa.PublicKey, error) {
	jm.mu.RLock()
	key, exists := jm.keys[kid]
	needsRefresh := time.Since(jm.lastFetch) > jm.cacheTTL
	jm.mu.RUnlock()

	if !exists || needsRefresh {
		if err := jm.RefreshKeys(); err != nil {
			return nil, fmt.Errorf("failed to refresh JWKS keys: %w", err)
		}

		jm.mu.RLock()
		key, exists = jm.keys[kid]
		jm.mu.RUnlock()

		if !exists {
			return nil, fmt.Errorf("key with kid %s not found", kid)
		}
	}

	return key, nil
}

// RefreshKeys fetches and updates the JWKS keys
func (jm *JWKSManager) RefreshKeys() error {
	resp, err := jm.httpClient.Get(jm.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty == "RSA" && (jwk.Use == "sig" || jwk.Use == "") {
			pubKey, err := jm.parseRSAPublicKey(jwk)
			if err != nil {
				return fmt.Errorf("failed to parse RSA public key for kid %s: %w", jwk.Kid, err)
			}
			newKeys[jwk.Kid] = pubKey
		}
	}

	jm.mu.Lock()
	jm.keys = newKeys
	jm.lastFetch = time.Now()
	jm.mu.Unlock()

	return nil
}

// parseRSAPublicKey parses an RSA public key from JWK format
func (jm *JWKSManager) parseRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	// This is a simplified implementation
	// In a production system, you would use a proper JWK parsing library
	// like github.com/lestrrat-go/jwx

	// For now, return an error indicating this needs proper implementation
	return nil, fmt.Errorf("JWK parsing not fully implemented - use proper JWK library")
}

// GetKeyIDs returns all available key IDs
func (jm *JWKSManager) GetKeyIDs() []string {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	kids := make([]string, 0, len(jm.keys))
	for kid := range jm.keys {
		kids = append(kids, kid)
	}
	return kids
}

// ValidateToken validates a JWT token using the appropriate key
func (jm *JWKSManager) ValidateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token missing kid header")
		}

		// Get public key for this kid
		return jm.GetPublicKey(kid)
	})

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return token, nil
}

// ConfigTemplate represents a configuration template with secret placeholders
type ConfigTemplate struct {
	templatePath  string
	outputPath    string
	secretManager *SecretManager
}

// NewConfigTemplate creates a new configuration template
func NewConfigTemplate(templatePath, outputPath string, secretManager *SecretManager) *ConfigTemplate {
	return &ConfigTemplate{
		templatePath:  templatePath,
		outputPath:    outputPath,
		secretManager: secretManager,
	}
}

// Render renders the template with current secret values
func (ct *ConfigTemplate) Render() error {
	// Read template file
	templateData, err := os.ReadFile(ct.templatePath)
	if err != nil {
		return fmt.Errorf("failed to read template file: %w", err)
	}

	content := string(templateData)

	// Replace secret placeholders
	// Format: ${SECRET_NAME}
	content = ct.replaceSecrets(content)

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(ct.outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write rendered configuration
	if err := os.WriteFile(ct.outputPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write rendered config: %w", err)
	}

	return nil
}

// replaceSecrets replaces secret placeholders in the content
func (ct *ConfigTemplate) replaceSecrets(content string) string {
	// Simple placeholder replacement
	// In a production system, you might want to use a proper template engine

	for key, value := range ct.secretManager.secrets {
		placeholder := fmt.Sprintf("${%s}", key)
		content = strings.ReplaceAll(content, placeholder, value)
	}

	return content
}

// SecretRotationHandler handles automatic secret rotation
type SecretRotationHandler struct {
	secretManager *SecretManager
	jwksManager   *JWKSManager
	templates     []*ConfigTemplate
}

// NewSecretRotationHandler creates a new secret rotation handler
func NewSecretRotationHandler(secretManager *SecretManager, jwksManager *JWKSManager) *SecretRotationHandler {
	return &SecretRotationHandler{
		secretManager: secretManager,
		jwksManager:   jwksManager,
		templates:     make([]*ConfigTemplate, 0),
	}
}

// AddTemplate adds a configuration template to be rendered on secret changes
func (srh *SecretRotationHandler) AddTemplate(template *ConfigTemplate) {
	srh.templates = append(srh.templates, template)
}

// HandleSecretChange handles secret changes by re-rendering templates
func (srh *SecretRotationHandler) HandleSecretChange(key, oldValue, newValue string) error {
	// Re-render all templates when secrets change
	for _, template := range srh.templates {
		if err := template.Render(); err != nil {
			return fmt.Errorf("failed to render template %s: %w", template.templatePath, err)
		}
	}

	// If this is a JWKS-related secret, refresh keys
	if strings.Contains(key, "jwks") || strings.Contains(key, "oidc") {
		if err := srh.jwksManager.RefreshKeys(); err != nil {
			return fmt.Errorf("failed to refresh JWKS keys: %w", err)
		}
	}

	return nil
}

// StartRotationWatcher starts watching for secret changes and handles rotation
func (srh *SecretRotationHandler) StartRotationWatcher(ctx context.Context) error {
	// Add ourselves as a watcher
	srh.secretManager.AddWatcher(srh.HandleSecretChange)

	// Start the secret manager's watching
	return srh.secretManager.StartWatching(ctx)
}

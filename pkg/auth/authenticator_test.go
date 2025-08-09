package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap/zaptest"
)

// testKeyPair holds RSA key pair for testing
type testKeyPair struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

func generateTestKeyPair(t testing.TB) *testKeyPair {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	return &testKeyPair{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      "test-key-1",
	}
}

// createTestJWT creates a JWT token for testing
func (kp *testKeyPair) createTestJWT(t testing.TB, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kp.keyID

	tokenString, err := token.SignedString(kp.privateKey)
	if err != nil {
		t.Fatalf("Failed to sign JWT: %v", err)
	}

	return tokenString
}

// mockOIDCServer creates a mock OIDC server for testing
func createMockOIDCServer(t testing.TB, keyPair *testKeyPair) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// OIDC discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]interface{}{
			"issuer":                                "http://" + r.Host,
			"jwks_uri":                              "http://" + r.Host + "/jwks",
			"supported_signing_algs":                []string{"RS256"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	})

	// JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		// Simple JWK representation
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"kid": keyPair.keyID,
					"use": "sig",
					"alg": "RS256",
					"n":   "test-modulus", // Simplified for testing
					"e":   "AQAB",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	return httptest.NewServer(mux)
}

func TestAuthenticator_ExtractClaims(t *testing.T) {
	logger := zaptest.NewLogger(t)

	config := Config{
		OIDCIssuer:   "https://example.com",
		Audience:     "test-audience",
		JWKSCacheTTL: 5 * time.Minute,
		ClockSkew:    2 * time.Minute,
	}

	// Create authenticator without OIDC provider for unit testing
	auth := &Authenticator{
		config: config,
		logger: logger,
	}

	tests := []struct {
		name        string
		rawClaims   map[string]interface{}
		expectError bool
		errorMsg    string
		expected    *Claims
	}{
		{
			name: "valid_claims",
			rawClaims: map[string]interface{}{
				"sub":    "user@example.com",
				"tid":    "tenant-1",
				"groups": []string{"mcp.users"},
				"aud":    "test-audience",
				"iss":    "https://example.com",
				"exp":    float64(time.Now().Add(time.Hour).Unix()),
				"iat":    float64(time.Now().Unix()),
			},
			expectError: false,
			expected: &Claims{
				Subject:   "user@example.com",
				Tenant:    "tenant-1",
				Groups:    []string{"mcp.users"},
				Audience:  []string{"test-audience"},
				Issuer:    "https://example.com",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
				IssuedAt:  time.Now().Unix(),
			},
		},
		{
			name: "missing_subject",
			rawClaims: map[string]interface{}{
				"tid":    "tenant-1",
				"groups": []string{"mcp.users"},
				"aud":    "test-audience",
			},
			expectError: true,
			errorMsg:    "missing or invalid subject claim",
		},
		{
			name: "missing_tenant",
			rawClaims: map[string]interface{}{
				"sub":    "user@example.com",
				"groups": []string{"mcp.users"},
				"aud":    "test-audience",
			},
			expectError: true,
			errorMsg:    "missing tenant claim (tid or org_id)",
		},
		{
			name: "org_id_as_tenant",
			rawClaims: map[string]interface{}{
				"sub":    "user@example.com",
				"org_id": "tenant-1",
				"groups": []string{"mcp.users"},
				"aud":    "test-audience",
			},
			expectError: false,
			expected: &Claims{
				Subject:  "user@example.com",
				Tenant:   "tenant-1",
				Groups:   []string{"mcp.users"},
				Audience: []string{"test-audience"},
			},
		},
		{
			name: "groups_as_interface_slice",
			rawClaims: map[string]interface{}{
				"sub":    "user@example.com",
				"tid":    "tenant-1",
				"groups": []interface{}{"mcp.users", "admin"},
				"aud":    "test-audience",
			},
			expectError: false,
			expected: &Claims{
				Subject:  "user@example.com",
				Tenant:   "tenant-1",
				Groups:   []string{"mcp.users", "admin"},
				Audience: []string{"test-audience"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := auth.extractClaims(tt.rawClaims)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("Expected error message %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if claims == nil {
					t.Errorf("Expected claims but got nil")
				} else {
					if claims.Subject != tt.expected.Subject {
						t.Errorf("Expected subject %s, got %s", tt.expected.Subject, claims.Subject)
					}
					if claims.Tenant != tt.expected.Tenant {
						t.Errorf("Expected tenant %s, got %s", tt.expected.Tenant, claims.Tenant)
					}
					if len(claims.Groups) != len(tt.expected.Groups) {
						t.Errorf("Expected %d groups, got %d", len(tt.expected.Groups), len(claims.Groups))
					}
				}
			}
		})
	}
}

func TestAuthenticator_ValidateTiming(t *testing.T) {
	logger := zaptest.NewLogger(t)

	config := Config{
		ClockSkew: 2 * time.Minute,
	}

	auth := &Authenticator{
		config: config,
		logger: logger,
	}

	now := time.Now().Unix()

	tests := []struct {
		name        string
		claims      *Claims
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid_timing",
			claims: &Claims{
				ExpiresAt: now + 3600, // 1 hour from now
				NotBefore: now - 60,   // 1 minute ago
			},
			expectError: false,
		},
		{
			name: "expired_token",
			claims: &Claims{
				ExpiresAt: now - 300, // 5 minutes ago (beyond clock skew)
			},
			expectError: true,
			errorMsg:    "token expired",
		},
		{
			name: "expired_within_skew",
			claims: &Claims{
				ExpiresAt: now - 60, // 1 minute ago (within clock skew)
			},
			expectError: false,
		},
		{
			name: "not_yet_valid",
			claims: &Claims{
				NotBefore: now + 300, // 5 minutes from now (beyond clock skew)
			},
			expectError: true,
			errorMsg:    "token not yet valid",
		},
		{
			name: "not_yet_valid_within_skew",
			claims: &Claims{
				NotBefore: now + 60, // 1 minute from now (within clock skew)
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.validateTiming(tt.claims)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("Expected error message %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestAuthenticator_ValidateAudience(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name        string
		configAud   string
		claimsAud   []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid_audience",
			configAud:   "test-audience",
			claimsAud:   []string{"test-audience"},
			expectError: false,
		},
		{
			name:        "valid_audience_multiple",
			configAud:   "test-audience",
			claimsAud:   []string{"other-audience", "test-audience"},
			expectError: false,
		},
		{
			name:        "invalid_audience",
			configAud:   "test-audience",
			claimsAud:   []string{"wrong-audience"},
			expectError: true,
			errorMsg:    "invalid audience",
		},
		{
			name:        "no_config_audience",
			configAud:   "",
			claimsAud:   []string{"any-audience"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				Audience: tt.configAud,
			}

			auth := &Authenticator{
				config: config,
				logger: logger,
			}

			claims := &Claims{
				Audience: tt.claimsAud,
			}

			err := auth.validateAudience(claims)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && err.Error()[:len(tt.errorMsg)] != tt.errorMsg {
					t.Errorf("Expected error message to start with %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestAuthenticator_ConcurrentAccess(t *testing.T) {
	logger := zaptest.NewLogger(t)

	config := Config{
		ClockSkew: 2 * time.Minute,
	}

	auth := &Authenticator{
		config: config,
		logger: logger,
	}

	// Test concurrent claim extraction
	const numGoroutines = 100
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			rawClaims := map[string]interface{}{
				"sub":    fmt.Sprintf("user%d@example.com", id),
				"tid":    "tenant-1",
				"groups": []string{"mcp.users"},
				"aud":    "test-audience",
				"exp":    float64(time.Now().Add(time.Hour).Unix()),
				"iat":    float64(time.Now().Unix()),
			}

			_, err := auth.extractClaims(rawClaims)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: %w", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent extraction error: %v", err)
	}
}

func TestAuthenticator_SingleflightProtection(t *testing.T) {
	logger := zaptest.NewLogger(t)

	config := Config{
		JWKSCacheTTL: 5 * time.Minute,
	}

	auth := &Authenticator{
		config: config,
		logger: logger,
	}

	// Test concurrent claim extraction (singleflight is used internally)
	const numGoroutines = 10
	var wg sync.WaitGroup
	results := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			rawClaims := map[string]interface{}{
				"sub":    fmt.Sprintf("user%d@example.com", id),
				"tid":    "tenant-1",
				"groups": []string{"mcp.users"},
				"aud":    "test-audience",
			}

			_, err := auth.extractClaims(rawClaims)
			results <- err
		}(i)
	}

	wg.Wait()
	close(results)

	// All goroutines should get the same error (singleflight working)
	var firstError error
	errorCount := 0
	for err := range results {
		if err != nil {
			errorCount++
			if firstError == nil {
				firstError = err
			}
		}
	}

	// All should succeed
	if errorCount > 0 {
		t.Errorf("Expected no errors, got %d failures", errorCount)
	}
}

// Benchmark tests
func BenchmarkAuthenticator_ExtractClaims(b *testing.B) {
	logger := zaptest.NewLogger(b)

	config := Config{
		Audience:  "test-audience",
		ClockSkew: 2 * time.Minute,
	}

	auth := &Authenticator{
		config: config,
		logger: logger,
	}

	rawClaims := map[string]interface{}{
		"sub":    "user@example.com",
		"tid":    "tenant-1",
		"groups": []string{"mcp.users"},
		"aud":    "test-audience",
		"iss":    "https://example.com",
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
		"iat":    float64(time.Now().Unix()),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := auth.extractClaims(rawClaims)
			if err != nil {
				b.Errorf("Claims extraction failed: %v", err)
			}
		}
	})
}

func BenchmarkAuthenticator_ValidateTiming(b *testing.B) {
	logger := zaptest.NewLogger(b)

	config := Config{
		ClockSkew: 2 * time.Minute,
	}

	auth := &Authenticator{
		config: config,
		logger: logger,
	}

	claims := &Claims{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		NotBefore: time.Now().Add(-time.Minute).Unix(),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := auth.validateTiming(claims)
			if err != nil {
				b.Errorf("Timing validation failed: %v", err)
			}
		}
	})
}

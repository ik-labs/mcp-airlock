package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// BenchmarkTokenValidation benchmarks the token validation performance
func BenchmarkTokenValidation(b *testing.B) {
	// Create test authenticator
	auth, token := setupBenchmarkAuth(b)
	defer auth.Close()

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := auth.ValidateToken(ctx, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkTokenValidationCached benchmarks cached token validation
func BenchmarkTokenValidationCached(b *testing.B) {
	auth, token := setupBenchmarkAuth(b)
	defer auth.Close()

	ctx := context.Background()

	// Warm up cache
	_, err := auth.ValidateToken(ctx, token)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := auth.ValidateToken(ctx, token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkTokenCache benchmarks the token cache performance
func BenchmarkTokenCache(b *testing.B) {
	cache := NewTokenCache(5 * time.Minute)
	ctx := context.Background()

	// Create test claims
	claims := &Claims{
		Subject: "test@example.com",
		Tenant:  "test-tenant",
		Groups:  []string{"test-group"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Set", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				tokenHash := fmt.Sprintf("token-hash-%d", i)
				cache.Set(ctx, tokenHash, claims)
				i++
			}
		})
	})

	b.Run("Get", func(b *testing.B) {
		// Pre-populate cache
		for i := 0; i < 1000; i++ {
			tokenHash := fmt.Sprintf("token-hash-%d", i)
			cache.Set(ctx, tokenHash, claims)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				tokenHash := fmt.Sprintf("token-hash-%d", i%1000)
				_, found := cache.Get(ctx, tokenHash)
				if !found {
					b.Fatal("expected cache hit")
				}
				i++
			}
		})
	})

	b.Run("GetOrValidate", func(b *testing.B) {
		validator := func(ctx context.Context, token string) (*Claims, error) {
			return claims, nil
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				token := fmt.Sprintf("token-%d", i%100) // 100 unique tokens
				_, err := cache.GetOrValidate(ctx, token, validator)
				if err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	})
}

// BenchmarkJWKSCache benchmarks the JWKS cache performance
func BenchmarkJWKSCache(b *testing.B) {
	// This would require a mock OIDC provider for realistic benchmarking
	b.Skip("JWKS cache benchmark requires mock OIDC provider setup")
}

// BenchmarkClaimsExtraction benchmarks claims extraction performance
func BenchmarkClaimsExtraction(b *testing.B) {
	auth, _ := setupBenchmarkAuth(b)
	defer auth.Close()

	// Create test raw claims
	rawClaims := map[string]interface{}{
		"sub":    "test@example.com",
		"tid":    "test-tenant",
		"groups": []string{"group1", "group2", "group3"},
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
		"nbf":    float64(time.Now().Add(-time.Minute).Unix()),
		"iat":    float64(time.Now().Unix()),
		"aud":    []string{"test-audience"},
		"iss":    "test-issuer",
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := auth.extractClaims(rawClaims)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkTimingValidation benchmarks timing validation performance
func BenchmarkTimingValidation(b *testing.B) {
	auth, _ := setupBenchmarkAuth(b)
	defer auth.Close()

	claims := &Claims{
		Subject:   "test@example.com",
		Tenant:    "test-tenant",
		Groups:    []string{"test-group"},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		NotBefore: time.Now().Add(-time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := auth.validateTiming(claims)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkAudienceValidation benchmarks audience validation performance
func BenchmarkAudienceValidation(b *testing.B) {
	auth, _ := setupBenchmarkAuth(b)
	defer auth.Close()

	claims := &Claims{
		Subject:  "test@example.com",
		Tenant:   "test-tenant",
		Groups:   []string{"test-group"},
		Audience: []string{"test-audience", "other-audience"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := auth.validateAudience(claims)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// setupBenchmarkAuth creates a test authenticator for benchmarking
func setupBenchmarkAuth(b *testing.B) (*Authenticator, string) {
	b.Helper()

	// Create test configuration
	config := Config{
		OIDCIssuer:     "https://test.example.com",
		Audience:       "test-audience",
		JWKSCacheTTL:   5 * time.Minute,
		ClockSkew:      2 * time.Minute,
		RequiredGroups: []string{"test-group"},
	}

	logger := zap.NewNop()

	// For benchmarking, we'll create a simplified authenticator
	// In a real benchmark, you'd want to use a mock OIDC provider
	auth := &Authenticator{
		config:     config,
		logger:     logger,
		tokenCache: NewTokenCache(config.JWKSCacheTTL / 2),
	}

	// Create a test JWT token
	token := createTestJWT(b)

	return auth, token
}

// createTestJWT creates a test JWT token for benchmarking
func createTestJWT(b *testing.B) string {
	b.Helper()

	// Generate RSA key for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	// Create claims
	claims := jwt.MapClaims{
		"sub":    "test@example.com",
		"tid":    "test-tenant",
		"groups": []string{"test-group"},
		"exp":    time.Now().Add(time.Hour).Unix(),
		"nbf":    time.Now().Add(-time.Minute).Unix(),
		"iat":    time.Now().Unix(),
		"aud":    []string{"test-audience"},
		"iss":    "test-issuer",
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		b.Fatal(err)
	}

	return tokenString
}

// BenchmarkConcurrentTokenValidation benchmarks concurrent token validation
func BenchmarkConcurrentTokenValidation(b *testing.B) {
	auth, token := setupBenchmarkAuth(b)
	defer auth.Close()

	ctx := context.Background()

	// Test different concurrency levels
	concurrencyLevels := []int{1, 2, 4, 8, 16, 32}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Concurrency-%d", concurrency), func(b *testing.B) {
			b.SetParallelism(concurrency)
			b.ResetTimer()
			b.ReportAllocs()

			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_, err := auth.ValidateToken(ctx, token)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	auth, token := setupBenchmarkAuth(b)
	defer auth.Close()

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	// Measure memory allocations per operation
	for i := 0; i < b.N; i++ {
		_, err := auth.ValidateToken(ctx, token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

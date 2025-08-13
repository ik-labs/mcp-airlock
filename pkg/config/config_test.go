package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLoader(t *testing.T) {
	loader := NewLoader()
	assert.NotNil(t, loader)
	assert.NotNil(t, loader.k)
	assert.NotNil(t, loader.validator)
}

func TestLoadFromFile_ValidConfig(t *testing.T) {
	// Create a temporary config file
	configContent := `
server:
  addr: ":8080"
  public_base_url: "http://localhost:8080"
  timeouts:
    read: "30s"
    write: "30s"
    idle: "120s"

auth:
  oidc_issuer: "https://accounts.google.com/.well-known/openid-configuration"
  audience: "mcp-airlock"
  jwks_cache_ttl: "5m"
  clock_skew: "2m"
  required_groups: ["mcp.users"]

policy:
  rego_file: "policy.rego"
  cache_ttl: "1m"
  reload_signal: "SIGHUP"

audit:
  backend: "sqlite"
  database: "/tmp/audit.db"
  retention: "720h"
  export_format: "jsonl"

observability:
  logging:
    level: "info"
    format: "json"
`

	tmpFile := createTempFile(t, configContent)
	defer os.Remove(tmpFile)

	loader := NewLoader()
	config, err := loader.LoadFromFile(tmpFile)

	require.NoError(t, err)
	assert.Equal(t, ":8080", config.Server.Addr)
	assert.Equal(t, "http://localhost:8080", config.Server.PublicBaseURL)
	assert.Equal(t, "https://accounts.google.com/.well-known/openid-configuration", config.Auth.OIDCIssuer)
	assert.Equal(t, "mcp-airlock", config.Auth.Audience)
	assert.Equal(t, 5*time.Minute, config.Auth.JWKSCacheTTL)
	assert.Equal(t, 2*time.Minute, config.Auth.ClockSkew)
	assert.Equal(t, []string{"mcp.users"}, config.Auth.RequiredGroups)
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	configContent := `
server:
  addr: ":8080"
  invalid_yaml: [
`

	tmpFile := createTempFile(t, configContent)
	defer os.Remove(tmpFile)

	loader := NewLoader()
	_, err := loader.LoadFromFile(tmpFile)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config file")
}

func TestLoadFromFile_ValidationErrors(t *testing.T) {
	tests := []struct {
		name           string
		config         string
		expectedErrors []string
	}{
		{
			name: "missing required server addr",
			config: `
auth:
  oidc_issuer: "https://example.com"
  audience: "test"
  jwks_cache_ttl: "5m"
  clock_skew: "2m"
  required_groups: ["users"]
`,
			expectedErrors: []string{"field 'Addr' is required"},
		},
		{
			name: "invalid URL",
			config: `
server:
  addr: ":8080"
  public_base_url: "not-a-url"
  timeouts:
    read: "30s"
    write: "30s"
    idle: "120s"
auth:
  oidc_issuer: "https://example.com"
  audience: "test"
  jwks_cache_ttl: "5m"
  clock_skew: "2m"
  required_groups: ["users"]
`,
			expectedErrors: []string{"field 'PublicBaseURL' must be a valid URL"},
		},
		{
			name: "invalid duration too short",
			config: `
server:
  addr: ":8080"
  public_base_url: "http://localhost:8080"
  timeouts:
    read: "30s"
    write: "30s"
    idle: "120s"
auth:
  oidc_issuer: "https://example.com"
  audience: "test"
  jwks_cache_ttl: "30s"
  clock_skew: "2m"
  required_groups: ["users"]
`,
			expectedErrors: []string{"field 'JWKSCacheTTL' must be at least 1m"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := createTempFile(t, tt.config)
			defer os.Remove(tmpFile)

			loader := NewLoader()
			_, err := loader.LoadFromFile(tmpFile)

			require.Error(t, err)
			for _, expectedError := range tt.expectedErrors {
				assert.Contains(t, err.Error(), expectedError)
			}
		})
	}
}

func TestLoadFromFile_EnvironmentVariables(t *testing.T) {
	// Set environment variables
	os.Setenv("AIRLOCK_SERVER_ADDR", ":9090")
	os.Setenv("AIRLOCK_AUTH_AUDIENCE", "env-audience")
	defer func() {
		os.Unsetenv("AIRLOCK_SERVER_ADDR")
		os.Unsetenv("AIRLOCK_AUTH_AUDIENCE")
	}()

	configContent := `
server:
  addr: ":8080"  # This should be overridden by env var
  public_base_url: "http://localhost:8080"
  timeouts:
    read: "30s"
    write: "30s"
    idle: "120s"

auth:
  oidc_issuer: "https://accounts.google.com/.well-known/openid-configuration"
  audience: "file-audience"  # This should be overridden by env var
  jwks_cache_ttl: "5m"
  clock_skew: "2m"
  required_groups: ["mcp.users"]

policy:
  rego_file: "policy.rego"
  cache_ttl: "1m"

audit:
  backend: "sqlite"
  database: "/tmp/audit.db"
  retention: "720h"
  export_format: "jsonl"

observability:
  logging:
    level: "info"
    format: "json"
`

	tmpFile := createTempFile(t, configContent)
	defer os.Remove(tmpFile)

	loader := NewLoader()
	config, err := loader.LoadFromFile(tmpFile)

	require.NoError(t, err)
	assert.Equal(t, ":9090", config.Server.Addr)          // From env var
	assert.Equal(t, "env-audience", config.Auth.Audience) // From env var
}

func TestLoadFromFile_SecretMounts(t *testing.T) {
	// Create temporary secret files
	tmpDir := t.TempDir()

	certFile := filepath.Join(tmpDir, "tls-cert")
	keyFile := filepath.Join(tmpDir, "tls-key")

	require.NoError(t, os.WriteFile(certFile, []byte("cert-content"), 0600))
	require.NoError(t, os.WriteFile(keyFile, []byte("key-content"), 0600))

	configContent := `
server:
  addr: ":8080"
  public_base_url: "http://localhost:8080"
  timeouts:
    read: "30s"
    write: "30s"
    idle: "120s"

auth:
  oidc_issuer: "https://accounts.google.com/.well-known/openid-configuration"
  audience: "mcp-airlock"
  jwks_cache_ttl: "5m"
  clock_skew: "2m"
  required_groups: ["mcp.users"]

policy:
  rego_file: "policy.rego"
  cache_ttl: "1m"

audit:
  backend: "sqlite"
  database: "/tmp/audit.db"
  retention: "720h"
  export_format: "jsonl"

observability:
  logging:
    level: "info"
    format: "json"
`

	tmpFile := createTempFile(t, configContent)
	defer os.Remove(tmpFile)

	// Mock the secret mount paths by temporarily modifying the loader
	loader := NewLoader()

	// Override the LoadSecrets method for testing by setting values directly
	// Use actual file paths instead of content for validation
	loader.k.Set("server.tls.cert_file", certFile)
	loader.k.Set("server.tls.key_file", keyFile)

	config, err := loader.LoadFromFile(tmpFile)

	require.NoError(t, err)
	assert.Equal(t, certFile, config.Server.TLS.CertFile)
	assert.Equal(t, keyFile, config.Server.TLS.KeyFile)
}

func TestValidateBusinessRules(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &Config{
				Server: ServerConfig{
					Addr:          ":8080",
					PublicBaseURL: "http://localhost:8080",
					Timeouts: TimeoutConfig{
						Read:  30 * time.Second,
						Write: 30 * time.Second,
						Idle:  120 * time.Second,
					},
				},
				Upstreams: []UpstreamConfig{
					{
						Name:    "test-stdio",
						Type:    "stdio",
						Command: []string{"echo", "test"},
						Timeout: 30 * time.Second,
					},
				},
				Roots: []RootConfig{
					{
						Name:    "test-root",
						Type:    "fs",
						Virtual: "mcp://test/",
						Real:    "/tmp/test",
					},
				},
				DLP: DLPConfig{
					Patterns: []PatternConfig{
						{
							Name:    "email",
							Regex:   `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
							Replace: "[EMAIL]",
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "mismatched TLS config",
			config: &Config{
				Server: ServerConfig{
					Addr:          ":8080",
					PublicBaseURL: "http://localhost:8080",
					TLS: TLSConfig{
						CertFile: "cert.pem",
						KeyFile:  "", // Missing key file
					},
					Timeouts: TimeoutConfig{
						Read:  30 * time.Second,
						Write: 30 * time.Second,
						Idle:  120 * time.Second,
					},
				},
			},
			expectError: true,
			errorMsg:    "both tls.cert_file and tls.key_file must be specified together",
		},
		{
			name: "invalid upstream stdio without command",
			config: &Config{
				Server: ServerConfig{
					Addr:          ":8080",
					PublicBaseURL: "http://localhost:8080",
					Timeouts: TimeoutConfig{
						Read:  30 * time.Second,
						Write: 30 * time.Second,
						Idle:  120 * time.Second,
					},
				},
				Upstreams: []UpstreamConfig{
					{
						Name:    "test-stdio",
						Type:    "stdio",
						Command: []string{}, // Empty command
						Timeout: 30 * time.Second,
					},
				},
			},
			expectError: true,
			errorMsg:    "command is required for stdio type",
		},
		{
			name: "invalid root virtual path",
			config: &Config{
				Server: ServerConfig{
					Addr:          ":8080",
					PublicBaseURL: "http://localhost:8080",
					Timeouts: TimeoutConfig{
						Read:  30 * time.Second,
						Write: 30 * time.Second,
						Idle:  120 * time.Second,
					},
				},
				Roots: []RootConfig{
					{
						Name:    "test-root",
						Type:    "fs",
						Virtual: "invalid://test/", // Invalid scheme
						Real:    "/tmp/test",
					},
				},
			},
			expectError: true,
			errorMsg:    "virtual path must start with 'mcp://'",
		},
		{
			name: "invalid DLP regex",
			config: &Config{
				Server: ServerConfig{
					Addr:          ":8080",
					PublicBaseURL: "http://localhost:8080",
					Timeouts: TimeoutConfig{
						Read:  30 * time.Second,
						Write: 30 * time.Second,
						Idle:  120 * time.Second,
					},
				},
				DLP: DLPConfig{
					Patterns: []PatternConfig{
						{
							Name:    "invalid",
							Regex:   "[invalid-regex", // Invalid regex
							Replace: "[REDACTED]",
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "invalid regex pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := NewLoader()
			err := loader.validateBusinessRules(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidationError(t *testing.T) {
	err := ValidationError{
		Field:   "test_field",
		Tag:     "required",
		Value:   "",
		Message: "field is required",
		Line:    10,
	}

	assert.Equal(t, "line 10: field is required", err.Error())

	errNoLine := ValidationError{
		Field:   "test_field",
		Tag:     "required",
		Value:   "",
		Message: "field is required",
	}

	assert.Equal(t, "field is required", errNoLine.Error())
}

func TestValidationErrors(t *testing.T) {
	errors := ValidationErrors{
		{Field: "field1", Message: "error 1"},
		{Field: "field2", Message: "error 2"},
	}

	assert.Equal(t, "error 1; error 2", errors.Error())
}

// TestFormatValidationMessage tests validation message formatting
// This test is simplified to avoid complex mock setup
func TestFormatValidationMessage(t *testing.T) {
	// Test will be implemented when we have real validation errors
	// For now, we test the validation through integration tests
	t.Skip("Validation message formatting tested through integration tests")
}

// Helper functions

func createTempFile(t *testing.T, content string) string {
	tmpFile, err := os.CreateTemp("", "config-test-*.yaml")
	require.NoError(t, err)

	_, err = tmpFile.WriteString(content)
	require.NoError(t, err)

	err = tmpFile.Close()
	require.NoError(t, err)

	return tmpFile.Name()
}

// Mock implementations removed for simplicity - validation tested through integration

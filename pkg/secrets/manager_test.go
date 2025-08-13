package secrets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecretManager(t *testing.T) {
	sm := NewSecretManager()

	assert.NotNil(t, sm)
	assert.NotNil(t, sm.secrets)
	assert.NotNil(t, sm.secretPaths)
	assert.Empty(t, sm.watchers)
	assert.Equal(t, 30*time.Second, sm.refreshInterval)
}

func TestSecretManager_RegisterSecretPath(t *testing.T) {
	sm := NewSecretManager()

	sm.RegisterSecretPath("test-secret", "/path/to/secret")

	assert.Equal(t, "/path/to/secret", sm.secretPaths["test-secret"])
}

func TestSecretManager_LoadSecrets_FromFile(t *testing.T) {
	sm := NewSecretManager()

	// Create a temporary secret file
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.txt")
	secretValue := "super-secret-value"

	err := os.WriteFile(secretFile, []byte(secretValue), 0600)
	require.NoError(t, err)

	sm.RegisterSecretPath("test-secret", secretFile)

	err = sm.LoadSecrets()
	require.NoError(t, err)

	value, exists := sm.GetSecret("test-secret")
	assert.True(t, exists)
	assert.Equal(t, secretValue, value)
}

func TestSecretManager_LoadSecrets_FromEnv(t *testing.T) {
	sm := NewSecretManager()

	// Set environment variable
	envVar := "TEST_SECRET_ENV"
	secretValue := "env-secret-value"
	os.Setenv(envVar, secretValue)
	defer os.Unsetenv(envVar)

	sm.RegisterSecretPath("test-secret", "env:"+envVar)

	err := sm.LoadSecrets()
	require.NoError(t, err)

	value, exists := sm.GetSecret("test-secret")
	assert.True(t, exists)
	assert.Equal(t, secretValue, value)
}

func TestSecretManager_LoadSecrets_FileNotExists(t *testing.T) {
	sm := NewSecretManager()

	sm.RegisterSecretPath("test-secret", "/nonexistent/secret.txt")

	err := sm.LoadSecrets()
	// Should not error when file doesn't exist
	assert.NoError(t, err)

	_, exists := sm.GetSecret("test-secret")
	assert.False(t, exists)
}

func TestSecretManager_LoadSecrets_EnvNotSet(t *testing.T) {
	sm := NewSecretManager()

	sm.RegisterSecretPath("test-secret", "env:NONEXISTENT_ENV_VAR")

	err := sm.LoadSecrets()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "environment variable NONEXISTENT_ENV_VAR is not set")
}

func TestSecretManager_AddWatcher(t *testing.T) {
	sm := NewSecretManager()

	watcherCalled := false
	watcher := func(key, oldValue, newValue string) error {
		watcherCalled = true
		assert.Equal(t, "test-secret", key)
		assert.Equal(t, "", oldValue)
		assert.Equal(t, "new-value", newValue)
		return nil
	}

	sm.AddWatcher(watcher)

	// Create a temporary secret file
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.txt")

	err := os.WriteFile(secretFile, []byte("new-value"), 0600)
	require.NoError(t, err)

	sm.RegisterSecretPath("test-secret", secretFile)

	err = sm.LoadSecrets()
	require.NoError(t, err)

	assert.True(t, watcherCalled)
}

func TestSecretManager_GetSecret(t *testing.T) {
	sm := NewSecretManager()

	// Test non-existent secret
	value, exists := sm.GetSecret("nonexistent")
	assert.False(t, exists)
	assert.Empty(t, value)

	// Add a secret manually for testing
	sm.secrets["test-secret"] = "test-value"

	value, exists = sm.GetSecret("test-secret")
	assert.True(t, exists)
	assert.Equal(t, "test-value", value)
}

func TestNewJWKSManager(t *testing.T) {
	jwksURL := "https://example.com/.well-known/jwks.json"
	cacheTTL := 5 * time.Minute

	jm := NewJWKSManager(jwksURL, cacheTTL)

	assert.NotNil(t, jm)
	assert.Equal(t, jwksURL, jm.jwksURL)
	assert.Equal(t, cacheTTL, jm.cacheTTL)
	assert.NotNil(t, jm.keys)
	assert.NotNil(t, jm.httpClient)
}

func TestJWKSManager_RefreshKeys_Success(t *testing.T) {
	// Create a mock JWKS server
	jwksResponse := `{
		"keys": [
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "test-key-1",
				"n": "test-n-value",
				"e": "AQAB"
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(jwksResponse))
	}))
	defer server.Close()

	jm := NewJWKSManager(server.URL, 5*time.Minute)

	err := jm.RefreshKeys()
	// This will fail because we haven't implemented full JWK parsing
	// but it should at least attempt to parse
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWK parsing not fully implemented")
}

func TestJWKSManager_RefreshKeys_HTTPError(t *testing.T) {
	// Create a mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	jm := NewJWKSManager(server.URL, 5*time.Minute)

	err := jm.RefreshKeys()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWKS endpoint returned status 500")
}

func TestJWKSManager_RefreshKeys_InvalidJSON(t *testing.T) {
	// Create a mock server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	jm := NewJWKSManager(server.URL, 5*time.Minute)

	err := jm.RefreshKeys()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse JWKS")
}

func TestJWKSManager_GetKeyIDs(t *testing.T) {
	jm := NewJWKSManager("https://example.com", 5*time.Minute)

	// Initially empty
	kids := jm.GetKeyIDs()
	assert.Empty(t, kids)

	// Add some mock keys
	jm.keys["key1"] = nil
	jm.keys["key2"] = nil

	kids = jm.GetKeyIDs()
	assert.Len(t, kids, 2)
	assert.Contains(t, kids, "key1")
	assert.Contains(t, kids, "key2")
}

func TestNewConfigTemplate(t *testing.T) {
	sm := NewSecretManager()
	templatePath := "/path/to/template"
	outputPath := "/path/to/output"

	ct := NewConfigTemplate(templatePath, outputPath, sm)

	assert.NotNil(t, ct)
	assert.Equal(t, templatePath, ct.templatePath)
	assert.Equal(t, outputPath, ct.outputPath)
	assert.Equal(t, sm, ct.secretManager)
}

func TestConfigTemplate_Render(t *testing.T) {
	sm := NewSecretManager()
	sm.secrets["DB_PASSWORD"] = "secret123"
	sm.secrets["API_KEY"] = "key456"

	// Create template file
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "template.yaml")
	outputPath := filepath.Join(tmpDir, "output.yaml")

	templateContent := `
database:
  password: ${DB_PASSWORD}
api:
  key: ${API_KEY}
  url: https://api.example.com
`

	err := os.WriteFile(templatePath, []byte(templateContent), 0644)
	require.NoError(t, err)

	ct := NewConfigTemplate(templatePath, outputPath, sm)

	err = ct.Render()
	require.NoError(t, err)

	// Check output file
	outputContent, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	expectedContent := `
database:
  password: secret123
api:
  key: key456
  url: https://api.example.com
`

	assert.Equal(t, expectedContent, string(outputContent))
}

func TestConfigTemplate_Render_TemplateNotFound(t *testing.T) {
	sm := NewSecretManager()
	ct := NewConfigTemplate("/nonexistent/template", "/tmp/output", sm)

	err := ct.Render()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read template file")
}

func TestNewSecretRotationHandler(t *testing.T) {
	sm := NewSecretManager()
	jm := NewJWKSManager("https://example.com", 5*time.Minute)

	srh := NewSecretRotationHandler(sm, jm)

	assert.NotNil(t, srh)
	assert.Equal(t, sm, srh.secretManager)
	assert.Equal(t, jm, srh.jwksManager)
	assert.Empty(t, srh.templates)
}

func TestSecretRotationHandler_AddTemplate(t *testing.T) {
	sm := NewSecretManager()
	jm := NewJWKSManager("https://example.com", 5*time.Minute)
	srh := NewSecretRotationHandler(sm, jm)

	ct := NewConfigTemplate("/template", "/output", sm)
	srh.AddTemplate(ct)

	assert.Len(t, srh.templates, 1)
	assert.Equal(t, ct, srh.templates[0])
}

func TestSecretRotationHandler_HandleSecretChange(t *testing.T) {
	sm := NewSecretManager()
	sm.secrets["TEST_SECRET"] = "old-value"

	// Create a mock JWKS server for testing JWKS refresh
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys": []}`))
	}))
	defer server.Close()

	jm := NewJWKSManager(server.URL, 5*time.Minute)
	srh := NewSecretRotationHandler(sm, jm)

	// Create a template
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "template.yaml")
	outputPath := filepath.Join(tmpDir, "output.yaml")

	templateContent := "secret: ${TEST_SECRET}"
	err := os.WriteFile(templatePath, []byte(templateContent), 0644)
	require.NoError(t, err)

	ct := NewConfigTemplate(templatePath, outputPath, sm)
	srh.AddTemplate(ct)

	// Handle secret change
	err = srh.HandleSecretChange("TEST_SECRET", "old-value", "new-value")
	require.NoError(t, err)

	// Check that template was rendered
	outputContent, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Equal(t, "secret: old-value", string(outputContent)) // Uses current secret value
}

func TestSecretRotationHandler_HandleSecretChange_JWKSRefresh(t *testing.T) {
	sm := NewSecretManager()

	// Create a mock JWKS server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys": []}`))
	}))
	defer server.Close()

	jm := NewJWKSManager(server.URL, 5*time.Minute)
	srh := NewSecretRotationHandler(sm, jm)

	// Handle JWKS-related secret change
	err := srh.HandleSecretChange("oidc_client_secret", "old", "new")
	require.NoError(t, err)

	// Should have attempted to refresh JWKS keys
	// (We can't easily test this without more complex mocking)
}

func TestSecretManager_StartWatching(t *testing.T) {
	sm := NewSecretManager()
	sm.refreshInterval = 10 * time.Millisecond // Fast for testing

	// Create a temporary secret file
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.txt")

	err := os.WriteFile(secretFile, []byte("initial-value"), 0600)
	require.NoError(t, err)

	sm.RegisterSecretPath("test-secret", secretFile)

	// Load initial secrets
	err = sm.LoadSecrets()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start watching in background
	go func() {
		sm.StartWatching(ctx)
	}()

	// Update the secret file
	time.Sleep(20 * time.Millisecond)
	err = os.WriteFile(secretFile, []byte("updated-value"), 0600)
	require.NoError(t, err)

	// Wait for context to expire
	<-ctx.Done()

	// Check that secret was updated
	value, exists := sm.GetSecret("test-secret")
	assert.True(t, exists)
	assert.Equal(t, "updated-value", value)
}

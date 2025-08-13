package config

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewReloadManager(t *testing.T) {
	loader := NewLoader()
	config := &Config{
		Server: ServerConfig{Addr: ":8080"},
	}

	rm := NewReloadManager("config.yaml", loader, config)

	assert.NotNil(t, rm)
	assert.Equal(t, "config.yaml", rm.configPath)
	assert.Equal(t, loader, rm.loader)
	assert.Equal(t, config, rm.currentConfig)
	assert.NotNil(t, rm.reloadCh)
	assert.NotNil(t, rm.stopCh)
	assert.Empty(t, rm.callbacks)
}

func TestReloadManager_GetCurrentConfig(t *testing.T) {
	config := &Config{
		Server: ServerConfig{Addr: ":8080"},
	}

	rm := NewReloadManager("config.yaml", NewLoader(), config)

	currentConfig := rm.GetCurrentConfig()
	assert.Equal(t, ":8080", currentConfig.Server.Addr)

	// Verify it's a copy, not the same instance
	assert.NotSame(t, config, currentConfig)
}

func TestReloadManager_AddCallback(t *testing.T) {
	rm := NewReloadManager("config.yaml", NewLoader(), &Config{})

	callback := func(oldConfig, newConfig *Config) error {
		return nil
	}

	rm.AddCallback(callback)

	assert.Len(t, rm.callbacks, 1)
}

func TestReloadManager_TriggerReload_Success(t *testing.T) {
	// Create a temporary config file
	configContent := `
server:
  addr: ":9090"
`
	tmpFile := createTempFile(t, configContent)
	defer os.Remove(tmpFile)

	loader := NewLoader()
	initialConfig := &Config{
		Server: ServerConfig{Addr: ":8080"},
	}

	rm := NewReloadManager(tmpFile, loader, initialConfig)

	// Add a callback that should succeed
	callbackCalled := false
	rm.AddCallback(func(oldConfig, newConfig *Config) error {
		callbackCalled = true
		assert.Equal(t, ":8080", oldConfig.Server.Addr)
		assert.Equal(t, ":9090", newConfig.Server.Addr)
		return nil
	})

	result := rm.TriggerReload()

	assert.True(t, result.Success)
	assert.Empty(t, result.Error)
	assert.True(t, callbackCalled)

	// Verify config was updated
	currentConfig := rm.GetCurrentConfig()
	assert.Equal(t, ":9090", currentConfig.Server.Addr)
}

func TestReloadManager_TriggerReload_InvalidConfig(t *testing.T) {
	// Create a temporary config file with invalid YAML
	configContent := `
server:
  addr: ":9090"
  invalid_yaml: [
`
	tmpFile := createTempFile(t, configContent)
	defer os.Remove(tmpFile)

	loader := NewLoader()
	initialConfig := &Config{
		Server: ServerConfig{Addr: ":8080"},
	}

	rm := NewReloadManager(tmpFile, loader, initialConfig)

	result := rm.TriggerReload()

	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "failed to load new configuration")

	// Verify config was not updated
	currentConfig := rm.GetCurrentConfig()
	assert.Equal(t, ":8080", currentConfig.Server.Addr)
}

func TestReloadManager_TriggerReload_CallbackFailure(t *testing.T) {
	// Create a temporary config file
	configContent := `
server:
  addr: ":9090"
`
	tmpFile := createTempFile(t, configContent)
	defer os.Remove(tmpFile)

	loader := NewLoader()
	initialConfig := &Config{
		Server: ServerConfig{Addr: ":8080"},
	}

	rm := NewReloadManager(tmpFile, loader, initialConfig)

	// Add a callback that will fail
	rm.AddCallback(func(oldConfig, newConfig *Config) error {
		return assert.AnError
	})

	result := rm.TriggerReload()

	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "callback 0 failed during reload")

	// Verify config was not updated (rollback)
	currentConfig := rm.GetCurrentConfig()
	assert.Equal(t, ":8080", currentConfig.Server.Addr)
}

func TestReloadManager_StartStop(t *testing.T) {
	rm := NewReloadManager("config.yaml", NewLoader(), &Config{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := rm.Start(ctx)
	assert.NoError(t, err)

	// Test that we can stop without issues
	rm.Stop()
}

func TestReloadManager_SignalHandling(t *testing.T) {
	// This test is more complex as it involves signal handling
	// For now, we'll test the basic setup

	configContent := `
server:
  addr: ":8080"
`
	tmpFile := createTempFile(t, configContent)
	defer os.Remove(tmpFile)

	loader := NewLoader()
	initialConfig := &Config{
		Server: ServerConfig{Addr: ":8080"},
	}

	rm := NewReloadManager(tmpFile, loader, initialConfig)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := rm.Start(ctx)
	assert.NoError(t, err)

	// In a real test, we would send SIGHUP and verify reload
	// For now, we just verify the manager starts without error

	rm.Stop()
}

func TestCompareConfigs(t *testing.T) {
	oldConfig := &Config{
		Server: ServerConfig{
			Addr:          ":8080",
			PublicBaseURL: "http://localhost:8080",
		},
		Auth: AuthConfig{
			OIDCIssuer: "https://old.example.com",
			Audience:   "old-audience",
		},
		Policy: PolicyConfig{
			RegoFile: "old-policy.rego",
		},
		Upstreams: []UpstreamConfig{
			{Name: "upstream1"},
		},
		Roots: []RootConfig{
			{Name: "root1"},
		},
	}

	newConfig := &Config{
		Server: ServerConfig{
			Addr:          ":9090",
			PublicBaseURL: "http://localhost:9090",
		},
		Auth: AuthConfig{
			OIDCIssuer: "https://new.example.com",
			Audience:   "old-audience", // Same
		},
		Policy: PolicyConfig{
			RegoFile: "old-policy.rego", // Same
		},
		Upstreams: []UpstreamConfig{
			{Name: "upstream1"},
			{Name: "upstream2"}, // Added
		},
		Roots: []RootConfig{
			{Name: "root1"}, // Same count
		},
	}

	diffs := CompareConfigs(oldConfig, newConfig)

	// Should detect changes in server.addr, server.public_base_url, auth.oidc_issuer, and upstreams.count
	assert.Len(t, diffs, 4)

	// Check specific diffs
	addrDiff := findDiff(diffs, "server.addr")
	require.NotNil(t, addrDiff)
	assert.Equal(t, ":8080", addrDiff.OldValue)
	assert.Equal(t, ":9090", addrDiff.NewValue)

	urlDiff := findDiff(diffs, "server.public_base_url")
	require.NotNil(t, urlDiff)
	assert.Equal(t, "http://localhost:8080", urlDiff.OldValue)
	assert.Equal(t, "http://localhost:9090", urlDiff.NewValue)

	issuerDiff := findDiff(diffs, "auth.oidc_issuer")
	require.NotNil(t, issuerDiff)
	assert.Equal(t, "https://old.example.com", issuerDiff.OldValue)
	assert.Equal(t, "https://new.example.com", issuerDiff.NewValue)

	upstreamsDiff := findDiff(diffs, "upstreams.count")
	require.NotNil(t, upstreamsDiff)
	assert.Equal(t, 1, upstreamsDiff.OldValue)
	assert.Equal(t, 2, upstreamsDiff.NewValue)
}

func TestCompareConfigs_NoChanges(t *testing.T) {
	config := &Config{
		Server: ServerConfig{
			Addr:          ":8080",
			PublicBaseURL: "http://localhost:8080",
		},
		Auth: AuthConfig{
			OIDCIssuer: "https://example.com",
			Audience:   "audience",
		},
	}

	diffs := CompareConfigs(config, config)
	assert.Empty(t, diffs)
}

func TestReloadStats(t *testing.T) {
	rm := NewReloadManager("config.yaml", NewLoader(), &Config{})

	stats := rm.GetStats()

	// For now, stats are empty - in a full implementation they would be tracked
	assert.Equal(t, int64(0), stats.TotalReloads)
	assert.Equal(t, int64(0), stats.SuccessfulReloads)
	assert.Equal(t, int64(0), stats.FailedReloads)
}

// Helper functions

func findDiff(diffs []ConfigDiff, field string) *ConfigDiff {
	for _, diff := range diffs {
		if diff.Field == field {
			return &diff
		}
	}
	return nil
}

// createTempFile is defined in config_test.go

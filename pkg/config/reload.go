package config

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ReloadManager handles configuration and policy hot-reloading
type ReloadManager struct {
	mu            sync.RWMutex
	configPath    string
	loader        *Loader
	currentConfig *Config
	reloadCh      chan struct{}
	stopCh        chan struct{}
	callbacks     []ReloadCallback
}

// ReloadCallback is called when configuration is successfully reloaded
type ReloadCallback func(oldConfig, newConfig *Config) error

// ReloadResult represents the result of a reload operation
type ReloadResult struct {
	Success   bool      `json:"success"`
	Timestamp time.Time `json:"timestamp"`
	Error     string    `json:"error,omitempty"`
	Changes   []string  `json:"changes,omitempty"`
}

// NewReloadManager creates a new reload manager
func NewReloadManager(configPath string, loader *Loader, initialConfig *Config) *ReloadManager {
	return &ReloadManager{
		configPath:    configPath,
		loader:        loader,
		currentConfig: initialConfig,
		reloadCh:      make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
		callbacks:     make([]ReloadCallback, 0),
	}
}

// AddCallback adds a callback to be called on successful reload
func (rm *ReloadManager) AddCallback(callback ReloadCallback) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.callbacks = append(rm.callbacks, callback)
}

// GetCurrentConfig returns the current configuration (thread-safe)
func (rm *ReloadManager) GetCurrentConfig() *Config {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Return a copy to prevent concurrent access issues
	configCopy := *rm.currentConfig
	return &configCopy
}

// Start starts the reload manager and signal handlers
func (rm *ReloadManager) Start(ctx context.Context) error {
	// Set up signal handler for SIGHUP
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-rm.stopCh:
				return
			case <-sigCh:
				// Trigger reload on SIGHUP
				select {
				case rm.reloadCh <- struct{}{}:
				default:
					// Channel is full, reload already pending
				}
			case <-rm.reloadCh:
				// Perform reload
				if err := rm.performReload(); err != nil {
					// Log error but continue running
					fmt.Printf("Configuration reload failed: %v\n", err)
				}
			}
		}
	}()

	return nil
}

// Stop stops the reload manager
func (rm *ReloadManager) Stop() {
	close(rm.stopCh)
	signal.Stop(make(chan os.Signal, 1))
}

// TriggerReload manually triggers a configuration reload
func (rm *ReloadManager) TriggerReload() *ReloadResult {
	result := &ReloadResult{
		Timestamp: time.Now(),
	}

	if err := rm.performReload(); err != nil {
		result.Success = false
		result.Error = err.Error()
	} else {
		result.Success = true
	}

	return result
}

// performReload performs the actual configuration reload with rollback capability
func (rm *ReloadManager) performReload() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Load new configuration
	newConfig, err := rm.loader.LoadFromFile(rm.configPath)
	if err != nil {
		return fmt.Errorf("failed to load new configuration: %w", err)
	}

	// Store old configuration for rollback
	oldConfig := rm.currentConfig

	// Validate new configuration by calling all callbacks
	// This is a transactional approach - if any callback fails, we rollback
	for i, callback := range rm.callbacks {
		if err := callback(oldConfig, newConfig); err != nil {
			return fmt.Errorf("callback %d failed during reload: %w", i, err)
		}
	}

	// If we get here, all callbacks succeeded, so commit the new configuration
	rm.currentConfig = newConfig

	return nil
}

// ConfigDiff represents a difference between two configurations
type ConfigDiff struct {
	Field    string      `json:"field"`
	OldValue interface{} `json:"old_value"`
	NewValue interface{} `json:"new_value"`
}

// CompareConfigs compares two configurations and returns the differences
func CompareConfigs(oldConfig, newConfig *Config) []ConfigDiff {
	var diffs []ConfigDiff

	// Compare server configuration
	if oldConfig.Server.Addr != newConfig.Server.Addr {
		diffs = append(diffs, ConfigDiff{
			Field:    "server.addr",
			OldValue: oldConfig.Server.Addr,
			NewValue: newConfig.Server.Addr,
		})
	}

	if oldConfig.Server.PublicBaseURL != newConfig.Server.PublicBaseURL {
		diffs = append(diffs, ConfigDiff{
			Field:    "server.public_base_url",
			OldValue: oldConfig.Server.PublicBaseURL,
			NewValue: newConfig.Server.PublicBaseURL,
		})
	}

	// Compare auth configuration
	if oldConfig.Auth.OIDCIssuer != newConfig.Auth.OIDCIssuer {
		diffs = append(diffs, ConfigDiff{
			Field:    "auth.oidc_issuer",
			OldValue: oldConfig.Auth.OIDCIssuer,
			NewValue: newConfig.Auth.OIDCIssuer,
		})
	}

	if oldConfig.Auth.Audience != newConfig.Auth.Audience {
		diffs = append(diffs, ConfigDiff{
			Field:    "auth.audience",
			OldValue: oldConfig.Auth.Audience,
			NewValue: newConfig.Auth.Audience,
		})
	}

	// Compare policy configuration
	if oldConfig.Policy.RegoFile != newConfig.Policy.RegoFile {
		diffs = append(diffs, ConfigDiff{
			Field:    "policy.rego_file",
			OldValue: oldConfig.Policy.RegoFile,
			NewValue: newConfig.Policy.RegoFile,
		})
	}

	// Compare upstreams (simplified - just count for now)
	if len(oldConfig.Upstreams) != len(newConfig.Upstreams) {
		diffs = append(diffs, ConfigDiff{
			Field:    "upstreams.count",
			OldValue: len(oldConfig.Upstreams),
			NewValue: len(newConfig.Upstreams),
		})
	}

	// Compare roots (simplified - just count for now)
	if len(oldConfig.Roots) != len(newConfig.Roots) {
		diffs = append(diffs, ConfigDiff{
			Field:    "roots.count",
			OldValue: len(oldConfig.Roots),
			NewValue: len(newConfig.Roots),
		})
	}

	return diffs
}

// ReloadStats tracks reload statistics
type ReloadStats struct {
	TotalReloads      int64     `json:"total_reloads"`
	SuccessfulReloads int64     `json:"successful_reloads"`
	FailedReloads     int64     `json:"failed_reloads"`
	LastReload        time.Time `json:"last_reload"`
	LastSuccess       time.Time `json:"last_success"`
	LastFailure       time.Time `json:"last_failure"`
	LastError         string    `json:"last_error,omitempty"`
}

// GetStats returns reload statistics
func (rm *ReloadManager) GetStats() ReloadStats {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// For now, return empty stats - in a full implementation,
	// we would track these metrics
	return ReloadStats{}
}

package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ik-labs/mcp-airlock/pkg/config"
)

// ReloadHandler handles configuration reload requests
type ReloadHandler struct {
	reloadManager *config.ReloadManager
}

// NewReloadHandler creates a new reload handler
func NewReloadHandler(reloadManager *config.ReloadManager) *ReloadHandler {
	return &ReloadHandler{
		reloadManager: reloadManager,
	}
}

// ServeHTTP handles HTTP requests for configuration reload
func (h *ReloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.handleReload(w)
	case http.MethodGet:
		h.handleStatus(w)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleReload triggers a configuration reload
func (h *ReloadHandler) handleReload(w http.ResponseWriter) {
	// TODO: Add proper authorization check here
	// For now, we'll implement basic authorization in a later task

	result := h.reloadManager.TriggerReload()

	w.Header().Set("Content-Type", "application/json")

	if result.Success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}

	err := json.NewEncoder(w).Encode(result)
	if err != nil {
		return
	}
}

// handleStatus returns the current reload status and statistics
func (h *ReloadHandler) handleStatus(w http.ResponseWriter) {
	stats := h.reloadManager.GetStats()
	currentConfig := h.reloadManager.GetCurrentConfig()

	response := map[string]interface{}{
		"stats": stats,
		"current_config_summary": map[string]interface{}{
			"server_addr":     currentConfig.Server.Addr,
			"upstreams_count": len(currentConfig.Upstreams),
			"roots_count":     len(currentConfig.Roots),
			"policy_file":     currentConfig.Policy.RegoFile,
		},
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}

// ConfigDiffHandler handles configuration diff requests
type ConfigDiffHandler struct {
	reloadManager *config.ReloadManager
	configPath    string
	loader        *config.Loader
}

// NewConfigDiffHandler creates a new config diff handler
func NewConfigDiffHandler(reloadManager *config.ReloadManager, configPath string, loader *config.Loader) *ConfigDiffHandler {
	return &ConfigDiffHandler{
		reloadManager: reloadManager,
		configPath:    configPath,
		loader:        loader,
	}
}

// ServeHTTP handles HTTP requests for configuration diff
func (h *ConfigDiffHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Load the configuration file to compare with current
	fileConfig, err := h.loader.LoadFromFile(h.configPath)
	if err != nil {
		http.Error(w, "Failed to load config file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	currentConfig := h.reloadManager.GetCurrentConfig()
	diffs := config.CompareConfigs(currentConfig, fileConfig)

	response := map[string]interface{}{
		"has_changes": len(diffs) > 0,
		"changes":     diffs,
		"timestamp":   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}

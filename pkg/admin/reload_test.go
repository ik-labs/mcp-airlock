package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ik-labs/mcp-airlock/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReloadHandler_ServeHTTP_POST_Success(t *testing.T) {
	// Create a temporary config file
	configContent := `
server:
  addr: ":9090"
`
	tmpFile := createTempFile(t, configContent)
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {

		}
	}(tmpFile)

	loader := config.NewLoader()
	initialConfig := &config.Config{
		Server: config.ServerConfig{Addr: ":8080"},
	}

	rm := config.NewReloadManager(tmpFile, loader, initialConfig)
	handler := NewReloadHandler(rm)

	req := httptest.NewRequest(http.MethodPost, "/admin/reload", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var result config.ReloadResult
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)

	assert.True(t, result.Success)
	assert.Empty(t, result.Error)
	assert.NotZero(t, result.Timestamp)
}

func TestReloadHandler_ServeHTTP_POST_Failure(t *testing.T) {
	// Create a temporary config file with invalid YAML
	configContent := `
server:
  addr: ":9090"
  invalid: [
`
	tmpFile := createTempFile(t, configContent)
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {

		}
	}(tmpFile)

	loader := config.NewLoader()
	initialConfig := &config.Config{
		Server: config.ServerConfig{Addr: ":8080"},
	}

	rm := config.NewReloadManager(tmpFile, loader, initialConfig)
	handler := NewReloadHandler(rm)

	req := httptest.NewRequest(http.MethodPost, "/admin/reload", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var result config.ReloadResult
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)

	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Error)
	assert.Contains(t, result.Error, "failed to load new configuration")
}

func TestReloadHandler_ServeHTTP_GET_Status(t *testing.T) {
	loader := config.NewLoader()
	initialConfig := &config.Config{
		Server: config.ServerConfig{Addr: ":8080"},
		Upstreams: []config.UpstreamConfig{
			{Name: "upstream1"},
		},
		Roots: []config.RootConfig{
			{Name: "root1"},
		},
		Policy: config.PolicyConfig{
			RegoFile: "policy.rego",
		},
	}

	rm := config.NewReloadManager("config.yaml", loader, initialConfig)
	handler := NewReloadHandler(rm)

	req := httptest.NewRequest(http.MethodGet, "/admin/reload", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "stats")
	assert.Contains(t, response, "current_config_summary")
	assert.Contains(t, response, "timestamp")

	summary := response["current_config_summary"].(map[string]interface{})
	assert.Equal(t, ":8080", summary["server_addr"])
	assert.Equal(t, float64(1), summary["upstreams_count"]) // JSON numbers are float64
	assert.Equal(t, float64(1), summary["roots_count"])
	assert.Equal(t, "policy.rego", summary["policy_file"])
}

func TestReloadHandler_ServeHTTP_InvalidMethod(t *testing.T) {
	rm := config.NewReloadManager("config.yaml", config.NewLoader(), &config.Config{})
	handler := NewReloadHandler(rm)

	req := httptest.NewRequest(http.MethodPut, "/admin/reload", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestConfigDiffHandler_ServeHTTP_GET_NoChanges(t *testing.T) {
	// Create a temporary config file
	configContent := `
server:
  addr: ":8080"
`
	tmpFile := createTempFile(t, configContent)
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {

		}
	}(tmpFile)

	loader := config.NewLoader()
	initialConfig := &config.Config{
		Server: config.ServerConfig{Addr: ":8080"},
	}

	rm := config.NewReloadManager(tmpFile, loader, initialConfig)
	handler := NewConfigDiffHandler(rm, tmpFile, loader)

	req := httptest.NewRequest(http.MethodGet, "/admin/config/diff", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.False(t, response["has_changes"].(bool))
	assert.Empty(t, response["changes"])
	assert.Contains(t, response, "timestamp")
}

func TestConfigDiffHandler_ServeHTTP_GET_WithChanges(t *testing.T) {
	// Create a temporary config file with different content
	configContent := `
server:
  addr: ":9090"
`
	tmpFile := createTempFile(t, configContent)
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {

		}
	}(tmpFile)

	loader := config.NewLoader()
	initialConfig := &config.Config{
		Server: config.ServerConfig{Addr: ":8080"},
	}

	rm := config.NewReloadManager(tmpFile, loader, initialConfig)
	handler := NewConfigDiffHandler(rm, tmpFile, loader)

	req := httptest.NewRequest(http.MethodGet, "/admin/config/diff", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.True(t, response["has_changes"].(bool))

	changes := response["changes"].([]interface{})
	assert.NotEmpty(t, changes)

	// Should detect the server.addr change
	found := false
	for _, change := range changes {
		changeMap := change.(map[string]interface{})
		if changeMap["field"] == "server.addr" {
			assert.Equal(t, ":8080", changeMap["old_value"])
			assert.Equal(t, ":9090", changeMap["new_value"])
			found = true
			break
		}
	}
	assert.True(t, found, "Should find server.addr change")
}

func TestConfigDiffHandler_ServeHTTP_GET_InvalidConfigFile(t *testing.T) {
	// Create a temporary config file with invalid YAML
	configContent := `
server:
  addr: ":9090"
  invalid: [
`
	tmpFile := createTempFile(t, configContent)
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			
		}
	}(tmpFile)

	loader := config.NewLoader()
	initialConfig := &config.Config{
		Server: config.ServerConfig{Addr: ":8080"},
	}

	rm := config.NewReloadManager(tmpFile, loader, initialConfig)
	handler := NewConfigDiffHandler(rm, tmpFile, loader)

	req := httptest.NewRequest(http.MethodGet, "/admin/config/diff", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to load config file")
}

func TestConfigDiffHandler_ServeHTTP_InvalidMethod(t *testing.T) {
	rm := config.NewReloadManager("config.yaml", config.NewLoader(), &config.Config{})
	handler := NewConfigDiffHandler(rm, "config.yaml", config.NewLoader())

	req := httptest.NewRequest(http.MethodPost, "/admin/config/diff", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
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

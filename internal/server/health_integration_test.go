package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// Mock implementations for testing

type mockHealthChecker struct {
	checks map[string]func(ctx context.Context) (string, string)
}

func newMockHealthChecker() *mockHealthChecker {
	return &mockHealthChecker{
		checks: make(map[string]func(ctx context.Context) (string, string)),
	}
}

func (m *mockHealthChecker) RegisterCheck(name string, checkFunc func(ctx context.Context) (string, string)) {
	m.checks[name] = checkFunc
}

func (m *mockHealthChecker) RunAllChecks(ctx context.Context) {
	// Run all registered checks
	for _, checkFunc := range m.checks {
		checkFunc(ctx)
	}
}

func (m *mockHealthChecker) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		json.NewEncoder(w).Encode(response)
	}
}

func (m *mockHealthChecker) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		m.RunAllChecks(ctx)

		// Check if all checks are healthy
		allHealthy := true
		checks := make(map[string]interface{})

		for name, checkFunc := range m.checks {
			status, message := checkFunc(ctx)
			checks[name] = map[string]interface{}{
				"status":  status,
				"message": message,
			}
			if status != "healthy" {
				allHealthy = false
			}
		}

		w.Header().Set("Content-Type", "application/json")

		response := map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"checks":    checks,
		}

		if allHealthy {
			response["status"] = "healthy"
			w.WriteHeader(http.StatusOK)
		} else {
			response["status"] = "unhealthy"
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(response)
	}
}

func (m *mockHealthChecker) StartPeriodicChecks(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.RunAllChecks(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

type mockAlertHandler struct {
	alerts []mockAlert
}

type mockAlert struct {
	level     string
	component string
	message   string
}

func (m *mockAlertHandler) SendAlert(ctx context.Context, level string, component, message string) error {
	m.alerts = append(m.alerts, mockAlert{
		level:     level,
		component: component,
		message:   message,
	})
	return nil
}

type mockEventBuffer struct {
	events []interface{}
}

func (m *mockEventBuffer) BufferEvent(event interface{}) error {
	m.events = append(m.events, event)
	return nil
}

func (m *mockEventBuffer) FlushBufferedEvents(ctx context.Context) error {
	m.events = nil
	return nil
}

func (m *mockEventBuffer) GetBufferedEventCount() int {
	return len(m.events)
}

type mockHealthCheckableComponent struct {
	status  string
	message string
}

func (m *mockHealthCheckableComponent) HealthCheck(ctx context.Context) (string, string) {
	return m.status, m.message
}

func TestAirlockServer_HealthEndpoints(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultConfig()
	config.Addr = ":0" // Use random port for testing

	server := NewAirlockServer(logger, config)

	// Set up mock health checker
	healthChecker := newMockHealthChecker()
	server.SetHealthChecker(healthChecker)

	// Register mock health checks
	mockAuth := &mockHealthCheckableComponent{status: "healthy", message: "JWKS operational"}
	mockPolicy := &mockHealthCheckableComponent{status: "healthy", message: "Policy engine operational"}
	mockAudit := &mockHealthCheckableComponent{status: "healthy", message: "Audit store operational"}
	mockUpstream := &mockHealthCheckableComponent{status: "healthy", message: "Upstream connections healthy"}

	server.RegisterHealthChecks(mockAuth, mockPolicy, mockAudit, mockUpstream)

	// Test liveness endpoint
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d for liveness, got %d", http.StatusOK, w.Code)
	}

	var livenessResponse map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &livenessResponse); err != nil {
		t.Errorf("Failed to unmarshal liveness response: %v", err)
	}

	if livenessResponse["status"] != "healthy" {
		t.Errorf("Expected liveness status 'healthy', got %v", livenessResponse["status"])
	}

	// Test readiness endpoint
	req = httptest.NewRequest("GET", "/ready", nil)
	w = httptest.NewRecorder()

	server.handleReady(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d for readiness, got %d", http.StatusOK, w.Code)
	}

	var readinessResponse map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &readinessResponse); err != nil {
		t.Errorf("Failed to unmarshal readiness response: %v", err)
	}

	if readinessResponse["status"] != "healthy" {
		t.Errorf("Expected readiness status 'healthy', got %v", readinessResponse["status"])
	}

	// Check that all health checks are included
	checks, ok := readinessResponse["checks"].(map[string]interface{})
	if !ok {
		t.Error("Expected checks to be present in readiness response")
	}

	expectedChecks := []string{"jwks", "policy", "audit", "upstream"}
	for _, checkName := range expectedChecks {
		if _, exists := checks[checkName]; !exists {
			t.Errorf("Expected health check '%s' to be present", checkName)
		}
	}
}

func TestAirlockServer_HealthEndpoints_Unhealthy(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultConfig()
	config.Addr = ":0"

	server := NewAirlockServer(logger, config)

	// Set up mock health checker
	healthChecker := newMockHealthChecker()
	server.SetHealthChecker(healthChecker)

	// Register health checks with one unhealthy component
	mockAuth := &mockHealthCheckableComponent{status: "healthy", message: "JWKS operational"}
	mockPolicy := &mockHealthCheckableComponent{status: "unhealthy", message: "Policy compilation failed"}
	mockAudit := &mockHealthCheckableComponent{status: "healthy", message: "Audit store operational"}
	mockUpstream := &mockHealthCheckableComponent{status: "healthy", message: "Upstream connections healthy"}

	server.RegisterHealthChecks(mockAuth, mockPolicy, mockAudit, mockUpstream)

	// Test readiness endpoint with unhealthy component
	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()

	server.handleReady(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status code %d for unhealthy readiness, got %d", http.StatusServiceUnavailable, w.Code)
	}

	var readinessResponse map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &readinessResponse); err != nil {
		t.Errorf("Failed to unmarshal readiness response: %v", err)
	}

	if readinessResponse["status"] != "unhealthy" {
		t.Errorf("Expected readiness status 'unhealthy', got %v", readinessResponse["status"])
	}

	// Verify the unhealthy check is reported correctly
	checks, ok := readinessResponse["checks"].(map[string]interface{})
	if !ok {
		t.Error("Expected checks to be present in readiness response")
	}

	policyCheck, exists := checks["policy"].(map[string]interface{})
	if !exists {
		t.Error("Expected policy check to be present")
	}

	if policyCheck["status"] != "unhealthy" {
		t.Errorf("Expected policy check status 'unhealthy', got %v", policyCheck["status"])
	}

	if policyCheck["message"] != "Policy compilation failed" {
		t.Errorf("Expected policy check message 'Policy compilation failed', got %v", policyCheck["message"])
	}
}

func TestAirlockServer_RegisterHealthChecks_WithAlerting(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultConfig()
	server := NewAirlockServer(logger, config)

	// Set up mock components
	healthChecker := newMockHealthChecker()
	alertHandler := &mockAlertHandler{}
	eventBuffer := &mockEventBuffer{}

	server.SetHealthChecker(healthChecker)
	server.SetAlertHandler(alertHandler)
	server.SetEventBuffer(eventBuffer)

	// Register health checks with unhealthy audit store
	mockAuth := &mockHealthCheckableComponent{status: "healthy", message: "JWKS operational"}
	mockPolicy := &mockHealthCheckableComponent{status: "healthy", message: "Policy engine operational"}
	mockAudit := &mockHealthCheckableComponent{status: "unhealthy", message: "Database connection failed"}
	mockUpstream := &mockHealthCheckableComponent{status: "healthy", message: "Upstream connections healthy"}

	server.RegisterHealthChecks(mockAuth, mockPolicy, mockAudit, mockUpstream)

	// Run audit health check (should trigger alert)
	ctx := context.Background()
	if auditCheck, exists := healthChecker.checks["audit"]; exists {
		status, message := auditCheck(ctx)
		if status != "unhealthy" {
			t.Errorf("Expected audit check status 'unhealthy', got %s", status)
		}
		if message != "Database connection failed" {
			t.Errorf("Expected audit check message 'Database connection failed', got %s", message)
		}
	} else {
		t.Error("Expected audit health check to be registered")
	}

	// Verify alert was sent
	if len(alertHandler.alerts) != 1 {
		t.Errorf("Expected 1 alert to be sent, got %d", len(alertHandler.alerts))
	}

	alert := alertHandler.alerts[0]
	if alert.level != "critical" {
		t.Errorf("Expected critical alert level, got %s", alert.level)
	}
	if alert.component != "audit_store" {
		t.Errorf("Expected component 'audit_store', got %s", alert.component)
	}
}

func TestAirlockServer_HealthEndpoints_NoHealthChecker(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultConfig()
	server := NewAirlockServer(logger, config)

	// Don't set health checker - test fallback behavior

	// Test liveness endpoint fallback
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d for liveness fallback, got %d", http.StatusOK, w.Code)
	}

	var livenessResponse map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &livenessResponse); err != nil {
		t.Errorf("Failed to unmarshal liveness response: %v", err)
	}

	if livenessResponse["status"] != "healthy" {
		t.Errorf("Expected liveness status 'healthy', got %v", livenessResponse["status"])
	}

	// Test readiness endpoint fallback
	req = httptest.NewRequest("GET", "/ready", nil)
	w = httptest.NewRecorder()

	// Server not started, should return not ready
	server.handleReady(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status code %d for not ready, got %d", http.StatusServiceUnavailable, w.Code)
	}

	var readinessResponse map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &readinessResponse); err != nil {
		t.Errorf("Failed to unmarshal readiness response: %v", err)
	}

	if readinessResponse["status"] != "not_ready" {
		t.Errorf("Expected readiness status 'not_ready', got %v", readinessResponse["status"])
	}
}

func TestAirlockServer_RegisterHealthChecks_MissingComponents(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := DefaultConfig()
	server := NewAirlockServer(logger, config)

	healthChecker := newMockHealthChecker()
	server.SetHealthChecker(healthChecker)

	// Register health checks with some nil components
	server.RegisterHealthChecks(nil, nil, nil, nil)

	// Should not panic and should not register any checks
	if len(healthChecker.checks) != 0 {
		t.Errorf("Expected 0 health checks with nil components, got %d", len(healthChecker.checks))
	}

	// Register with some valid components
	mockAuth := &mockHealthCheckableComponent{status: "healthy", message: "JWKS operational"}
	mockPolicy := &mockHealthCheckableComponent{status: "healthy", message: "Policy engine operational"}

	server.RegisterHealthChecks(mockAuth, mockPolicy, nil, nil)

	// Should register only the valid components
	expectedChecks := []string{"jwks", "policy"}
	if len(healthChecker.checks) != len(expectedChecks) {
		t.Errorf("Expected %d health checks, got %d", len(expectedChecks), len(healthChecker.checks))
	}

	for _, checkName := range expectedChecks {
		if _, exists := healthChecker.checks[checkName]; !exists {
			t.Errorf("Expected health check '%s' to be registered", checkName)
		}
	}
}

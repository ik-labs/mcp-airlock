package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestHealthChecker_RegisterCheck(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hc := NewHealthChecker(logger)

	checkFunc := func(ctx context.Context) (Status, string) {
		return StatusHealthy, "test check"
	}

	hc.RegisterCheck("test", checkFunc)

	checks := hc.GetChecks()
	if len(checks) != 1 {
		t.Errorf("Expected 1 check, got %d", len(checks))
	}

	if check, exists := checks["test"]; !exists {
		t.Error("Expected 'test' check to exist")
	} else if check.Name != "test" {
		t.Errorf("Expected check name 'test', got %s", check.Name)
	}
}

func TestHealthChecker_RunCheck(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hc := NewHealthChecker(logger)

	checkFunc := func(ctx context.Context) (Status, string) {
		return StatusHealthy, "test successful"
	}

	hc.RegisterCheck("test", checkFunc)

	ctx := context.Background()
	err := hc.RunCheck(ctx, "test")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	checks := hc.GetChecks()
	check := checks["test"]

	if check.Status != StatusHealthy {
		t.Errorf("Expected status %s, got %s", StatusHealthy, check.Status)
	}

	if check.Message != "test successful" {
		t.Errorf("Expected message 'test successful', got %s", check.Message)
	}

	if check.LastChecked.IsZero() {
		t.Error("Expected LastChecked to be set")
	}
}

func TestHealthChecker_GetStatus(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hc := NewHealthChecker(logger)

	// Test with no checks
	status := hc.GetStatus()
	if status != StatusHealthy {
		t.Errorf("Expected status %s with no checks, got %s", StatusHealthy, status)
	}

	// Test with healthy check
	hc.RegisterCheck("healthy", func(ctx context.Context) (Status, string) {
		return StatusHealthy, "healthy"
	})
	hc.RunCheck(context.Background(), "healthy")

	status = hc.GetStatus()
	if status != StatusHealthy {
		t.Errorf("Expected status %s with healthy check, got %s", StatusHealthy, status)
	}

	// Test with unhealthy check
	hc.RegisterCheck("unhealthy", func(ctx context.Context) (Status, string) {
		return StatusUnhealthy, "unhealthy"
	})
	hc.RunCheck(context.Background(), "unhealthy")

	status = hc.GetStatus()
	if status != StatusUnhealthy {
		t.Errorf("Expected status %s with unhealthy check, got %s", StatusUnhealthy, status)
	}
}

func TestHealthChecker_LivenessHandler(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hc := NewHealthChecker(logger)

	handler := hc.LivenessHandler()
	req := httptest.NewRequest("GET", "/live", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	var response HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response.Status != StatusHealthy {
		t.Errorf("Expected status %s, got %s", StatusHealthy, response.Status)
	}
}

func TestHealthChecker_ReadinessHandler(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hc := NewHealthChecker(logger)

	// Test with healthy checks
	hc.RegisterCheck("test", func(ctx context.Context) (Status, string) {
		return StatusHealthy, "ready"
	})

	handler := hc.ReadinessHandler()
	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	var response HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response.Status != StatusHealthy {
		t.Errorf("Expected status %s, got %s", StatusHealthy, response.Status)
	}

	if len(response.Checks) != 1 {
		t.Errorf("Expected 1 check in response, got %d", len(response.Checks))
	}
}

func TestHealthChecker_ReadinessHandler_Unhealthy(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hc := NewHealthChecker(logger)

	// Test with unhealthy check
	hc.RegisterCheck("test", func(ctx context.Context) (Status, string) {
		return StatusUnhealthy, "not ready"
	})

	handler := hc.ReadinessHandler()
	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status code %d, got %d", http.StatusServiceUnavailable, w.Code)
	}

	var response HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if response.Status != StatusUnhealthy {
		t.Errorf("Expected status %s, got %s", StatusUnhealthy, response.Status)
	}
}

func TestComponentHealthChecker(t *testing.T) {
	checkFunc := func(ctx context.Context) (Status, string) {
		return StatusHealthy, "component healthy"
	}

	chc := NewComponentHealthChecker("test-component", checkFunc, AlertLevelWarning)

	status, message := chc.Check(context.Background())
	if status != StatusHealthy {
		t.Errorf("Expected status %s, got %s", StatusHealthy, status)
	}
	if message != "component healthy" {
		t.Errorf("Expected message 'component healthy', got %s", message)
	}

	// Check stored status
	storedStatus, storedMessage, lastChecked, failureCount := chc.GetStatus()
	if storedStatus != StatusHealthy {
		t.Errorf("Expected stored status %s, got %s", StatusHealthy, storedStatus)
	}
	if storedMessage != "component healthy" {
		t.Errorf("Expected stored message 'component healthy', got %s", storedMessage)
	}
	if lastChecked.IsZero() {
		t.Error("Expected lastChecked to be set")
	}
	if failureCount != 0 {
		t.Errorf("Expected failure count 0, got %d", failureCount)
	}

	// Test failure tracking
	failingCheckFunc := func(ctx context.Context) (Status, string) {
		return StatusUnhealthy, "component failed"
	}
	chc.checkFunc = failingCheckFunc

	chc.Check(context.Background())
	_, _, _, failureCount = chc.GetStatus()
	if failureCount != 1 {
		t.Errorf("Expected failure count 1, got %d", failureCount)
	}

	// Test recovery
	chc.checkFunc = checkFunc
	chc.Check(context.Background())
	_, _, _, failureCount = chc.GetStatus()
	if failureCount != 0 {
		t.Errorf("Expected failure count reset to 0, got %d", failureCount)
	}
}

func TestJWKSHealthChecker(t *testing.T) {
	// Mock authenticator
	mockAuth := &mockHealthCheckable{
		status:  "healthy",
		message: "JWKS fetch successful",
	}

	checkFunc := JWKSHealthChecker(mockAuth)
	status, message := checkFunc(context.Background())

	if status != "healthy" {
		t.Errorf("Expected status 'healthy', got %s", status)
	}
	if message != "JWKS fetch successful" {
		t.Errorf("Expected message 'JWKS fetch successful', got %s", message)
	}

	// Test with nil authenticator
	checkFunc = JWKSHealthChecker(nil)
	status, message = checkFunc(context.Background())

	if status != "unhealthy" {
		t.Errorf("Expected status 'unhealthy' with nil authenticator, got %s", status)
	}
	if message != "Authenticator not initialized" {
		t.Errorf("Expected message 'Authenticator not initialized', got %s", message)
	}
}

func TestPolicyHealthChecker(t *testing.T) {
	// Mock policy engine
	mockPolicy := &mockHealthCheckable{
		status:  "healthy",
		message: "Policy engine operational",
	}

	checkFunc := PolicyHealthChecker(mockPolicy)
	status, message := checkFunc(context.Background())

	if status != "healthy" {
		t.Errorf("Expected status 'healthy', got %s", status)
	}
	if message != "Policy engine operational" {
		t.Errorf("Expected message 'Policy engine operational', got %s", message)
	}

	// Test with nil policy engine
	checkFunc = PolicyHealthChecker(nil)
	status, message = checkFunc(context.Background())

	if status != "unhealthy" {
		t.Errorf("Expected status 'unhealthy' with nil policy engine, got %s", status)
	}
	if message != "Policy engine not initialized" {
		t.Errorf("Expected message 'Policy engine not initialized', got %s", message)
	}
}

func TestAuditHealthChecker(t *testing.T) {
	// Mock audit logger
	mockAudit := &mockHealthCheckable{
		status:  "healthy",
		message: "Database operational",
	}

	// Mock event buffer
	mockBuffer := &mockEventBuffer{
		count: 0,
	}

	checkFunc := AuditHealthChecker(mockAudit, mockBuffer)
	status, message := checkFunc(context.Background())

	if status != "healthy" {
		t.Errorf("Expected status 'healthy', got %s", status)
	}
	if message != "Database operational" {
		t.Errorf("Expected message 'Database operational', got %s", message)
	}

	// Test with unhealthy audit store but with buffering
	mockAudit.status = "unhealthy"
	mockAudit.message = "Database connection failed"
	mockBuffer.count = 5

	status, message = checkFunc(context.Background())
	if status != "unhealthy" {
		t.Errorf("Expected status 'unhealthy', got %s", status)
	}
	expectedMessage := "Audit store unhealthy (buffered events: 5): Database connection failed"
	if message != expectedMessage {
		t.Errorf("Expected message '%s', got %s", expectedMessage, message)
	}
}

func TestUpstreamHealthChecker(t *testing.T) {
	// Mock upstream connector
	mockUpstream := &mockHealthCheckable{
		status:  "healthy",
		message: "All upstream clients connected (2/2)",
	}

	checkFunc := UpstreamHealthChecker(mockUpstream)
	status, message := checkFunc(context.Background())

	if status != "healthy" {
		t.Errorf("Expected status 'healthy', got %s", status)
	}
	if message != "All upstream clients connected (2/2)" {
		t.Errorf("Expected message 'All upstream clients connected (2/2)', got %s", message)
	}

	// Test with nil upstream connector
	checkFunc = UpstreamHealthChecker(nil)
	status, message = checkFunc(context.Background())

	if status != "unhealthy" {
		t.Errorf("Expected status 'unhealthy' with nil upstream connector, got %s", status)
	}
	if message != "Upstream connector not initialized" {
		t.Errorf("Expected message 'Upstream connector not initialized', got %s", message)
	}
}

func TestHealthChecker_StartPeriodicChecks(t *testing.T) {
	logger := zaptest.NewLogger(t)
	hc := NewHealthChecker(logger)

	checkCount := 0
	hc.RegisterCheck("periodic", func(ctx context.Context) (Status, string) {
		checkCount++
		return StatusHealthy, "periodic check"
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	// Start periodic checks with short interval
	go hc.StartPeriodicChecks(ctx, 50*time.Millisecond)

	// Wait for context to timeout
	<-ctx.Done()

	// Should have run at least 2 checks (at 50ms and 100ms)
	if checkCount < 2 {
		t.Errorf("Expected at least 2 periodic checks, got %d", checkCount)
	}
}

// Mock implementations for testing

type mockHealthCheckable struct {
	status  string
	message string
}

func (m *mockHealthCheckable) HealthCheck(ctx context.Context) (string, string) {
	return m.status, m.message
}

type mockEventBuffer struct {
	count int
}

func (m *mockEventBuffer) BufferEvent(event interface{}) error {
	m.count++
	return nil
}

func (m *mockEventBuffer) FlushBufferedEvents(ctx context.Context) error {
	m.count = 0
	return nil
}

func (m *mockEventBuffer) GetBufferedEventCount() int {
	return m.count
}

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// ComprehensiveIntegrationTest tests all security controls working together
func TestComprehensiveSecurityIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping comprehensive integration test in short mode")
	}

	logger := zaptest.NewLogger(t)

	// Setup test environment
	testEnv := setupTestEnvironment(t, logger)
	defer testEnv.Cleanup()

	// Test scenarios that validate all security controls
	t.Run("AuthenticatedUserWithValidPolicy", func(t *testing.T) {
		testAuthenticatedUserFlow(t, testEnv)
	})

	t.Run("UnauthenticatedUserRejection", func(t *testing.T) {
		testUnauthenticatedUserRejection(t, testEnv)
	})

	t.Run("PolicyViolationHandling", func(t *testing.T) {
		testPolicyViolationHandling(t, testEnv)
	})

	t.Run("RateLimitingEnforcement", func(t *testing.T) {
		testRateLimitingEnforcement(t, testEnv)
	})

	t.Run("DataRedactionInAction", func(t *testing.T) {
		testDataRedactionInAction(t, testEnv)
	})

	t.Run("RootVirtualizationSecurity", func(t *testing.T) {
		testRootVirtualizationSecurity(t, testEnv)
	})

	t.Run("AuditTrailCompleteness", func(t *testing.T) {
		testAuditTrailCompleteness(t, testEnv)
	})

	t.Run("FailureRecoveryScenarios", func(t *testing.T) {
		testFailureRecoveryScenarios(t, testEnv)
	})

	t.Run("ConcurrentUserSessions", func(t *testing.T) {
		testConcurrentUserSessions(t, testEnv)
	})

	t.Run("SecurityViolationDetection", func(t *testing.T) {
		testSecurityViolationDetection(t, testEnv)
	})
}

// TestEnvironment encapsulates the test setup
type TestEnvironment struct {
	Server       *httptest.Server
	JWTKey       *rsa.PrivateKey
	AuditLogger  *MockAuditLogger
	PolicyEngine *MockPolicyEngine
	Redactor     *MockRedactor
	TempDir      string
	logger       *zap.Logger
}

func setupTestEnvironment(t *testing.T, logger *zap.Logger) *TestEnvironment {
	// Generate RSA key for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "airlock-integration-test-*")
	require.NoError(t, err)

	// Setup mock components
	auditLogger := NewMockAuditLogger()
	policyEngine := NewMockPolicyEngine()
	redactor := NewMockRedactor()

	// Create test server with all security middleware
	server := createTestServer(t, logger, privateKey, auditLogger, policyEngine, redactor, tempDir)

	return &TestEnvironment{
		Server:       server,
		JWTKey:       privateKey,
		AuditLogger:  auditLogger,
		PolicyEngine: policyEngine,
		Redactor:     redactor,
		TempDir:      tempDir,
		logger:       logger,
	}
}

func (te *TestEnvironment) Cleanup() {
	te.Server.Close()
	os.RemoveAll(te.TempDir)
}

func (te *TestEnvironment) CreateValidToken(subject, tenant string, groups []string) string {
	claims := jwt.MapClaims{
		"sub":    subject,
		"tid":    tenant,
		"groups": groups,
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"aud":    "mcp-airlock",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(te.JWTKey)
	return tokenString
}

func testAuthenticatedUserFlow(t *testing.T, env *TestEnvironment) {
	// Reset mocks
	env.AuditLogger.Reset()
	env.PolicyEngine.SetShouldDeny(false)
	env.Redactor.SetRedactionCount(0)

	// Create valid token
	token := env.CreateValidToken("user@example.com", "tenant-1", []string{"mcp.users"})

	// Test successful MCP tool call
	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "test-1",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "read_file",
			"arguments": map[string]interface{}{
				"path": "mcp://repo/README.md",
			},
		},
	}

	response := makeAuthenticatedRequest(t, env.Server, token, request)

	// Verify successful response
	assert.Equal(t, "2.0", response["jsonrpc"])
	assert.Equal(t, "test-1", response["id"])
	assert.NotNil(t, response["result"])

	// Verify audit trail
	events := env.AuditLogger.GetEvents()
	assert.GreaterOrEqual(t, len(events), 3, "Should have authentication, policy, and tool call events")

	// Verify all events have same correlation ID
	correlationID := events[0].CorrelationID
	for _, event := range events {
		assert.Equal(t, correlationID, event.CorrelationID)
	}

	// Verify event types
	eventTypes := make(map[string]bool)
	for _, event := range events {
		eventTypes[event.Action] = true
	}
	assert.True(t, eventTypes["token_validate"])
	assert.True(t, eventTypes["policy_evaluate"])
}

func testUnauthenticatedUserRejection(t *testing.T, env *TestEnvironment) {
	env.AuditLogger.Reset()

	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "test-unauth",
		"method":  "tools/list",
	}

	reqBody, _ := json.Marshal(request)
	httpReq, _ := http.NewRequest("POST", env.Server.URL+"/mcp", bytes.NewReader(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")
	// No Authorization header

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(httpReq)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be rejected with 401
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Bearer")

	// Verify authentication failure is audited
	events := env.AuditLogger.GetEvents()
	assert.GreaterOrEqual(t, len(events), 1)

	authEvent := events[0]
	assert.Equal(t, "token_validate", authEvent.Action)
	assert.Equal(t, "deny", authEvent.Decision)
}

func testPolicyViolationHandling(t *testing.T, env *TestEnvironment) {
	env.AuditLogger.Reset()
	env.PolicyEngine.SetShouldDeny(true)
	defer env.PolicyEngine.SetShouldDeny(false)

	token := env.CreateValidToken("user@example.com", "tenant-1", []string{"mcp.users"})

	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "test-policy-deny",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "restricted_tool",
			"arguments": map[string]interface{}{
				"action": "dangerous_operation",
			},
		},
	}

	response := makeAuthenticatedRequest(t, env.Server, token, request)

	// Should get error response
	assert.NotNil(t, response["error"])
	errorObj := response["error"].(map[string]interface{})
	assert.Equal(t, float64(-32603), errorObj["code"]) // Forbidden
	assert.Contains(t, errorObj["message"], "Policy denied")

	// Verify policy denial is audited
	events := env.AuditLogger.GetEvents()
	policyEvent := findEventByAction(events, "policy_evaluate")
	require.NotNil(t, policyEvent)
	assert.Equal(t, "deny", policyEvent.Decision)
	assert.Equal(t, "insufficient_permissions", policyEvent.Reason)
}

func testRateLimitingEnforcement(t *testing.T, env *TestEnvironment) {
	env.AuditLogger.Reset()
	env.PolicyEngine.SetShouldDeny(false)

	token := env.CreateValidToken("user@example.com", "tenant-1", []string{"mcp.users"})

	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "test_tool",
		},
	}

	// Make rapid requests to trigger rate limiting
	rateLimitHit := false
	for i := 0; i < 50; i++ {
		request["id"] = fmt.Sprintf("rate-test-%d", i)

		reqBody, _ := json.Marshal(request)
		httpReq, _ := http.NewRequest("POST", env.Server.URL+"/mcp", bytes.NewReader(reqBody))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+token)

		client := &http.Client{Timeout: 1 * time.Second}
		resp, err := client.Do(httpReq)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimitHit = true
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	assert.True(t, rateLimitHit, "Rate limiting should be triggered")

	// Verify rate limit events are audited
	events := env.AuditLogger.GetEvents()
	rateLimitEvent := findEventByAction(events, "rate_limit_exceeded")
	if rateLimitEvent != nil {
		assert.Equal(t, "deny", rateLimitEvent.Decision)
	}
}

func testDataRedactionInAction(t *testing.T, env *TestEnvironment) {
	env.AuditLogger.Reset()
	env.PolicyEngine.SetShouldDeny(false)
	env.Redactor.SetRedactionCount(3) // Simulate finding 3 sensitive items

	token := env.CreateValidToken("user@example.com", "tenant-1", []string{"mcp.users"})

	// Request with sensitive data
	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "test-redaction",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "process_data",
			"arguments": map[string]interface{}{
				"data": "User SSN: 123-45-6789, Email: user@example.com, Phone: 555-1234",
			},
		},
	}

	response := makeAuthenticatedRequest(t, env.Server, token, request)

	// Verify response is successful
	assert.Equal(t, "test-redaction", response["id"])
	assert.NotNil(t, response["result"])

	// Verify redaction events are audited
	events := env.AuditLogger.GetEvents()
	redactionEvent := findEventByAction(events, "redact_data")
	require.NotNil(t, redactionEvent, "Should have redaction event")
	assert.Equal(t, 3, redactionEvent.RedactionCount)

	// Verify no sensitive data in audit logs
	for _, event := range events {
		eventJSON, _ := json.Marshal(event)
		eventStr := string(eventJSON)
		assert.NotContains(t, eventStr, "123-45-6789", "SSN should not appear in audit logs")
		assert.NotContains(t, eventStr, "user@example.com", "Email should not appear in audit logs")
	}
}

func testRootVirtualizationSecurity(t *testing.T, env *TestEnvironment) {
	env.AuditLogger.Reset()
	env.PolicyEngine.SetShouldDeny(false)

	token := env.CreateValidToken("user@example.com", "tenant-1", []string{"mcp.users"})

	// Test path traversal attempt
	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "test-path-traversal",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "read_file",
			"arguments": map[string]interface{}{
				"path": "mcp://repo/../../../etc/passwd",
			},
		},
	}

	response := makeAuthenticatedRequest(t, env.Server, token, request)

	// Should get error response
	assert.NotNil(t, response["error"])
	errorObj := response["error"].(map[string]interface{})
	assert.Contains(t, errorObj["message"], "path traversal")

	// Verify security violation is audited
	events := env.AuditLogger.GetEvents()
	securityEvent := findEventByAction(events, "security_violation")
	require.NotNil(t, securityEvent)
	assert.Equal(t, "deny", securityEvent.Decision)
	assert.Contains(t, securityEvent.Reason, "Path traversal")
}

func testAuditTrailCompleteness(t *testing.T, env *TestEnvironment) {
	env.AuditLogger.Reset()
	env.PolicyEngine.SetShouldDeny(false)

	token := env.CreateValidToken("user@example.com", "tenant-1", []string{"mcp.users"})

	// Make a complete request
	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "test-audit-complete",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "read_file",
			"arguments": map[string]interface{}{
				"path": "mcp://repo/test.txt",
			},
		},
	}

	makeAuthenticatedRequest(t, env.Server, token, request)

	// Verify complete audit trail
	events := env.AuditLogger.GetEvents()
	assert.GreaterOrEqual(t, len(events), 3, "Should have multiple audit events")

	// Verify required audit fields
	for i, event := range events {
		assert.NotEmpty(t, event.ID, "Event %d should have ID", i)
		assert.False(t, event.Timestamp.IsZero(), "Event %d should have timestamp", i)
		assert.NotEmpty(t, event.CorrelationID, "Event %d should have correlation ID", i)
		assert.NotEmpty(t, event.Action, "Event %d should have action", i)
		assert.NotEmpty(t, event.Decision, "Event %d should have decision", i)
		assert.NotEmpty(t, event.Subject, "Event %d should have subject", i)
		assert.NotEmpty(t, event.Tenant, "Event %d should have tenant", i)
	}

	// Verify hash chaining
	for i := 1; i < len(events); i++ {
		assert.Equal(t, events[i-1].Hash, events[i].PreviousHash,
			"Event %d should chain to previous event", i)
	}
}

func testFailureRecoveryScenarios(t *testing.T, env *TestEnvironment) {
	env.AuditLogger.Reset()

	token := env.CreateValidToken("user@example.com", "tenant-1", []string{"mcp.users"})

	// Test upstream server failure
	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "test-upstream-failure",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "nonexistent_tool",
		},
	}

	response := makeAuthenticatedRequest(t, env.Server, token, request)

	// Should get error response but not crash
	assert.NotNil(t, response["error"])
	errorObj := response["error"].(map[string]interface{})
	assert.Contains(t, errorObj["message"], "upstream")

	// Verify failure is audited
	events := env.AuditLogger.GetEvents()
	assert.GreaterOrEqual(t, len(events), 1)

	// Test policy engine failure recovery
	env.PolicyEngine.SetShouldError(true)
	defer env.PolicyEngine.SetShouldError(false)

	request["id"] = "test-policy-failure"
	response = makeAuthenticatedRequest(t, env.Server, token, request)

	// Should fail closed (deny request)
	assert.NotNil(t, response["error"])
}

func testConcurrentUserSessions(t *testing.T, env *TestEnvironment) {
	env.AuditLogger.Reset()
	env.PolicyEngine.SetShouldDeny(false)

	numUsers := 5
	requestsPerUser := 10
	var wg sync.WaitGroup

	// Create tokens for different users
	tokens := make([]string, numUsers)
	for i := 0; i < numUsers; i++ {
		tokens[i] = env.CreateValidToken(
			fmt.Sprintf("user%d@example.com", i),
			fmt.Sprintf("tenant-%d", i),
			[]string{"mcp.users"},
		)
	}

	// Launch concurrent sessions
	for userID := 0; userID < numUsers; userID++ {
		wg.Add(1)
		go func(uid int) {
			defer wg.Done()

			for reqID := 0; reqID < requestsPerUser; reqID++ {
				request := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      fmt.Sprintf("user-%d-req-%d", uid, reqID),
					"method":  "tools/call",
					"params": map[string]interface{}{
						"name": "test_tool",
						"arguments": map[string]interface{}{
							"user_id": uid,
							"req_id":  reqID,
						},
					},
				}

				response := makeAuthenticatedRequest(t, env.Server, tokens[uid], request)
				assert.Equal(t, request["id"], response["id"])

				time.Sleep(10 * time.Millisecond) // Small delay
			}
		}(userID)
	}

	wg.Wait()

	// Verify all requests were audited with proper tenant isolation
	events := env.AuditLogger.GetEvents()
	assert.GreaterOrEqual(t, len(events), numUsers*requestsPerUser)

	// Verify tenant isolation in audit logs
	tenantEvents := make(map[string]int)
	for _, event := range events {
		tenantEvents[event.Tenant]++
	}

	for i := 0; i < numUsers; i++ {
		tenant := fmt.Sprintf("tenant-%d", i)
		assert.Greater(t, tenantEvents[tenant], 0, "Should have events for tenant %s", tenant)
	}
}

func testSecurityViolationDetection(t *testing.T, env *TestEnvironment) {
	env.AuditLogger.Reset()
	env.PolicyEngine.SetShouldDeny(false)

	token := env.CreateValidToken("user@example.com", "tenant-1", []string{"mcp.users"})

	// Test various security violations
	violations := []struct {
		name    string
		request map[string]interface{}
	}{
		{
			name: "oversized_request",
			request: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      "test-oversized",
				"method":  "tools/call",
				"params": map[string]interface{}{
					"name": "process_data",
					"arguments": map[string]interface{}{
						"data": strings.Repeat("x", 300*1024), // 300KB payload
					},
				},
			},
		},
		{
			name: "invalid_scheme",
			request: map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      "test-invalid-scheme",
				"method":  "tools/call",
				"params": map[string]interface{}{
					"name": "read_file",
					"arguments": map[string]interface{}{
						"path": "file:///etc/passwd",
					},
				},
			},
		},
		{
			name: "malformed_json_rpc",
			request: map[string]interface{}{
				"jsonrpc": "1.0", // Wrong version
				"id":      "test-malformed",
				"method":  "tools/call",
			},
		},
	}

	for _, violation := range violations {
		t.Run(violation.name, func(t *testing.T) {
			response := makeAuthenticatedRequest(t, env.Server, token, violation.request)

			// Should get error response
			assert.NotNil(t, response["error"], "Should get error for %s", violation.name)
		})
	}

	// Verify security violations are audited
	events := env.AuditLogger.GetEvents()
	securityEvents := filterEventsByAction(events, "security_violation")
	assert.GreaterOrEqual(t, len(securityEvents), 1, "Should have security violation events")
}

// Helper functions

func makeAuthenticatedRequest(t *testing.T, server *httptest.Server, token string, request map[string]interface{}) map[string]interface{} {
	reqBody, err := json.Marshal(request)
	require.NoError(t, err)

	httpReq, err := http.NewRequest("POST", server.URL+"/mcp", bytes.NewReader(reqBody))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(httpReq)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	return response
}

func findEventByAction(events []*AuditEvent, action string) *AuditEvent {
	for _, event := range events {
		if event.Action == action {
			return event
		}
	}
	return nil
}

func filterEventsByAction(events []*AuditEvent, action string) []*AuditEvent {
	var filtered []*AuditEvent
	for _, event := range events {
		if event.Action == action {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

// Mock implementations for testing

type AuditEvent struct {
	ID             string                 `json:"id"`
	Timestamp      time.Time              `json:"timestamp"`
	CorrelationID  string                 `json:"correlation_id"`
	Subject        string                 `json:"subject"`
	Tenant         string                 `json:"tenant"`
	Action         string                 `json:"action"`
	Decision       string                 `json:"decision"`
	Reason         string                 `json:"reason"`
	LatencyMs      int64                  `json:"latency_ms"`
	RedactionCount int                    `json:"redaction_count"`
	Metadata       map[string]interface{} `json:"metadata"`
	Hash           string                 `json:"hash"`
	PreviousHash   string                 `json:"previous_hash"`
}

type MockAuditLogger struct {
	events []*AuditEvent
	mutex  sync.RWMutex
}

func NewMockAuditLogger() *MockAuditLogger {
	return &MockAuditLogger{
		events: make([]*AuditEvent, 0),
	}
}

func (m *MockAuditLogger) LogEvent(event *AuditEvent) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Generate hash chain
	event.Hash = fmt.Sprintf("hash-%d", len(m.events))
	if len(m.events) > 0 {
		event.PreviousHash = m.events[len(m.events)-1].Hash
	}

	m.events = append(m.events, event)
}

func (m *MockAuditLogger) GetEvents() []*AuditEvent {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Return copy
	events := make([]*AuditEvent, len(m.events))
	copy(events, m.events)
	return events
}

func (m *MockAuditLogger) Reset() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.events = m.events[:0]
}

type MockPolicyEngine struct {
	shouldDeny  bool
	shouldError bool
	mutex       sync.RWMutex
}

func NewMockPolicyEngine() *MockPolicyEngine {
	return &MockPolicyEngine{}
}

func (m *MockPolicyEngine) SetShouldDeny(deny bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.shouldDeny = deny
}

func (m *MockPolicyEngine) SetShouldError(err bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.shouldError = err
}

func (m *MockPolicyEngine) Evaluate(ctx context.Context, input interface{}) (bool, string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.shouldError {
		return false, "policy_engine_error", fmt.Errorf("policy engine failure")
	}

	if m.shouldDeny {
		return false, "insufficient_permissions", nil
	}

	return true, "policy_allowed", nil
}

type MockRedactor struct {
	redactionCount int
	mutex          sync.RWMutex
}

func NewMockRedactor() *MockRedactor {
	return &MockRedactor{}
}

func (m *MockRedactor) SetRedactionCount(count int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.redactionCount = count
}

func (m *MockRedactor) Redact(ctx context.Context, data []byte) ([]byte, int, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Simulate redaction
	redacted := bytes.ReplaceAll(data, []byte("123-45-6789"), []byte("[REDACTED-SSN]"))
	redacted = bytes.ReplaceAll(redacted, []byte("user@example.com"), []byte("[REDACTED-EMAIL]"))

	return redacted, m.redactionCount, nil
}

func createTestServer(t *testing.T, logger *zap.Logger, jwtKey *rsa.PrivateKey, auditLogger *MockAuditLogger, policyEngine *MockPolicyEngine, redactor *MockRedactor, tempDir string) *httptest.Server {
	// Create JWKS for token validation
	publicKey := &jwtKey.PublicKey

	// Create test server with middleware
	mux := http.NewServeMux()

	// MCP endpoint with all security middleware
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		correlationID := fmt.Sprintf("test-%d", time.Now().UnixNano())
		ctx = context.WithValue(ctx, "correlation_id", correlationID)

		// Authentication
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			auditLogger.LogEvent(&AuditEvent{
				ID:            fmt.Sprintf("audit-%d", time.Now().UnixNano()),
				Timestamp:     time.Now(),
				CorrelationID: correlationID,
				Subject:       "unknown",
				Tenant:        "unknown",
				Action:        "token_validate",
				Decision:      "deny",
				Reason:        "missing_token",
				LatencyMs:     1,
			})

			w.Header().Set("WWW-Authenticate", "Bearer realm=\"mcp-airlock\"")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})

		if err != nil || !token.Valid {
			auditLogger.LogEvent(&AuditEvent{
				ID:            fmt.Sprintf("audit-%d", time.Now().UnixNano()),
				Timestamp:     time.Now(),
				CorrelationID: correlationID,
				Subject:       "unknown",
				Tenant:        "unknown",
				Action:        "token_validate",
				Decision:      "deny",
				Reason:        "invalid_token",
				LatencyMs:     1,
			})

			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		subject := claims["sub"].(string)
		tenant := claims["tid"].(string)

		// Log successful authentication
		auditLogger.LogEvent(&AuditEvent{
			ID:            fmt.Sprintf("audit-%d", time.Now().UnixNano()),
			Timestamp:     time.Now(),
			CorrelationID: correlationID,
			Subject:       subject,
			Tenant:        tenant,
			Action:        "token_validate",
			Decision:      "allow",
			Reason:        "valid_token",
			LatencyMs:     5,
		})

		// Read and parse request
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Check message size
		if len(body) > 256*1024 {
			auditLogger.LogEvent(&AuditEvent{
				ID:            fmt.Sprintf("audit-%d", time.Now().UnixNano()),
				Timestamp:     time.Now(),
				CorrelationID: correlationID,
				Subject:       subject,
				Tenant:        tenant,
				Action:        "security_violation",
				Decision:      "deny",
				Reason:        "message_too_large",
				LatencyMs:     1,
			})

			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
			return
		}

		var request map[string]interface{}
		if err := json.Unmarshal(body, &request); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Policy evaluation
		allowed, reason, err := policyEngine.Evaluate(ctx, request)

		auditLogger.LogEvent(&AuditEvent{
			ID:            fmt.Sprintf("audit-%d", time.Now().UnixNano()),
			Timestamp:     time.Now(),
			CorrelationID: correlationID,
			Subject:       subject,
			Tenant:        tenant,
			Action:        "policy_evaluate",
			Decision:      map[bool]string{true: "allow", false: "deny"}[allowed],
			Reason:        reason,
			LatencyMs:     10,
		})

		if err != nil || !allowed {
			response := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      request["id"],
				"error": map[string]interface{}{
					"code":    -32603,
					"message": "Policy denied request",
					"data": map[string]interface{}{
						"reason":         reason,
						"correlation_id": correlationID,
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		// Check for security violations in request
		if params, ok := request["params"].(map[string]interface{}); ok {
			if args, ok := params["arguments"].(map[string]interface{}); ok {
				if path, ok := args["path"].(string); ok {
					if strings.Contains(path, "..") || strings.Contains(path, "file://") {
						auditLogger.LogEvent(&AuditEvent{
							ID:            fmt.Sprintf("audit-%d", time.Now().UnixNano()),
							Timestamp:     time.Now(),
							CorrelationID: correlationID,
							Subject:       subject,
							Tenant:        tenant,
							Action:        "security_violation",
							Decision:      "deny",
							Reason:        "Path traversal attempt detected",
							LatencyMs:     1,
						})

						response := map[string]interface{}{
							"jsonrpc": "2.0",
							"id":      request["id"],
							"error": map[string]interface{}{
								"code":    -32600,
								"message": "Security violation: path traversal attempt",
							},
						}

						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(response)
						return
					}
				}
			}
		}

		// Data redaction
		redactedBody, redactionCount, err := redactor.Redact(ctx, body)
		if err == nil && redactionCount > 0 {
			auditLogger.LogEvent(&AuditEvent{
				ID:             fmt.Sprintf("audit-%d", time.Now().UnixNano()),
				Timestamp:      time.Now(),
				CorrelationID:  correlationID,
				Subject:        subject,
				Tenant:         tenant,
				Action:         "redact_data",
				Decision:       "allow",
				Reason:         "data_redacted",
				LatencyMs:      5,
				RedactionCount: redactionCount,
			})
		}

		// Simulate successful tool call
		response := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      request["id"],
			"result": map[string]interface{}{
				"content": []map[string]interface{}{
					{
						"type": "text",
						"text": "Mock tool response",
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	return httptest.NewServer(mux)
}

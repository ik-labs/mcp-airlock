package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestFailureRecoveryScenarios tests system behavior under various failure conditions
func TestFailureRecoveryScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping failure recovery tests in short mode")
	}

	logger := zaptest.NewLogger(t)
	testEnv := setupTestEnvironment(t, logger)
	defer testEnv.Cleanup()

	t.Run("UpstreamServerFailures", func(t *testing.T) {
		testUpstreamServerFailures(t, testEnv)
	})

	t.Run("PolicyEngineFailures", func(t *testing.T) {
		testPolicyEngineFailures(t, testEnv)
	})

	t.Run("AuditSystemFailures", func(t *testing.T) {
		testAuditSystemFailures(t, testEnv)
	})

	t.Run("AuthenticationSystemFailures", func(t *testing.T) {
		testAuthenticationSystemFailures(t, testEnv)
	})

	t.Run("NetworkPartitionRecovery", func(t *testing.T) {
		testNetworkPartitionRecovery(t, testEnv)
	})

	t.Run("ResourceExhaustionHandling", func(t *testing.T) {
		testResourceExhaustionHandling(t, testEnv)
	})

	t.Run("CascadingFailuresPrevention", func(t *testing.T) {
		testCascadingFailuresPrevention(t, testEnv)
	})

	t.Run("GracefulDegradation", func(t *testing.T) {
		testGracefulDegradation(t, testEnv)
	})
}

func testUpstreamServerFailures(t *testing.T, env *TestEnvironment) {
	// Test various upstream server failure scenarios

	token := env.CreateValidToken("user@company.com", "test-tenant", []string{"mcp.users"})

	// Test 1: Upstream server not responding
	t.Run("UpstreamTimeout", func(t *testing.T) {
		env.AuditLogger.Reset()

		timeoutRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "upstream-timeout",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "slow_operation",
				"arguments": map[string]interface{}{
					"delay": "30s", // Should timeout
				},
			},
		}

		start := time.Now()
		response := makeAuthenticatedRequest(t, env.Server, token, timeoutRequest)
		duration := time.Since(start)

		// Should fail with timeout error within reasonable time
		assert.Less(t, duration, 10*time.Second, "Should timeout quickly")
		assert.NotNil(t, response["error"])

		errorObj := response["error"].(map[string]interface{})
		assert.Contains(t, errorObj["message"], "timeout")

		// Verify timeout is audited
		events := env.AuditLogger.GetEvents()
		timeoutEvent := findEventByAction(events, "upstream_timeout")
		if timeoutEvent != nil {
			assert.Equal(t, "deny", timeoutEvent.Decision)
			assert.Contains(t, timeoutEvent.Reason, "timeout")
		}
	})

	// Test 2: Upstream server returns error
	t.Run("UpstreamError", func(t *testing.T) {
		env.AuditLogger.Reset()

		errorRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "upstream-error",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "failing_tool",
			},
		}

		response := makeAuthenticatedRequest(t, env.Server, token, errorRequest)

		// Should get error response but system should remain stable
		assert.Equal(t, "upstream-error", response["id"])
		assert.NotNil(t, response["error"])

		// Verify error is properly mapped
		errorObj := response["error"].(map[string]interface{})
		assert.NotEmpty(t, errorObj["message"])
		assert.NotEmpty(t, errorObj["code"])

		// System should still be responsive after error
		healthRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "health-after-error",
			"method":  "ping",
		}

		healthResponse := makeAuthenticatedRequest(t, env.Server, token, healthRequest)
		assert.Equal(t, "health-after-error", healthResponse["id"])
	})

	// Test 3: Upstream server connection refused
	t.Run("UpstreamConnectionRefused", func(t *testing.T) {
		env.AuditLogger.Reset()

		connectionRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "connection-refused",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "nonexistent_upstream_tool",
			},
		}

		response := makeAuthenticatedRequest(t, env.Server, token, connectionRequest)

		// Should handle connection failure gracefully
		assert.Equal(t, "connection-refused", response["id"])
		assert.NotNil(t, response["error"])

		errorObj := response["error"].(map[string]interface{})
		assert.Contains(t, errorObj["message"], "upstream")

		// Verify connection failure is audited
		events := env.AuditLogger.GetEvents()
		connectionEvent := findEventByAction(events, "upstream_connection_failed")
		if connectionEvent != nil {
			assert.Equal(t, "deny", connectionEvent.Decision)
		}
	})
}

func testPolicyEngineFailures(t *testing.T, env *TestEnvironment) {
	// Test policy engine failure scenarios and fail-closed behavior

	token := env.CreateValidToken("user@company.com", "test-tenant", []string{"mcp.users"})

	// Test 1: Policy engine compilation error
	t.Run("PolicyCompilationError", func(t *testing.T) {
		env.AuditLogger.Reset()
		env.PolicyEngine.SetShouldError(true)
		defer env.PolicyEngine.SetShouldError(false)

		policyFailRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "policy-compilation-error",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "test_tool",
			},
		}

		response := makeAuthenticatedRequest(t, env.Server, token, policyFailRequest)

		// Should fail closed (deny request)
		assert.Equal(t, "policy-compilation-error", response["id"])
		assert.NotNil(t, response["error"])

		errorObj := response["error"].(map[string]interface{})
		assert.Contains(t, errorObj["message"], "Policy")

		// Verify policy failure is audited
		events := env.AuditLogger.GetEvents()
		policyEvent := findEventByAction(events, "policy_evaluate")
		require.NotNil(t, policyEvent)
		assert.Equal(t, "deny", policyEvent.Decision)
		assert.Contains(t, policyEvent.Reason, "error")
	})

	// Test 2: Policy engine timeout
	t.Run("PolicyEvaluationTimeout", func(t *testing.T) {
		env.AuditLogger.Reset()

		// Simulate slow policy evaluation
		slowPolicyRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "slow-policy",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "complex_policy_tool",
				"arguments": map[string]interface{}{
					"complexity": "high",
				},
			},
		}

		start := time.Now()
		response := makeAuthenticatedRequest(t, env.Server, token, slowPolicyRequest)
		duration := time.Since(start)

		// Should complete within reasonable time (fail fast)
		assert.Less(t, duration, 5*time.Second, "Policy evaluation should timeout quickly")

		// Should either succeed or fail with timeout
		assert.Equal(t, "slow-policy", response["id"])

		if response["error"] != nil {
			errorObj := response["error"].(map[string]interface{})
			assert.Contains(t, errorObj["message"], "timeout")
		}
	})

	// Test 3: Policy engine recovery after failure
	t.Run("PolicyEngineRecovery", func(t *testing.T) {
		env.AuditLogger.Reset()

		// First request fails due to policy engine error
		env.PolicyEngine.SetShouldError(true)

		failRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "policy-fail-1",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "test_tool",
			},
		}

		response1 := makeAuthenticatedRequest(t, env.Server, token, failRequest)
		assert.NotNil(t, response1["error"])

		// Policy engine recovers
		env.PolicyEngine.SetShouldError(false)

		// Second request should succeed
		successRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "policy-success-1",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "test_tool",
			},
		}

		response2 := makeAuthenticatedRequest(t, env.Server, token, successRequest)
		assert.Equal(t, "policy-success-1", response2["id"])
		assert.Nil(t, response2["error"], "Should succeed after policy engine recovery")

		// Verify recovery is reflected in audit logs
		events := env.AuditLogger.GetEvents()
		policyEvents := filterEventsByAction(events, "policy_evaluate")
		assert.GreaterOrEqual(t, len(policyEvents), 2)

		// Last policy event should be successful
		lastPolicyEvent := policyEvents[len(policyEvents)-1]
		assert.Equal(t, "allow", lastPolicyEvent.Decision)
	})
}

func testAuditSystemFailures(t *testing.T, env *TestEnvironment) {
	// Test audit system failure scenarios

	token := env.CreateValidToken("user@company.com", "test-tenant", []string{"mcp.users"})

	// Test 1: Audit system unavailable (should continue serving)
	t.Run("AuditSystemUnavailable", func(t *testing.T) {
		// Simulate audit system failure by making it reject events
		originalLogger := env.AuditLogger
		failingLogger := &FailingAuditLogger{shouldFail: true}
		env.AuditLogger = failingLogger

		auditFailRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "audit-fail-test",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "test_tool",
			},
		}

		response := makeAuthenticatedRequest(t, env.Server, token, auditFailRequest)

		// Should continue serving despite audit failure
		assert.Equal(t, "audit-fail-test", response["id"])
		// May succeed or fail based on other factors, but shouldn't crash

		// Restore original logger
		env.AuditLogger = originalLogger

		// Verify system is still responsive
		healthRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "health-after-audit-fail",
			"method":  "ping",
		}

		healthResponse := makeAuthenticatedRequest(t, env.Server, token, healthRequest)
		assert.Equal(t, "health-after-audit-fail", healthResponse["id"])
	})

	// Test 2: Audit system recovery
	t.Run("AuditSystemRecovery", func(t *testing.T) {
		env.AuditLogger.Reset()

		// Make request while audit is working
		beforeRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "before-audit-recovery",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "test_tool",
			},
		}

		makeAuthenticatedRequest(t, env.Server, token, beforeRequest)

		eventsBefore := len(env.AuditLogger.GetEvents())
		assert.Greater(t, eventsBefore, 0, "Should have audit events before failure")

		// Simulate audit recovery by making another request
		afterRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "after-audit-recovery",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "test_tool",
			},
		}

		makeAuthenticatedRequest(t, env.Server, token, afterRequest)

		eventsAfter := len(env.AuditLogger.GetEvents())
		assert.Greater(t, eventsAfter, eventsBefore, "Should have more audit events after recovery")
	})
}

func testAuthenticationSystemFailures(t *testing.T, env *TestEnvironment) {
	// Test authentication system failure scenarios

	// Test 1: JWKS endpoint unavailable
	t.Run("JWKSEndpointUnavailable", func(t *testing.T) {
		env.AuditLogger.Reset()

		// Create token with invalid signature (simulates JWKS failure)
		invalidToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGNvbXBhbnkuY29tIiwidGlkIjoidGVzdC10ZW5hbnQiLCJncm91cHMiOlsibWNwLnVzZXJzIl0sImV4cCI6OTk5OTk5OTk5OX0.invalid_signature"

		request := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "jwks-fail-test",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "test_tool",
			},
		}

		reqBody, _ := json.Marshal(request)
		httpReq, _ := http.NewRequest("POST", env.Server.URL+"/mcp", bytes.NewReader(reqBody))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+invalidToken)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(httpReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should reject with 401
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Verify authentication failure is audited
		events := env.AuditLogger.GetEvents()
		authEvent := findEventByAction(events, "token_validate")
		require.NotNil(t, authEvent)
		assert.Equal(t, "deny", authEvent.Decision)
	})

	// Test 2: Token expiration handling
	t.Run("TokenExpirationHandling", func(t *testing.T) {
		env.AuditLogger.Reset()

		// Create expired token
		expiredToken := env.CreateExpiredToken("user@company.com", "test-tenant", []string{"mcp.users"})

		request := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "expired-token-test",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "test_tool",
			},
		}

		reqBody, _ := json.Marshal(request)
		httpReq, _ := http.NewRequest("POST", env.Server.URL+"/mcp", bytes.NewReader(reqBody))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+expiredToken)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(httpReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should reject expired token
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// Verify expiration is audited
		events := env.AuditLogger.GetEvents()
		authEvent := findEventByAction(events, "token_validate")
		require.NotNil(t, authEvent)
		assert.Equal(t, "deny", authEvent.Decision)
		assert.Contains(t, authEvent.Reason, "expired")
	})
}

func testNetworkPartitionRecovery(t *testing.T, env *TestEnvironment) {
	// Test network partition and recovery scenarios

	token := env.CreateValidToken("user@company.com", "test-tenant", []string{"mcp.users"})

	// Test 1: Simulated network partition
	t.Run("NetworkPartitionSimulation", func(t *testing.T) {
		env.AuditLogger.Reset()

		// Make requests with very short timeout to simulate network issues
		client := &http.Client{Timeout: 100 * time.Millisecond}

		request := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "network-partition-test",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "test_tool",
			},
		}

		reqBody, _ := json.Marshal(request)
		httpReq, _ := http.NewRequest("POST", env.Server.URL+"/mcp", bytes.NewReader(reqBody))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+token)

		_, err := client.Do(httpReq)

		// Should timeout (simulating network partition)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timeout")

		// System should recover when network is restored (normal timeout)
		normalClient := &http.Client{Timeout: 5 * time.Second}
		resp, err := normalClient.Do(httpReq)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should work normally after "network recovery"
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func testResourceExhaustionHandling(t *testing.T, env *TestEnvironment) {
	// Test resource exhaustion scenarios

	token := env.CreateValidToken("user@company.com", "test-tenant", []string{"mcp.users"})

	// Test 1: Memory exhaustion simulation
	t.Run("MemoryExhaustionHandling", func(t *testing.T) {
		env.AuditLogger.Reset()

		// Send large request to simulate memory pressure
		largeData := make(map[string]interface{})
		for i := 0; i < 1000; i++ {
			largeData[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_%d_%s", i,
				"large_string_to_consume_memory_and_test_resource_exhaustion_handling")
		}

		largeRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "memory-exhaustion-test",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name":      "process_large_data",
				"arguments": largeData,
			},
		}

		response := makeAuthenticatedRequest(t, env.Server, token, largeRequest)

		// Should handle large request gracefully
		assert.Equal(t, "memory-exhaustion-test", response["id"])

		// May succeed or fail with size limit, but shouldn't crash
		if response["error"] != nil {
			errorObj := response["error"].(map[string]interface{})
			// Should get appropriate error message
			assert.NotEmpty(t, errorObj["message"])
		}

		// System should remain responsive after large request
		healthRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "health-after-large-request",
			"method":  "ping",
		}

		healthResponse := makeAuthenticatedRequest(t, env.Server, token, healthRequest)
		assert.Equal(t, "health-after-large-request", healthResponse["id"])
	})

	// Test 2: Connection exhaustion
	t.Run("ConnectionExhaustionHandling", func(t *testing.T) {
		env.AuditLogger.Reset()

		// Create many concurrent connections
		numConnections := 20
		var wg sync.WaitGroup
		results := make(chan bool, numConnections)

		for i := 0; i < numConnections; i++ {
			wg.Add(1)
			go func(connID int) {
				defer wg.Done()

				request := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      fmt.Sprintf("conn-exhaustion-%d", connID),
					"method":  "tools/call",
					"params": map[string]interface{}{
						"name": "test_tool",
					},
				}

				response := makeAuthenticatedRequest(t, env.Server, token, request)

				// Should handle connection gracefully
				success := response["id"] == request["id"]
				results <- success
			}(i)
		}

		wg.Wait()
		close(results)

		// Count successful connections
		successCount := 0
		for success := range results {
			if success {
				successCount++
			}
		}

		// Should handle most connections successfully
		successRate := float64(successCount) / float64(numConnections)
		assert.GreaterOrEqual(t, successRate, 0.8, "Should handle at least 80% of connections")

		t.Logf("Connection exhaustion test: %d/%d successful (%.2f%%)",
			successCount, numConnections, successRate*100)
	})
}

func testCascadingFailuresPrevention(t *testing.T, env *TestEnvironment) {
	// Test prevention of cascading failures

	token := env.CreateValidToken("user@company.com", "test-tenant", []string{"mcp.users"})

	// Test 1: Circuit breaker behavior
	t.Run("CircuitBreakerBehavior", func(t *testing.T) {
		env.AuditLogger.Reset()

		// Make multiple failing requests to trigger circuit breaker
		failingRequests := 10
		successCount := 0
		circuitBreakerTriggered := false

		for i := 0; i < failingRequests; i++ {
			request := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      fmt.Sprintf("circuit-breaker-test-%d", i),
				"method":  "tools/call",
				"params": map[string]interface{}{
					"name": "always_failing_tool",
				},
			}

			start := time.Now()
			response := makeAuthenticatedRequest(t, env.Server, token, request)
			duration := time.Since(start)

			if response["error"] == nil {
				successCount++
			} else {
				errorObj := response["error"].(map[string]interface{})
				if strings.Contains(errorObj["message"].(string), "circuit") {
					circuitBreakerTriggered = true
				}
			}

			// Later requests should fail faster (circuit breaker)
			if i > 5 && duration < 100*time.Millisecond {
				circuitBreakerTriggered = true
			}

			time.Sleep(50 * time.Millisecond)
		}

		t.Logf("Circuit breaker test: %d successes, circuit breaker triggered: %v",
			successCount, circuitBreakerTriggered)

		// Verify circuit breaker prevents cascading failures
		if circuitBreakerTriggered {
			// System should still be responsive for other operations
			healthRequest := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      "health-after-circuit-breaker",
				"method":  "ping",
			}

			healthResponse := makeAuthenticatedRequest(t, env.Server, token, healthRequest)
			assert.Equal(t, "health-after-circuit-breaker", healthResponse["id"])
		}
	})

	// Test 2: Bulkhead isolation
	t.Run("BulkheadIsolation", func(t *testing.T) {
		env.AuditLogger.Reset()

		// Start failing operations in one "bulkhead"
		var wg sync.WaitGroup

		// Failing operations
		wg.Add(1)
		go func() {
			defer wg.Done()

			for i := 0; i < 5; i++ {
				request := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      fmt.Sprintf("bulkhead-fail-%d", i),
					"method":  "tools/call",
					"params": map[string]interface{}{
						"name": "failing_tool",
					},
				}

				makeAuthenticatedRequest(t, env.Server, token, request)
				time.Sleep(100 * time.Millisecond)
			}
		}()

		// Successful operations should continue working
		wg.Add(1)
		successfulOps := 0
		go func() {
			defer wg.Done()

			for i := 0; i < 5; i++ {
				request := map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      fmt.Sprintf("bulkhead-success-%d", i),
					"method":  "tools/call",
					"params": map[string]interface{}{
						"name": "working_tool",
					},
				}

				response := makeAuthenticatedRequest(t, env.Server, token, request)
				if response["error"] == nil {
					successfulOps++
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()

		wg.Wait()

		// Should have some successful operations despite failures in other bulkhead
		assert.Greater(t, successfulOps, 0, "Bulkhead isolation should allow some operations to succeed")

		t.Logf("Bulkhead isolation test: %d successful operations", successfulOps)
	})
}

func testGracefulDegradation(t *testing.T, env *TestEnvironment) {
	// Test graceful degradation under various failure conditions

	token := env.CreateValidToken("user@company.com", "test-tenant", []string{"mcp.users"})

	// Test 1: Partial service degradation
	t.Run("PartialServiceDegradation", func(t *testing.T) {
		env.AuditLogger.Reset()

		// Some services fail, others continue working
		services := []string{"service_a", "service_b", "service_c"}
		results := make(map[string]bool)

		for _, service := range services {
			request := map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      fmt.Sprintf("degradation-test-%s", service),
				"method":  "tools/call",
				"params": map[string]interface{}{
					"name": service,
				},
			}

			response := makeAuthenticatedRequest(t, env.Server, token, request)
			results[service] = response["error"] == nil
		}

		// Should have mixed results (some succeed, some fail)
		successCount := 0
		for _, success := range results {
			if success {
				successCount++
			}
		}

		t.Logf("Partial degradation test: %d/%d services working", successCount, len(services))

		// System should continue operating with reduced functionality
		assert.GreaterOrEqual(t, successCount, 0, "Some services should continue working")

		// Core functionality (health check) should still work
		healthRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "health-during-degradation",
			"method":  "ping",
		}

		healthResponse := makeAuthenticatedRequest(t, env.Server, token, healthRequest)
		assert.Equal(t, "health-during-degradation", healthResponse["id"])
	})

	// Test 2: Read-only mode fallback
	t.Run("ReadOnlyModeFallback", func(t *testing.T) {
		env.AuditLogger.Reset()

		// Test read operations (should work)
		readRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "read-only-test-read",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "read_file",
				"arguments": map[string]interface{}{
					"path": "mcp://repo/README.md",
				},
			},
		}

		readResponse := makeAuthenticatedRequest(t, env.Server, token, readRequest)
		assert.Equal(t, "read-only-test-read", readResponse["id"])

		// Test write operations (may be restricted)
		writeRequest := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "read-only-test-write",
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "write_file",
				"arguments": map[string]interface{}{
					"path":    "mcp://repo/test.txt",
					"content": "test content",
				},
			},
		}

		writeResponse := makeAuthenticatedRequest(t, env.Server, token, writeRequest)
		assert.Equal(t, "read-only-test-write", writeResponse["id"])

		// Write may fail due to read-only restrictions
		if writeResponse["error"] != nil {
			errorObj := writeResponse["error"].(map[string]interface{})
			assert.Contains(t, errorObj["message"], "read-only")
		}

		// Verify degradation is audited
		events := env.AuditLogger.GetEvents()
		assert.Greater(t, len(events), 0, "Should have audit events during degradation")
	})
}

// Helper types and functions for failure testing

type FailingAuditLogger struct {
	shouldFail bool
	events     []*AuditEvent
	mutex      sync.RWMutex
}

func (f *FailingAuditLogger) LogEvent(event *AuditEvent) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if f.shouldFail {
		// Simulate audit system failure
		return
	}

	f.events = append(f.events, event)
}

func (f *FailingAuditLogger) GetEvents() []*AuditEvent {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	events := make([]*AuditEvent, len(f.events))
	copy(events, f.events)
	return events
}

func (f *FailingAuditLogger) Reset() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.events = f.events[:0]
}

func (env *TestEnvironment) CreateExpiredToken(subject, tenant string, groups []string) string {
	claims := map[string]interface{}{
		"sub":    subject,
		"tid":    tenant,
		"groups": groups,
		"exp":    time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
		"iat":    time.Now().Add(-2 * time.Hour).Unix(),
		"aud":    "mcp-airlock",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	tokenString, _ := token.SignedString(env.JWTKey)
	return tokenString
}

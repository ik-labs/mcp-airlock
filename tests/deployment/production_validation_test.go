package deployment

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestProductionDeploymentValidation validates production deployment
func TestProductionDeploymentValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping production deployment validation in short mode")
	}

	// Check if we're running in production-like environment
	if os.Getenv("PRODUCTION_VALIDATION") != "true" {
		t.Skip("Skipping production validation - set PRODUCTION_VALIDATION=true to run")
	}

	zaptest.NewLogger(t)

	// Get deployment configuration
	config := getDeploymentConfig(t)

	t.Run("KubernetesDeploymentHealth", func(t *testing.T) {
		testKubernetesDeploymentHealth(t, config)
	})

	t.Run("ServiceEndpointValidation", func(t *testing.T) {
		testServiceEndpointValidation(t, config)
	})

	t.Run("TLSConfigurationValidation", func(t *testing.T) {
		testTLSConfigurationValidation(t, config)
	})

	t.Run("SecurityHardeningValidation", func(t *testing.T) {
		testSecurityHardeningValidation(t, config)
	})

	t.Run("MonitoringAndAlerting", func(t *testing.T) {
		testMonitoringAndAlerting(t, config)
	})

	t.Run("BackupAndRecovery", func(t *testing.T) {
		testBackupAndRecovery(t, config)
	})

	t.Run("LoadBalancerConfiguration", func(t *testing.T) {
		testLoadBalancerConfiguration(t, config)
	})

	t.Run("PersistentVolumeValidation", func(t *testing.T) {
		testPersistentVolumeValidation(t, config)
	})

	t.Run("NetworkPolicyValidation", func(t *testing.T) {
		testNetworkPolicyValidation(t, config)
	})

	t.Run("ResourceLimitsValidation", func(t *testing.T) {
		testResourceLimitsValidation(t, config)
	})
}

type DeploymentConfig struct {
	Namespace       string
	ServiceURL      string
	IngressURL      string
	AdminToken      string
	TestToken       string
	KubeConfig      string
	TLSEnabled      bool
	MonitoringURL   string
	AlertManagerURL string
}

func getDeploymentConfig(t *testing.T) *DeploymentConfig {
	config := &DeploymentConfig{
		Namespace:       getEnvOrDefault("AIRLOCK_NAMESPACE", "airlock-system"),
		ServiceURL:      getEnvOrDefault("AIRLOCK_SERVICE_URL", "http://airlock:8080"),
		IngressURL:      getEnvOrDefault("AIRLOCK_INGRESS_URL", "https://airlock.example.com"),
		AdminToken:      os.Getenv("AIRLOCK_ADMIN_TOKEN"),
		TestToken:       os.Getenv("AIRLOCK_TEST_TOKEN"),
		KubeConfig:      getEnvOrDefault("KUBECONFIG", "~/.kube/config"),
		TLSEnabled:      getEnvOrDefault("AIRLOCK_TLS_ENABLED", "true") == "true",
		MonitoringURL:   getEnvOrDefault("PROMETHEUS_URL", "http://prometheus:9090"),
		AlertManagerURL: getEnvOrDefault("ALERTMANAGER_URL", "http://alertmanager:9093"),
	}

	if config.AdminToken == "" {
		t.Skip("AIRLOCK_ADMIN_TOKEN not provided, skipping production validation")
	}

	if config.TestToken == "" {
		t.Skip("AIRLOCK_TEST_TOKEN not provided, skipping production validation")
	}

	return config
}

func testKubernetesDeploymentHealth(t *testing.T, config *DeploymentConfig) {
	// Test 1: Pod status
	t.Run("PodStatus", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "pods",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		require.NoError(t, err, "Failed to get pod status")

		var podList map[string]interface{}
		err = json.Unmarshal(output, &podList)
		require.NoError(t, err)

		items, ok := podList["items"].([]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, items, "Should have at least one Airlock pod")

		// Check that all pods are running and ready
		for i, item := range items {
			pod := item.(map[string]interface{})
			metadata := pod["metadata"].(map[string]interface{})
			podName := metadata["name"].(string)

			status := pod["status"].(map[string]interface{})
			phase := status["phase"].(string)
			assert.Equal(t, "Running", phase, "Pod %s should be in Running state", podName)

			// Check readiness
			if conditions, ok := status["conditions"].([]interface{}); ok {
				readyCondition := findCondition(conditions, "Ready")
				if readyCondition != nil {
					assert.Equal(t, "True", readyCondition["status"],
						"Pod %s should be ready", podName)
				}
			}

			t.Logf("Pod %d: %s - %s", i+1, podName, phase)
		}
	})

	// Test 2: Service status
	t.Run("ServiceStatus", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "service",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		require.NoError(t, err, "Failed to get service status")

		var serviceList map[string]interface{}
		err = json.Unmarshal(output, &serviceList)
		require.NoError(t, err)

		items, ok := serviceList["items"].([]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, items, "Should have at least one Airlock service")

		for _, item := range items {
			service := item.(map[string]interface{})
			metadata := service["metadata"].(map[string]interface{})
			serviceName := metadata["name"].(string)

			spec := service["spec"].(map[string]interface{})
			ports := spec["ports"].([]interface{})
			assert.NotEmpty(t, ports, "Service %s should have ports defined", serviceName)

			t.Logf("Service: %s with %d ports", serviceName, len(ports))
		}
	})

	// Test 3: Deployment status
	t.Run("DeploymentStatus", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "deployment",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		require.NoError(t, err, "Failed to get deployment status")

		var deploymentList map[string]interface{}
		err = json.Unmarshal(output, &deploymentList)
		require.NoError(t, err)

		items, ok := deploymentList["items"].([]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, items, "Should have at least one Airlock deployment")

		for _, item := range items {
			deployment := item.(map[string]interface{})
			metadata := deployment["metadata"].(map[string]interface{})
			deploymentName := metadata["name"].(string)

			status := deployment["status"].(map[string]interface{})
			replicas := int(status["replicas"].(float64))
			readyReplicas := int(status["readyReplicas"].(float64))

			assert.Equal(t, replicas, readyReplicas,
				"Deployment %s should have all replicas ready", deploymentName)

			t.Logf("Deployment: %s - %d/%d replicas ready",
				deploymentName, readyReplicas, replicas)
		}
	})
}

func testServiceEndpointValidation(t *testing.T, config *DeploymentConfig) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !config.TLSEnabled, // Only for testing
			},
		},
	}

	// Test 1: Health endpoints
	t.Run("HealthEndpoints", func(t *testing.T) {
		endpoints := []struct {
			name string
			path string
		}{
			{"Liveness", "/live"},
			{"Readiness", "/ready"},
			{"Info", "/info"},
		}

		for _, endpoint := range endpoints {
			t.Run(endpoint.name, func(t *testing.T) {
				url := config.IngressURL + endpoint.path
				resp, err := client.Get(url)
				require.NoError(t, err, "Failed to reach %s endpoint", endpoint.name)
				defer resp.Body.Close()

				assert.Equal(t, http.StatusOK, resp.StatusCode,
					"%s endpoint should return 200", endpoint.name)

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)

				if endpoint.name == "Info" {
					var info map[string]interface{}
					err = json.Unmarshal(body, &info)
					require.NoError(t, err)
					assert.Contains(t, info, "version")
					assert.Contains(t, info, "build_time")
				}

				t.Logf("%s endpoint: %s - Status: %d",
					endpoint.name, url, resp.StatusCode)
			})
		}
	})

	// Test 2: MCP endpoint authentication
	t.Run("MCPEndpointAuthentication", func(t *testing.T) {
		// Test unauthenticated request
		mcpURL := config.IngressURL + "/mcp"

		req, err := http.NewRequest("POST", mcpURL, strings.NewReader("{}"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"Unauthenticated MCP request should return 401")
		assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Bearer")

		// Test authenticated request
		req.Header.Set("Authorization", "Bearer "+config.TestToken)

		resp, err = client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode,
			"Authenticated MCP request should not return 401")

		t.Logf("MCP endpoint authentication: Unauthenticated=401, Authenticated=%d",
			resp.StatusCode)
	})

	// Test 3: Metrics endpoint
	t.Run("MetricsEndpoint", func(t *testing.T) {
		metricsURL := config.IngressURL + "/metrics"

		resp, err := client.Get(metricsURL)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"Metrics endpoint should return 200")

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		metricsContent := string(body)
		assert.Contains(t, metricsContent, "airlock_requests_total")
		assert.Contains(t, metricsContent, "airlock_request_duration_seconds")

		t.Logf("Metrics endpoint: %s - %d bytes of metrics",
			metricsURL, len(body))
	})
}

func testTLSConfigurationValidation(t *testing.T, config *DeploymentConfig) {
	if !config.TLSEnabled {
		t.Skip("TLS not enabled, skipping TLS validation")
	}

	// Test 1: TLS certificate validation
	t.Run("TLSCertificateValidation", func(t *testing.T) {
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false, // Validate certificates
				},
			},
		}

		resp, err := client.Get(config.IngressURL + "/live")
		require.NoError(t, err, "TLS certificate should be valid")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		t.Logf("TLS certificate validation: PASS")
	})

	// Test 2: TLS version and cipher validation
	t.Run("TLSVersionAndCiphers", func(t *testing.T) {
		conn, err := tls.Dial("tcp", extractHostPort(config.IngressURL), &tls.Config{
			InsecureSkipVerify: false,
		})
		require.NoError(t, err, "Should be able to establish TLS connection")
		defer conn.Close()

		state := conn.ConnectionState()

		// Verify TLS version
		assert.GreaterOrEqual(t, state.Version, uint16(tls.VersionTLS12),
			"Should use TLS 1.2 or higher")

		// Verify cipher suite
		assert.NotEqual(t, uint16(0), state.CipherSuite,
			"Should have a valid cipher suite")

		t.Logf("TLS Version: %x, Cipher Suite: %x",
			state.Version, state.CipherSuite)
	})

	// Test 3: HTTP to HTTPS redirect
	t.Run("HTTPSRedirect", func(t *testing.T) {
		httpURL := strings.Replace(config.IngressURL, "https://", "http://", 1)

		client := &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}

		resp, err := client.Get(httpURL + "/live")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should redirect to HTTPS
		assert.True(t, resp.StatusCode >= 300 && resp.StatusCode < 400,
			"HTTP should redirect to HTTPS")

		location := resp.Header.Get("Location")
		assert.True(t, strings.HasPrefix(location, "https://"),
			"Should redirect to HTTPS URL")

		t.Logf("HTTP to HTTPS redirect: %d -> %s", resp.StatusCode, location)
	})
}

func testSecurityHardeningValidation(t *testing.T, config *DeploymentConfig) {
	// Test 1: Security headers
	t.Run("SecurityHeaders", func(t *testing.T) {
		client := &http.Client{Timeout: 10 * time.Second}

		resp, err := client.Get(config.IngressURL + "/live")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check security headers
		securityHeaders := map[string]string{
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "DENY",
			"X-XSS-Protection":          "1; mode=block",
			"Strict-Transport-Security": "max-age=",
		}

		for header, expectedValue := range securityHeaders {
			actualValue := resp.Header.Get(header)
			if expectedValue == "" {
				assert.NotEmpty(t, actualValue, "Header %s should be present", header)
			} else {
				assert.Contains(t, actualValue, expectedValue,
					"Header %s should contain %s", header, expectedValue)
			}
		}

		t.Logf("Security headers validation: PASS")
	})

	// Test 2: Pod security context
	t.Run("PodSecurityContext", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "pods",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		require.NoError(t, err)

		var podList map[string]interface{}
		err = json.Unmarshal(output, &podList)
		require.NoError(t, err)

		items := podList["items"].([]interface{})
		require.NotEmpty(t, items)

		for _, item := range items {
			pod := item.(map[string]interface{})
			spec := pod["spec"].(map[string]interface{})

			// Check security context
			if securityContext, ok := spec["securityContext"].(map[string]interface{}); ok {
				// Should run as non-root
				if runAsNonRoot, ok := securityContext["runAsNonRoot"].(bool); ok {
					assert.True(t, runAsNonRoot, "Pod should run as non-root")
				}

				// Should have read-only root filesystem
				containers := spec["containers"].([]interface{})
				for _, container := range containers {
					cont := container.(map[string]interface{})
					if contSecCtx, ok := cont["securityContext"].(map[string]interface{}); ok {
						if readOnlyRootFS, ok := contSecCtx["readOnlyRootFilesystem"].(bool); ok {
							assert.True(t, readOnlyRootFS,
								"Container should have read-only root filesystem")
						}
					}
				}
			}
		}

		t.Logf("Pod security context validation: PASS")
	})

	// Test 3: Network policies
	t.Run("NetworkPolicies", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "networkpolicy",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		if err != nil {
			t.Skip("NetworkPolicy not available or accessible")
			return
		}

		var networkPolicyList map[string]interface{}
		err = json.Unmarshal(output, &networkPolicyList)
		require.NoError(t, err)

		items := networkPolicyList["items"].([]interface{})
		assert.NotEmpty(t, items, "Should have network policies defined")

		t.Logf("Network policies validation: %d policies found", len(items))
	})
}

func testMonitoringAndAlerting(t *testing.T, config *DeploymentConfig) {
	// Test 1: Prometheus metrics collection
	t.Run("PrometheusMetrics", func(t *testing.T) {
		if config.MonitoringURL == "" {
			t.Skip("Monitoring URL not configured")
		}

		client := &http.Client{Timeout: 10 * time.Second}

		// Query Airlock metrics
		queryURL := fmt.Sprintf("%s/api/v1/query?query=airlock_requests_total",
			config.MonitoringURL)

		resp, err := client.Get(queryURL)
		require.NoError(t, err, "Should be able to query Prometheus")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)

		assert.Equal(t, "success", result["status"])

		data := result["data"].(map[string]interface{})
		resultData := data["result"].([]interface{})

		t.Logf("Prometheus metrics: Found %d metric series", len(resultData))
	})

	// Test 2: Alert manager configuration
	t.Run("AlertManagerConfiguration", func(t *testing.T) {
		if config.AlertManagerURL == "" {
			t.Skip("AlertManager URL not configured")
		}

		client := &http.Client{Timeout: 10 * time.Second}

		resp, err := client.Get(config.AlertManagerURL + "/api/v1/status")
		require.NoError(t, err, "Should be able to reach AlertManager")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var status map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&status)
		require.NoError(t, err)

		assert.Equal(t, "success", status["status"])

		t.Logf("AlertManager status: %s", status["status"])
	})

	// Test 3: Service monitor configuration
	t.Run("ServiceMonitorConfiguration", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "servicemonitor",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		if err != nil {
			t.Skip("ServiceMonitor CRD not available")
			return
		}

		var serviceMonitorList map[string]interface{}
		err = json.Unmarshal(output, &serviceMonitorList)
		require.NoError(t, err)

		items := serviceMonitorList["items"].([]interface{})
		assert.NotEmpty(t, items, "Should have ServiceMonitor configured")

		t.Logf("ServiceMonitor configuration: %d monitors found", len(items))
	})
}

func testBackupAndRecovery(t *testing.T, config *DeploymentConfig) {
	// Test 1: Persistent volume backup
	t.Run("PersistentVolumeBackup", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "pvc",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		require.NoError(t, err)

		var pvcList map[string]interface{}
		err = json.Unmarshal(output, &pvcList)
		require.NoError(t, err)

		items := pvcList["items"].([]interface{})
		assert.NotEmpty(t, items, "Should have persistent volumes for backup")

		for _, item := range items {
			pvc := item.(map[string]interface{})
			metadata := pvc["metadata"].(map[string]interface{})
			pvcName := metadata["name"].(string)

			status := pvc["status"].(map[string]interface{})
			phase := status["phase"].(string)

			assert.Equal(t, "Bound", phase, "PVC %s should be bound", pvcName)
		}

		t.Logf("Persistent volume backup: %d PVCs validated", len(items))
	})

	// Test 2: Configuration backup
	t.Run("ConfigurationBackup", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "configmap",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		require.NoError(t, err)

		var configMapList map[string]interface{}
		err = json.Unmarshal(output, &configMapList)
		require.NoError(t, err)

		items := configMapList["items"].([]interface{})
		assert.NotEmpty(t, items, "Should have configuration maps")

		t.Logf("Configuration backup: %d ConfigMaps found", len(items))
	})

	// Test 3: Secret backup validation
	t.Run("SecretBackupValidation", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "secret",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		require.NoError(t, err)

		var secretList map[string]interface{}
		err = json.Unmarshal(output, &secretList)
		require.NoError(t, err)

		items := secretList["items"].([]interface{})
		assert.NotEmpty(t, items, "Should have secrets for backup")

		t.Logf("Secret backup validation: %d secrets found", len(items))
	})
}

func testLoadBalancerConfiguration(t *testing.T, config *DeploymentConfig) {
	// Test 1: Ingress configuration
	t.Run("IngressConfiguration", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "ingress",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		require.NoError(t, err)

		var ingressList map[string]interface{}
		err = json.Unmarshal(output, &ingressList)
		require.NoError(t, err)

		items := ingressList["items"].([]interface{})
		assert.NotEmpty(t, items, "Should have ingress configured")

		for _, item := range items {
			ingress := item.(map[string]interface{})
			spec := ingress["spec"].(map[string]interface{})

			// Check TLS configuration
			if tls, ok := spec["tls"].([]interface{}); ok && config.TLSEnabled {
				assert.NotEmpty(t, tls, "Should have TLS configuration")
			}

			// Check rules
			rules := spec["rules"].([]interface{})
			assert.NotEmpty(t, rules, "Should have ingress rules")
		}

		t.Logf("Ingress configuration: %d ingresses validated", len(items))
	})

	// Test 2: Service load balancer
	t.Run("ServiceLoadBalancer", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "service",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		require.NoError(t, err)

		var serviceList map[string]interface{}
		err = json.Unmarshal(output, &serviceList)
		require.NoError(t, err)

		items := serviceList["items"].([]interface{})
		require.NotEmpty(t, items)

		for _, item := range items {
			service := item.(map[string]interface{})
			spec := service["spec"].(map[string]interface{})

			serviceType := spec["type"].(string)
			if serviceType == "LoadBalancer" {
				status := service["status"].(map[string]interface{})
				if loadBalancer, ok := status["loadBalancer"].(map[string]interface{}); ok {
					if ingress, ok := loadBalancer["ingress"].([]interface{}); ok {
						assert.NotEmpty(t, ingress, "LoadBalancer should have ingress")
					}
				}
			}
		}

		t.Logf("Service load balancer: %d services validated", len(items))
	})
}

func testPersistentVolumeValidation(t *testing.T, config *DeploymentConfig) {
	// Test 1: PVC status and capacity
	t.Run("PVCStatusAndCapacity", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "pvc",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		require.NoError(t, err)

		var pvcList map[string]interface{}
		err = json.Unmarshal(output, &pvcList)
		require.NoError(t, err)

		items := pvcList["items"].([]interface{})
		assert.NotEmpty(t, items, "Should have persistent volume claims")

		for _, item := range items {
			pvc := item.(map[string]interface{})
			metadata := pvc["metadata"].(map[string]interface{})
			pvcName := metadata["name"].(string)

			status := pvc["status"].(map[string]interface{})
			phase := status["phase"].(string)

			assert.Equal(t, "Bound", phase, "PVC %s should be bound", pvcName)

			// Check capacity
			if capacity, ok := status["capacity"].(map[string]interface{}); ok {
				storage := capacity["storage"].(string)
				assert.NotEmpty(t, storage, "PVC %s should have storage capacity", pvcName)
				t.Logf("PVC %s: %s storage", pvcName, storage)
			}
		}
	})

	// Test 2: Storage class validation
	t.Run("StorageClassValidation", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "storageclass", "-o", "json")

		output, err := cmd.Output()
		require.NoError(t, err)

		var storageClassList map[string]interface{}
		err = json.Unmarshal(output, &storageClassList)
		require.NoError(t, err)

		items := storageClassList["items"].([]interface{})
		assert.NotEmpty(t, items, "Should have storage classes available")

		t.Logf("Storage class validation: %d storage classes available", len(items))
	})
}

func testNetworkPolicyValidation(t *testing.T, config *DeploymentConfig) {
	// Test 1: Network policy existence
	t.Run("NetworkPolicyExistence", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "networkpolicy",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		if err != nil {
			t.Skip("NetworkPolicy not supported in this cluster")
			return
		}

		var networkPolicyList map[string]interface{}
		err = json.Unmarshal(output, &networkPolicyList)
		require.NoError(t, err)

		items := networkPolicyList["items"].([]interface{})
		assert.NotEmpty(t, items, "Should have network policies for security")

		for _, item := range items {
			policy := item.(map[string]interface{})
			metadata := policy["metadata"].(map[string]interface{})
			policyName := metadata["name"].(string)

			spec := policy["spec"].(map[string]interface{})

			// Should have pod selector
			assert.Contains(t, spec, "podSelector",
				"Network policy %s should have pod selector", policyName)

			t.Logf("Network policy: %s", policyName)
		}
	})

	// Test 2: Ingress and egress rules
	t.Run("IngressEgressRules", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "networkpolicy",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		if err != nil {
			t.Skip("Airlock-specific NetworkPolicy not found")
			return
		}

		var networkPolicyList map[string]interface{}
		err = json.Unmarshal(output, &networkPolicyList)
		require.NoError(t, err)

		items := networkPolicyList["items"].([]interface{})
		if len(items) == 0 {
			t.Skip("No Airlock-specific network policies found")
			return
		}

		for _, item := range items {
			policy := item.(map[string]interface{})
			spec := policy["spec"].(map[string]interface{})

			// Check for ingress rules
			if ingress, ok := spec["ingress"].([]interface{}); ok {
				assert.NotEmpty(t, ingress, "Should have ingress rules defined")
			}

			// Check for egress rules
			if egress, ok := spec["egress"].([]interface{}); ok {
				assert.NotEmpty(t, egress, "Should have egress rules defined")
			}
		}

		t.Logf("Ingress/Egress rules: %d policies validated", len(items))
	})
}

func testResourceLimitsValidation(t *testing.T, config *DeploymentConfig) {
	// Test 1: Pod resource limits
	t.Run("PodResourceLimits", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "pods",
			"-l", "app.kubernetes.io/name=airlock",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		require.NoError(t, err)

		var podList map[string]interface{}
		err = json.Unmarshal(output, &podList)
		require.NoError(t, err)

		items := podList["items"].([]interface{})
		require.NotEmpty(t, items)

		for _, item := range items {
			pod := item.(map[string]interface{})
			spec := pod["spec"].(map[string]interface{})
			containers := spec["containers"].([]interface{})

			for _, container := range containers {
				cont := container.(map[string]interface{})
				containerName := cont["name"].(string)

				if resources, ok := cont["resources"].(map[string]interface{}); ok {
					// Check limits
					if limits, ok := resources["limits"].(map[string]interface{}); ok {
						assert.Contains(t, limits, "memory",
							"Container %s should have memory limits", containerName)
						assert.Contains(t, limits, "cpu",
							"Container %s should have CPU limits", containerName)
					}

					// Check requests
					if requests, ok := resources["requests"].(map[string]interface{}); ok {
						assert.Contains(t, requests, "memory",
							"Container %s should have memory requests", containerName)
						assert.Contains(t, requests, "cpu",
							"Container %s should have CPU requests", containerName)
					}
				}
			}
		}

		t.Logf("Pod resource limits: %d pods validated", len(items))
	})

	// Test 2: Resource quotas
	t.Run("ResourceQuotas", func(t *testing.T) {
		cmd := exec.Command("kubectl", "get", "resourcequota",
			"-n", config.Namespace,
			"-o", "json")

		output, err := cmd.Output()
		if err != nil {
			t.Skip("ResourceQuota not configured")
			return
		}

		var quotaList map[string]interface{}
		err = json.Unmarshal(output, &quotaList)
		require.NoError(t, err)

		items := quotaList["items"].([]interface{})
		if len(items) > 0 {
			t.Logf("Resource quotas: %d quotas found", len(items))
		} else {
			t.Log("Resource quotas: No quotas configured")
		}
	})
}

// Helper functions

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func findCondition(conditions []interface{}, conditionType string) map[string]interface{} {
	for _, condition := range conditions {
		cond := condition.(map[string]interface{})
		if cond["type"].(string) == conditionType {
			return cond
		}
	}
	return nil
}

func extractHostPort(url string) string {
	// Simple extraction for testing
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	if strings.Contains(url, ":") {
		return url
	}

	// Default HTTPS port
	return url + ":443"
}

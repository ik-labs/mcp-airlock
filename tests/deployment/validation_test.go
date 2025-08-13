package deployment

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestHelmChartValidation tests that all Helm charts are valid
func TestHelmChartValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Helm chart validation in short mode")
	}

	// Check if helm is available
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("Helm not available, skipping chart validation tests")
	}

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	chartPath := filepath.Join(projectRoot, "helm", "airlock")

	tests := []struct {
		name       string
		valuesFile string
	}{
		{"default", "values.yaml"},
		{"staging", "values-staging.yaml"},
		{"production", "values-production.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			valuesPath := filepath.Join(chartPath, tt.valuesFile)

			// Test helm lint
			cmd := exec.CommandContext(ctx, "helm", "lint", chartPath, "--values", valuesPath)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "Helm lint failed for %s: %s", tt.name, string(output))

			// Test helm template
			cmd = exec.CommandContext(ctx, "helm", "template", "test-"+tt.name, chartPath, "--values", valuesPath)
			output, err = cmd.CombinedOutput()
			require.NoError(t, err, "Helm template failed for %s: %s", tt.name, string(output))

			// Validate that essential resources are present
			manifestStr := string(output)
			assert.Contains(t, manifestStr, "kind: Deployment", "Deployment should be present")
			assert.Contains(t, manifestStr, "kind: Service", "Service should be present")
			assert.Contains(t, manifestStr, "kind: ConfigMap", "ConfigMap should be present")
			assert.Contains(t, manifestStr, "kind: ServiceAccount", "ServiceAccount should be present")
		})
	}
}

// TestDeploymentExamples tests that deployment examples are valid Kubernetes manifests
func TestDeploymentExamples(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping deployment examples validation in short mode")
	}

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	examplesDir := filepath.Join(projectRoot, "deployments", "examples")

	examples := []string{
		"aws-single-vpc.yaml",
		"sidecar-deployment.yaml",
		"http-service-upstream.yaml",
		"efs-s3-integration.yaml",
	}

	for _, example := range examples {
		t.Run(example, func(t *testing.T) {
			examplePath := filepath.Join(examplesDir, example)

			// Check that file exists
			_, err := os.Stat(examplePath)
			require.NoError(t, err, "Example file should exist: %s", examplePath)

			// Read and parse YAML
			content, err := os.ReadFile(examplePath)
			require.NoError(t, err, "Should be able to read example file")

			// Split by document separator and validate each document
			documents := strings.Split(string(content), "---")
			for i, doc := range documents {
				doc = strings.TrimSpace(doc)
				if doc == "" {
					continue
				}

				var manifest map[string]interface{}
				err := yaml.Unmarshal([]byte(doc), &manifest)
				require.NoError(t, err, "Document %d in %s should be valid YAML", i, example)

				// Check for required fields
				if manifest["apiVersion"] != nil && manifest["kind"] != nil {
					assert.NotEmpty(t, manifest["apiVersion"], "apiVersion should not be empty")
					assert.NotEmpty(t, manifest["kind"], "kind should not be empty")

					if metadata, ok := manifest["metadata"].(map[string]interface{}); ok {
						assert.NotEmpty(t, metadata["name"], "metadata.name should not be empty")
					}
				}
			}
		})
	}
}

// TestSecurityPolicies tests that security policies are properly configured
func TestSecurityPolicies(t *testing.T) {
	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	chartPath := filepath.Join(projectRoot, "helm", "airlock")

	tests := []struct {
		name       string
		valuesFile string
	}{
		{"default", "values.yaml"},
		{"staging", "values-staging.yaml"},
		{"production", "values-production.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			valuesPath := filepath.Join(chartPath, tt.valuesFile)

			// Generate manifests
			cmd := exec.CommandContext(ctx, "helm", "template", "test-"+tt.name, chartPath, "--values", valuesPath)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "Failed to generate manifests for %s", tt.name)

			manifestStr := string(output)

			// Test security context
			assert.Contains(t, manifestStr, "runAsNonRoot: true", "Should run as non-root")
			assert.Contains(t, manifestStr, "runAsUser: 1001", "Should specify non-root user")
			assert.Contains(t, manifestStr, "readOnlyRootFilesystem: true", "Should have read-only root filesystem")
			assert.Contains(t, manifestStr, "allowPrivilegeEscalation: false", "Should not allow privilege escalation")

			// Test capabilities
			assert.Contains(t, manifestStr, "drop:\n        - ALL", "Should drop all capabilities")

			// Test seccomp profile
			assert.Contains(t, manifestStr, "seccompProfile:\n        type: RuntimeDefault", "Should use RuntimeDefault seccomp profile")

			// Test network policy (if enabled)
			if strings.Contains(manifestStr, "kind: NetworkPolicy") {
				assert.Contains(t, manifestStr, "policyTypes:", "NetworkPolicy should have policy types")
			}
		})
	}
}

// TestResourceLimits tests that resource limits are properly configured
func TestResourceLimits(t *testing.T) {
	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	chartPath := filepath.Join(projectRoot, "helm", "airlock")

	tests := []struct {
		name       string
		valuesFile string
		minCPU     string
		minMemory  string
	}{
		{"default", "values.yaml", "100m", "128Mi"},
		{"staging", "values-staging.yaml", "200m", "256Mi"},
		{"production", "values-production.yaml", "500m", "512Mi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			valuesPath := filepath.Join(chartPath, tt.valuesFile)

			// Generate manifests
			cmd := exec.CommandContext(ctx, "helm", "template", "test-"+tt.name, chartPath, "--values", valuesPath)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "Failed to generate manifests for %s", tt.name)

			manifestStr := string(output)

			// Test that resource limits and requests are present
			assert.Contains(t, manifestStr, "resources:", "Should have resource configuration")
			assert.Contains(t, manifestStr, "limits:", "Should have resource limits")
			assert.Contains(t, manifestStr, "requests:", "Should have resource requests")

			// Test minimum resource requests
			assert.Contains(t, manifestStr, fmt.Sprintf("cpu: %s", tt.minCPU), "Should have minimum CPU request")
			assert.Contains(t, manifestStr, fmt.Sprintf("memory: %s", tt.minMemory), "Should have minimum memory request")
		})
	}
}

// TestPersistenceConfiguration tests that persistence is properly configured
func TestPersistenceConfiguration(t *testing.T) {
	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	chartPath := filepath.Join(projectRoot, "helm", "airlock")

	tests := []struct {
		name       string
		valuesFile string
		expectPVC  bool
	}{
		{"default", "values.yaml", true},
		{"staging", "values-staging.yaml", true},
		{"production", "values-production.yaml", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			valuesPath := filepath.Join(chartPath, tt.valuesFile)

			// Generate manifests
			cmd := exec.CommandContext(ctx, "helm", "template", "test-"+tt.name, chartPath, "--values", valuesPath)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "Failed to generate manifests for %s", tt.name)

			manifestStr := string(output)

			if tt.expectPVC {
				assert.Contains(t, manifestStr, "kind: PersistentVolumeClaim", "Should have PVC when persistence is enabled")
				assert.Contains(t, manifestStr, "mountPath: /var/lib/airlock", "Should mount data volume")
			}
		})
	}
}

// TestIngressConfiguration tests that ingress is properly configured
func TestIngressConfiguration(t *testing.T) {
	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	chartPath := filepath.Join(projectRoot, "helm", "airlock")

	tests := []struct {
		name          string
		valuesFile    string
		expectIngress bool
		ingressClass  string
	}{
		{"staging", "values-staging.yaml", true, "alb"},
		{"production", "values-production.yaml", true, "alb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			valuesPath := filepath.Join(chartPath, tt.valuesFile)

			// Generate manifests
			cmd := exec.CommandContext(ctx, "helm", "template", "test-"+tt.name, chartPath, "--values", valuesPath)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "Failed to generate manifests for %s", tt.name)

			manifestStr := string(output)

			if tt.expectIngress {
				assert.Contains(t, manifestStr, "kind: Ingress", "Should have Ingress when enabled")
				assert.Contains(t, manifestStr, fmt.Sprintf("ingressClassName: %s", tt.ingressClass), "Should have correct ingress class")
				assert.Contains(t, manifestStr, "alb.ingress.kubernetes.io/", "Should have ALB annotations")
			}
		})
	}
}

// TestAutoscalingConfiguration tests that HPA is properly configured
func TestAutoscalingConfiguration(t *testing.T) {
	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	chartPath := filepath.Join(projectRoot, "helm", "airlock")

	tests := []struct {
		name        string
		valuesFile  string
		expectHPA   bool
		minReplicas int
		maxReplicas int
	}{
		{"staging", "values-staging.yaml", true, 2, 5},
		{"production", "values-production.yaml", true, 3, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			valuesPath := filepath.Join(chartPath, tt.valuesFile)

			// Generate manifests
			cmd := exec.CommandContext(ctx, "helm", "template", "test-"+tt.name, chartPath, "--values", valuesPath)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "Failed to generate manifests for %s", tt.name)

			manifestStr := string(output)

			if tt.expectHPA {
				assert.Contains(t, manifestStr, "kind: HorizontalPodAutoscaler", "Should have HPA when autoscaling is enabled")
				assert.Contains(t, manifestStr, fmt.Sprintf("minReplicas: %d", tt.minReplicas), "Should have correct min replicas")
				assert.Contains(t, manifestStr, fmt.Sprintf("maxReplicas: %d", tt.maxReplicas), "Should have correct max replicas")
			}
		})
	}
}

// getProjectRoot returns the project root directory
func getProjectRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Walk up the directory tree to find go.mod
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd, nil
		}

		parent := filepath.Dir(wd)
		if parent == wd {
			return "", fmt.Errorf("could not find project root (go.mod not found)")
		}
		wd = parent
	}
}

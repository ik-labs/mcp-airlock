package ci

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
)

// TestDockerBuild tests that the Docker image builds successfully
func TestDockerBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker build test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Get the project root directory
	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	// Build the Docker image
	imageName := "mcp-airlock:test"
	cmd := exec.CommandContext(ctx, "docker", "build",
		"-t", imageName,
		"--build-arg", "VERSION=test",
		"--build-arg", "GIT_COMMIT=test-commit",
		"--build-arg", "BUILD_TIME="+time.Now().Format(time.RFC3339),
		projectRoot)

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Docker build failed: %s", string(output))

	// Verify the image was created
	cmd = exec.CommandContext(ctx, "docker", "images", imageName, "--format", "{{.Repository}}:{{.Tag}}")
	output, err = cmd.Output()
	require.NoError(t, err)
	assert.Contains(t, string(output), imageName)

	// Clean up
	defer func() {
		exec.Command("docker", "rmi", imageName).Run()
	}()
}

// TestDockerImageSecurity tests security aspects of the Docker image
func TestDockerImageSecurity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker security test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	imageName := "mcp-airlock:security-test"

	// Build the image first
	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	cmd := exec.CommandContext(ctx, "docker", "build", "-t", imageName, projectRoot)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Docker build failed: %s", string(output))

	defer func() {
		exec.Command("docker", "rmi", imageName).Run()
	}()

	// Test 1: Check that the image runs as non-root
	t.Run("NonRootUser", func(t *testing.T) {
		cmd := exec.CommandContext(ctx, "docker", "run", "--rm", imageName, "id", "-u")
		output, err := cmd.Output()
		require.NoError(t, err)

		userID := strings.TrimSpace(string(output))
		assert.NotEqual(t, "0", userID, "Container should not run as root")
		assert.Equal(t, "1001", userID, "Container should run as user 1001")
	})

	// Test 2: Check that the filesystem is read-only
	t.Run("ReadOnlyFilesystem", func(t *testing.T) {
		cmd := exec.CommandContext(ctx, "docker", "run", "--rm", imageName, "touch", "/test-file")
		err := cmd.Run()
		assert.Error(t, err, "Should not be able to write to read-only filesystem")
	})

	// Test 3: Check that /tmp is writable
	t.Run("WritableTmp", func(t *testing.T) {
		cmd := exec.CommandContext(ctx, "docker", "run", "--rm", imageName, "touch", "/tmp/test-file")
		err := cmd.Run()
		assert.NoError(t, err, "Should be able to write to /tmp")
	})

	// Test 4: Check that the binary exists and is executable
	t.Run("BinaryExists", func(t *testing.T) {
		cmd := exec.CommandContext(ctx, "docker", "run", "--rm", imageName, "ls", "-la", "/app/airlock")
		output, err := cmd.Output()
		require.NoError(t, err)

		assert.Contains(t, string(output), "/app/airlock")
		assert.Contains(t, string(output), "-rwxr-xr-x", "Binary should be executable")
	})
}

// TestHelmChart tests that the Helm chart is valid
func TestHelmChart(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Helm chart test in short mode")
	}

	// Check if helm is available
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("Helm not available, skipping chart tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	chartPath := filepath.Join(projectRoot, "helm", "airlock")

	// Test 1: Lint the Helm chart
	t.Run("HelmLint", func(t *testing.T) {
		cmd := exec.CommandContext(ctx, "helm", "lint", chartPath)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Helm lint failed: %s", string(output))
		assert.Contains(t, string(output), "1 chart(s) linted, 0 chart(s) failed")
	})

	// Test 2: Template the Helm chart
	t.Run("HelmTemplate", func(t *testing.T) {
		cmd := exec.CommandContext(ctx, "helm", "template", "test-release", chartPath)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Helm template failed: %s", string(output))

		// Check that essential resources are generated
		assert.Contains(t, string(output), "kind: Deployment")
		assert.Contains(t, string(output), "kind: Service")
		assert.Contains(t, string(output), "kind: ConfigMap")
		assert.Contains(t, string(output), "kind: ServiceAccount")
	})

	// Test 3: Template with custom values
	t.Run("HelmTemplateWithValues", func(t *testing.T) {
		valuesFile := filepath.Join(chartPath, "values-staging.yaml")
		cmd := exec.CommandContext(ctx, "helm", "template", "test-release", chartPath,
			"--values", valuesFile)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Helm template with values failed: %s", string(output))

		// Check staging-specific configurations
		assert.Contains(t, string(output), "airlock-staging.example.com")
		assert.Contains(t, string(output), "environment: staging")
	})
}

// TestKubernetesManifests tests that generated Kubernetes manifests are valid
func TestKubernetesManifests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Kubernetes manifest validation in short mode")
	}

	// Check if kubeval is available
	if _, err := exec.LookPath("kubeval"); err != nil {
		t.Skip("kubeval not available, skipping manifest validation")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	chartPath := filepath.Join(projectRoot, "helm", "airlock")
	tempDir := t.TempDir()

	// Generate manifests
	cmd := exec.CommandContext(ctx, "helm", "template", "test-release", chartPath,
		"--output-dir", tempDir)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to generate manifests: %s", string(output))

	// Validate all generated YAML files
	err = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if strings.HasSuffix(path, ".yaml") {
			cmd := exec.CommandContext(ctx, "kubeval", path)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("kubeval failed for %s: %s", path, string(output))
			}
		}
		return nil
	})
	require.NoError(t, err)
}

// TestSecurityScanning tests that security scanning tools work
func TestSecurityScanning(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping security scanning test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	// Test gosec
	t.Run("Gosec", func(t *testing.T) {
		if _, err := exec.LookPath("gosec"); err != nil {
			t.Skip("gosec not available")
		}

		cmd := exec.CommandContext(ctx, "gosec", "-fmt", "json", "./...")
		cmd.Dir = projectRoot
		output, _ := cmd.CombinedOutput()

		// gosec returns non-zero exit code if issues are found
		// We just want to make sure it runs without crashing
		assert.NotEmpty(t, output, "gosec should produce output")
	})

	// Test govulncheck
	t.Run("Govulncheck", func(t *testing.T) {
		// Install govulncheck if not available
		if _, err := exec.LookPath("govulncheck"); err != nil {
			installCmd := exec.CommandContext(ctx, "go", "install", "golang.org/x/vuln/cmd/govulncheck@latest")
			installCmd.Dir = projectRoot
			err := installCmd.Run()
			if err != nil {
				t.Skip("Failed to install govulncheck")
			}
		}

		cmd := exec.CommandContext(ctx, "govulncheck", "./...")
		cmd.Dir = projectRoot
		output, _ := cmd.CombinedOutput()

		// govulncheck returns non-zero if vulnerabilities are found
		// We just want to make sure it runs
		assert.NotEmpty(t, output, "govulncheck should produce output")
	})
}

// TestCIWorkflowSyntax tests that GitHub Actions workflows have valid syntax
func TestCIWorkflowSyntax(t *testing.T) {
	projectRoot, err := getProjectRoot()
	require.NoError(t, err)

	workflowsDir := filepath.Join(projectRoot, ".github", "workflows")

	// Check that workflow files exist
	workflows := []string{"ci.yml", "security-scan.yml"}

	for _, workflow := range workflows {
		workflowPath := filepath.Join(workflowsDir, workflow)

		t.Run(workflow, func(t *testing.T) {
			// Check that file exists
			_, err := os.Stat(workflowPath)
			require.NoError(t, err, "Workflow file should exist: %s", workflowPath)

			// Read and validate basic YAML structure
			content, err := os.ReadFile(workflowPath)
			require.NoError(t, err)

			// Basic checks for required fields
			contentStr := string(content)
			assert.Contains(t, contentStr, "name:", "Workflow should have a name")
			assert.Contains(t, contentStr, "on:", "Workflow should have triggers")
			assert.Contains(t, contentStr, "jobs:", "Workflow should have jobs")
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

#!/bin/bash

# Integration Test Runner for MCP Airlock
# This script sets up and runs comprehensive integration tests

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-airlock-test}"
RELEASE_NAME="${RELEASE_NAME:-airlock-test}"
TIMEOUT="${TIMEOUT:-600}"
CHART_PATH="${CHART_PATH:-./helm/airlock}"
TEST_TOKEN="${TEST_TOKEN:-}"
CLEANUP="${CLEANUP:-true}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check required tools
    for tool in kubectl helm docker go; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    # Check Kubernetes connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Build Docker images
build_images() {
    log_info "Building Docker images..."
    
    # Build main Airlock image
    docker build -t mcp-airlock:test \
        --build-arg VERSION=test \
        --build-arg GIT_COMMIT=test-$(git rev-parse --short HEAD 2>/dev/null || echo "unknown") \
        --build-arg BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
        .
    
    # Build MCP server images
    docker build -f examples/mcp-servers/Dockerfile.docs \
        -t mcp-docs-server:test \
        examples/mcp-servers/
    
    docker build -f examples/mcp-servers/Dockerfile.analytics \
        -t mcp-analytics-server:test \
        examples/mcp-servers/
    
    log_info "Docker images built successfully"
}

# Load images into kind (if using kind)
load_images_kind() {
    if kubectl config current-context | grep -q "kind"; then
        log_info "Loading images into kind cluster..."
        
        kind load docker-image mcp-airlock:test
        kind load docker-image mcp-docs-server:test
        kind load docker-image mcp-analytics-server:test
        
        log_info "Images loaded into kind cluster"
    fi
}

# Create test namespace
create_namespace() {
    log_info "Creating test namespace: $NAMESPACE"
    
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Label namespace for network policies
    kubectl label namespace "$NAMESPACE" name="$NAMESPACE" --overwrite
    
    log_info "Test namespace created"
}

# Deploy sample MCP servers
deploy_mcp_servers() {
    log_info "Deploying sample MCP servers..."
    
    # Create ConfigMap with sample documentation
    kubectl create configmap docs-content \
        --from-literal=README.md="# Test Documentation

This is test documentation for integration testing.

## Features
- Document search
- File reading
- Directory listing

## Usage
Use MCP tools to interact with this documentation.
" \
        --from-literal=api.md="# API Documentation

## Tools
- search_docs: Search for documents
- read_file: Read file contents
- list_directory: List directory contents
" \
        -n "$NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy docs server
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: docs-server
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: docs-server
  template:
    metadata:
      labels:
        app: docs-server
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        runAsGroup: 1001
        fsGroup: 1001
      containers:
      - name: docs-server
        image: mcp-docs-server:test
        imagePullPolicy: Never
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1001
          capabilities:
            drop: ["ALL"]
        env:
        - name: DOCS_ROOT
          value: "/mnt/docs"
        - name: MCP_SOCKET_PATH
          value: "/run/mcp/docs.sock"
        volumeMounts:
        - name: docs-content
          mountPath: /mnt/docs
        - name: mcp-sockets
          mountPath: /run/mcp
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: docs-content
        configMap:
          name: docs-content
      - name: mcp-sockets
        emptyDir: {}
      - name: tmp
        emptyDir: {}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: analytics-server
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: analytics-server
  template:
    metadata:
      labels:
        app: analytics-server
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        runAsGroup: 1001
        fsGroup: 1001
      containers:
      - name: analytics-server
        image: mcp-analytics-server:test
        imagePullPolicy: Never
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1001
          capabilities:
            drop: ["ALL"]
        env:
        - name: ANALYTICS_DB_PATH
          value: "/var/lib/analytics/analytics.db"
        - name: MCP_SOCKET_PATH
          value: "/run/mcp/analytics.sock"
        volumeMounts:
        - name: analytics-data
          mountPath: /var/lib/analytics
        - name: mcp-sockets
          mountPath: /run/mcp
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: analytics-data
        emptyDir: {}
      - name: mcp-sockets
        emptyDir: {}
      - name: tmp
        emptyDir: {}
EOF
    
    log_info "Sample MCP servers deployed"
}

# Deploy Airlock with test configuration
deploy_airlock() {
    log_info "Deploying Airlock..."
    
    # Create test values file
    cat > /tmp/test-values.yaml <<EOF
# Test configuration for integration tests
replicaCount: 1

image:
  repository: mcp-airlock
  tag: test
  pullPolicy: Never

# Disable authentication for testing
config:
  server:
    addr: ":8080"
    public_base_url: "http://localhost:8080"
  
  # Simplified auth for testing
  auth:
    oidc_issuer: "https://test.example.com/.well-known/openid-configuration"
    audience: "mcp-airlock-test"
    required_groups: ["test.users"]
  
  # Test upstreams
  upstreams:
    - name: "docs-server"
      type: "unix"
      socket: "/run/mcp/docs.sock"
      timeout: "30s"
      allow_tools: ["search_docs", "read_file", "list_directory"]
    - name: "analytics-server"
      type: "unix"
      socket: "/run/mcp/analytics.sock"
      timeout: "30s"
      allow_tools: ["query_metrics", "generate_report"]
  
  # Test roots
  roots:
    - name: "docs"
      type: "fs"
      virtual: "mcp://docs/"
      real: "/mnt/docs"
      read_only: true
  
  # Simplified DLP for testing
  dlp:
    patterns:
      - name: "test_pattern"
        regex: "secret"
        replace: "[REDACTED]"
  
  # Relaxed rate limiting for testing
  rate_limiting:
    per_token: "1000/min"
    per_ip: "5000/min"
    burst: 100
  
  # Test audit configuration
  audit:
    backend: "sqlite"
    database: "/var/lib/airlock/audit.db"
    retention: "1d"
  
  # Test observability
  observability:
    metrics:
      enabled: true
    logging:
      level: "debug"
      format: "json"

# Enable persistence for testing
persistence:
  enabled: true
  size: 1Gi
  storageClass: "standard"

# Test security context
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1001
  runAsGroup: 1001
  fsGroup: 1001

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 1001
  capabilities:
    drop: ["ALL"]

# Test resources
resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

# Test sidecars for MCP servers
sidecars:
  - name: docs-sidecar
    image: mcp-docs-server:test
    imagePullPolicy: Never
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1001
      capabilities:
        drop: ["ALL"]
    env:
      - name: MCP_SOCKET_PATH
        value: "/run/mcp/docs.sock"
    volumeMounts:
      - name: mcp-sockets
        mountPath: /run/mcp
      - name: docs-content
        mountPath: /mnt/docs
      - name: tmp
        mountPath: /tmp
  - name: analytics-sidecar
    image: mcp-analytics-server:test
    imagePullPolicy: Never
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1001
      capabilities:
        drop: ["ALL"]
    env:
      - name: MCP_SOCKET_PATH
        value: "/run/mcp/analytics.sock"
    volumeMounts:
      - name: mcp-sockets
        mountPath: /run/mcp
      - name: analytics-data
        mountPath: /var/lib/analytics
      - name: tmp
        mountPath: /tmp

# Extra volumes for MCP servers
extraVolumes:
  - name: mcp-sockets
    emptyDir: {}
  - name: docs-content
    configMap:
      name: docs-content
  - name: analytics-data
    emptyDir: {}

# Extra volume mounts
extraVolumeMounts:
  - name: mcp-sockets
    mountPath: /run/mcp
  - name: docs-content
    mountPath: /mnt/docs
EOF
    
    # Install Airlock
    helm upgrade --install "$RELEASE_NAME" "$CHART_PATH" \
        --namespace "$NAMESPACE" \
        --values /tmp/test-values.yaml \
        --timeout "${TIMEOUT}s" \
        --wait
    
    log_info "Airlock deployed successfully"
}

# Wait for deployments to be ready
wait_for_ready() {
    log_info "Waiting for deployments to be ready..."
    
    # Wait for Airlock
    kubectl wait --for=condition=available \
        --timeout="${TIMEOUT}s" \
        deployment/"$RELEASE_NAME" \
        -n "$NAMESPACE"
    
    # Wait for MCP servers
    kubectl wait --for=condition=available \
        --timeout="${TIMEOUT}s" \
        deployment/docs-server \
        -n "$NAMESPACE"
    
    kubectl wait --for=condition=available \
        --timeout="${TIMEOUT}s" \
        deployment/analytics-server \
        -n "$NAMESPACE"
    
    log_info "All deployments are ready"
}

# Generate test token (mock)
generate_test_token() {
    if [ -z "$TEST_TOKEN" ]; then
        log_info "Generating mock test token..."
        # In a real scenario, this would be a proper JWT token
        TEST_TOKEN="test-token-$(date +%s)"
        export TEST_TOKEN
        log_debug "Generated test token: $TEST_TOKEN"
    fi
}

# Run Go integration tests
run_go_tests() {
    log_info "Running Go integration tests..."
    
    # Set up environment for tests
    export KUBERNETES_SERVICE_HOST="kubernetes.default.svc"
    export AIRLOCK_URL="http://$RELEASE_NAME.$NAMESPACE.svc.cluster.local:8080"
    export TEST_NAMESPACE="$NAMESPACE"
    
    # Port forward for local testing
    kubectl port-forward -n "$NAMESPACE" service/"$RELEASE_NAME" 8080:8080 &
    PORT_FORWARD_PID=$!
    
    # Wait for port forward to be ready
    sleep 5
    
    # Override URL for local access
    export AIRLOCK_URL="http://localhost:8080"
    
    # Run the tests
    go test -v -timeout=10m ./tests/integration/e2e/... || TEST_FAILED=true
    
    # Clean up port forward
    kill $PORT_FORWARD_PID 2>/dev/null || true
    
    if [ "${TEST_FAILED:-false}" = "true" ]; then
        log_error "Integration tests failed"
        return 1
    fi
    
    log_info "Go integration tests passed"
}

# Run Helm tests
run_helm_tests() {
    log_info "Running Helm tests..."
    
    helm test "$RELEASE_NAME" -n "$NAMESPACE" --timeout "${TIMEOUT}s"
    
    log_info "Helm tests passed"
}

# Run load tests
run_load_tests() {
    log_info "Running load tests..."
    
    # Set up environment
    export KUBERNETES_SERVICE_HOST="kubernetes.default.svc"
    export AIRLOCK_URL="http://localhost:8080"
    export TEST_NAMESPACE="$NAMESPACE"
    
    # Port forward for load testing
    kubectl port-forward -n "$NAMESPACE" service/"$RELEASE_NAME" 8080:8080 &
    PORT_FORWARD_PID=$!
    
    # Wait for port forward to be ready
    sleep 5
    
    # Run load tests
    go test -v -timeout=10m -run TestLoadTesting ./tests/integration/e2e/... || LOAD_TEST_FAILED=true
    
    # Clean up port forward
    kill $PORT_FORWARD_PID 2>/dev/null || true
    
    if [ "${LOAD_TEST_FAILED:-false}" = "true" ]; then
        log_warn "Load tests failed or had issues"
    else
        log_info "Load tests passed"
    fi
}

# Collect logs and debug information
collect_debug_info() {
    log_info "Collecting debug information..."
    
    local debug_dir="/tmp/airlock-debug-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$debug_dir"
    
    # Collect pod logs
    kubectl logs -l app.kubernetes.io/name=airlock -n "$NAMESPACE" --tail=1000 > "$debug_dir/airlock-logs.txt" || true
    kubectl logs -l app=docs-server -n "$NAMESPACE" --tail=1000 > "$debug_dir/docs-server-logs.txt" || true
    kubectl logs -l app=analytics-server -n "$NAMESPACE" --tail=1000 > "$debug_dir/analytics-server-logs.txt" || true
    
    # Collect resource descriptions
    kubectl describe pods -n "$NAMESPACE" > "$debug_dir/pods-describe.txt" || true
    kubectl describe services -n "$NAMESPACE" > "$debug_dir/services-describe.txt" || true
    kubectl describe configmaps -n "$NAMESPACE" > "$debug_dir/configmaps-describe.txt" || true
    
    # Collect events
    kubectl get events -n "$NAMESPACE" --sort-by=.metadata.creationTimestamp > "$debug_dir/events.txt" || true
    
    # Collect Helm status
    helm status "$RELEASE_NAME" -n "$NAMESPACE" > "$debug_dir/helm-status.txt" || true
    
    log_info "Debug information collected in: $debug_dir"
}

# Cleanup function
cleanup() {
    if [ "$CLEANUP" = "true" ]; then
        log_info "Cleaning up test resources..."
        
        # Kill any remaining port forwards
        pkill -f "kubectl port-forward" 2>/dev/null || true
        
        # Uninstall Helm release
        helm uninstall "$RELEASE_NAME" -n "$NAMESPACE" || true
        
        # Delete namespace
        kubectl delete namespace "$NAMESPACE" || true
        
        # Clean up temporary files
        rm -f /tmp/test-values.yaml
        
        log_info "Cleanup completed"
    else
        log_info "Cleanup skipped (CLEANUP=false)"
        log_info "To clean up manually:"
        log_info "  helm uninstall $RELEASE_NAME -n $NAMESPACE"
        log_info "  kubectl delete namespace $NAMESPACE"
    fi
}

# Main execution
main() {
    log_info "Starting MCP Airlock integration tests..."
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    # Run all steps
    check_prerequisites
    build_images
    load_images_kind
    create_namespace
    deploy_mcp_servers
    deploy_airlock
    wait_for_ready
    generate_test_token
    
    # Run tests
    local test_failed=false
    
    run_helm_tests || test_failed=true
    run_go_tests || test_failed=true
    
    # Optional load tests
    if [ "${RUN_LOAD_TESTS:-false}" = "true" ]; then
        run_load_tests
    fi
    
    # Collect debug info if tests failed
    if [ "$test_failed" = "true" ]; then
        collect_debug_info
        log_error "Some tests failed. Check debug information."
        exit 1
    fi
    
    log_info "All integration tests passed! ✅"
}

# Handle script arguments
case "${1:-}" in
    "cleanup")
        CLEANUP=true
        cleanup
        exit 0
        ;;
    "debug")
        collect_debug_info
        exit 0
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [cleanup|debug|help]"
        echo ""
        echo "Environment variables:"
        echo "  NAMESPACE      - Kubernetes namespace (default: airlock-test)"
        echo "  RELEASE_NAME   - Helm release name (default: airlock-test)"
        echo "  TIMEOUT        - Timeout in seconds (default: 600)"
        echo "  CHART_PATH     - Path to Helm chart (default: ./helm/airlock)"
        echo "  TEST_TOKEN     - Authentication token for tests"
        echo "  CLEANUP        - Clean up resources after tests (default: true)"
        echo "  RUN_LOAD_TESTS - Run load tests (default: false)"
        exit 0
        ;;
    "")
        # Run main function
        main
        ;;
    *)
        log_error "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac
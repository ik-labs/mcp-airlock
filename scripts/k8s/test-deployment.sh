#!/bin/bash

# Test script for Kubernetes deployment validation
# This script validates the Airlock deployment in a Kubernetes environment

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-airlock-test}"
RELEASE_NAME="${RELEASE_NAME:-airlock-test}"
TIMEOUT="${TIMEOUT:-300}"
CHART_PATH="${CHART_PATH:-./helm/airlock}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if helm is available
    if ! command -v helm &> /dev/null; then
        log_error "helm is not installed or not in PATH"
        exit 1
    fi
    
    # Check if we can connect to Kubernetes cluster
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Create namespace if it doesn't exist
create_namespace() {
    log_info "Creating namespace ${NAMESPACE}..."
    
    if kubectl get namespace "${NAMESPACE}" &> /dev/null; then
        log_warn "Namespace ${NAMESPACE} already exists"
    else
        kubectl create namespace "${NAMESPACE}"
        log_info "Namespace ${NAMESPACE} created"
    fi
}

# Install or upgrade Helm chart
install_chart() {
    log_info "Installing/upgrading Helm chart..."
    
    helm upgrade --install "${RELEASE_NAME}" "${CHART_PATH}" \
        --namespace "${NAMESPACE}" \
        --timeout "${TIMEOUT}s" \
        --wait \
        --values - <<EOF
# Test configuration
replicaCount: 1
image:
  tag: "latest"
  pullPolicy: IfNotPresent

# Enable security features for testing
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1001
  runAsGroup: 1001
  fsGroup: 1001
  seccompProfile:
    type: RuntimeDefault

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 1001
  runAsGroup: 1001
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault

# Enable network policy for testing
networkPolicy:
  enabled: true

# Enable persistence for testing
persistence:
  enabled: true
  size: 1Gi
  storageClass: "standard"

# Test configuration
config:
  server:
    addr: ":8080"
    public_base_url: "http://localhost:8080"
  auth:
    oidc_issuer: "https://test.example.com/.well-known/openid-configuration"
    audience: "mcp-airlock-test"
  observability:
    logging:
      level: "debug"
EOF
    
    log_info "Helm chart installed/upgraded successfully"
}

# Wait for deployment to be ready
wait_for_deployment() {
    log_info "Waiting for deployment to be ready..."
    
    kubectl wait --for=condition=available \
        --timeout="${TIMEOUT}s" \
        deployment/"${RELEASE_NAME}" \
        -n "${NAMESPACE}"
    
    log_info "Deployment is ready"
}

# Run security validation tests
test_security() {
    log_info "Running security validation tests..."
    
    # Get pod name
    POD_NAME=$(kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=airlock,app.kubernetes.io/instance=${RELEASE_NAME}" -o jsonpath="{.items[0].metadata.name}")
    
    # Test 1: Check if running as non-root
    log_info "Testing non-root execution..."
    USER_ID=$(kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -- id -u)
    if [ "${USER_ID}" -eq 0 ]; then
        log_error "Pod is running as root user"
        return 1
    fi
    log_info "✓ Pod is running as non-root user (${USER_ID})"
    
    # Test 2: Check read-only filesystem
    log_info "Testing read-only filesystem..."
    if kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -- touch /test-file 2>/dev/null; then
        log_error "Root filesystem is writable"
        return 1
    fi
    log_info "✓ Root filesystem is read-only"
    
    # Test 3: Check security context
    log_info "Testing security context..."
    SECURITY_CONTEXT=$(kubectl get pod -n "${NAMESPACE}" "${POD_NAME}" -o jsonpath='{.spec.securityContext}')
    if [[ "${SECURITY_CONTEXT}" != *"runAsNonRoot\":true"* ]]; then
        log_error "Pod security context not properly configured"
        return 1
    fi
    log_info "✓ Security context properly configured"
    
    # Test 4: Check capabilities
    log_info "Testing capabilities..."
    CAPABILITIES=$(kubectl get pod -n "${NAMESPACE}" "${POD_NAME}" -o jsonpath='{.spec.containers[0].securityContext.capabilities}')
    if [[ "${CAPABILITIES}" != *"drop\":[\"ALL\"]"* ]]; then
        log_error "Capabilities not properly dropped"
        return 1
    fi
    log_info "✓ All capabilities dropped"
    
    log_info "Security validation tests passed"
}

# Test application functionality
test_functionality() {
    log_info "Testing application functionality..."
    
    # Port forward to access the service
    kubectl port-forward -n "${NAMESPACE}" service/"${RELEASE_NAME}" 8080:8080 &
    PORT_FORWARD_PID=$!
    
    # Wait for port forward to be ready
    sleep 5
    
    # Test health endpoints
    log_info "Testing health endpoints..."
    
    # Test liveness endpoint
    if ! curl -f -s http://localhost:8080/live > /dev/null; then
        log_error "Liveness endpoint failed"
        kill ${PORT_FORWARD_PID} 2>/dev/null || true
        return 1
    fi
    log_info "✓ Liveness endpoint working"
    
    # Test readiness endpoint
    if ! curl -f -s http://localhost:8080/ready > /dev/null; then
        log_error "Readiness endpoint failed"
        kill ${PORT_FORWARD_PID} 2>/dev/null || true
        return 1
    fi
    log_info "✓ Readiness endpoint working"
    
    # Test info endpoint
    if ! curl -f -s http://localhost:8080/info | grep -q "version"; then
        log_error "Info endpoint failed"
        kill ${PORT_FORWARD_PID} 2>/dev/null || true
        return 1
    fi
    log_info "✓ Info endpoint working"
    
    # Clean up port forward
    kill ${PORT_FORWARD_PID} 2>/dev/null || true
    
    log_info "Functionality tests passed"
}

# Run Helm tests
run_helm_tests() {
    log_info "Running Helm tests..."
    
    helm test "${RELEASE_NAME}" -n "${NAMESPACE}" --timeout "${TIMEOUT}s"
    
    log_info "Helm tests passed"
}

# Test persistence
test_persistence() {
    log_info "Testing persistence..."
    
    # Check if PVC exists and is bound
    PVC_STATUS=$(kubectl get pvc -n "${NAMESPACE}" "${RELEASE_NAME}-data" -o jsonpath='{.status.phase}')
    if [ "${PVC_STATUS}" != "Bound" ]; then
        log_error "PVC is not bound (status: ${PVC_STATUS})"
        return 1
    fi
    log_info "✓ PVC is bound"
    
    # Test writing to persistent volume
    POD_NAME=$(kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=airlock,app.kubernetes.io/instance=${RELEASE_NAME}" -o jsonpath="{.items[0].metadata.name}")
    
    kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -- touch /var/lib/airlock/test-file
    if ! kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -- ls /var/lib/airlock/test-file > /dev/null; then
        log_error "Cannot write to persistent volume"
        return 1
    fi
    log_info "✓ Persistent volume is writable"
    
    # Clean up test file
    kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -- rm -f /var/lib/airlock/test-file
    
    log_info "Persistence tests passed"
}

# Test network policy
test_network_policy() {
    log_info "Testing network policy..."
    
    # Check if network policy exists
    if ! kubectl get networkpolicy -n "${NAMESPACE}" "${RELEASE_NAME}" > /dev/null; then
        log_error "Network policy not found"
        return 1
    fi
    log_info "✓ Network policy exists"
    
    log_info "Network policy tests passed"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test resources..."
    
    # Kill any remaining port forwards
    pkill -f "kubectl port-forward" 2>/dev/null || true
    
    # Optionally delete the test release and namespace
    if [ "${CLEANUP:-false}" = "true" ]; then
        helm uninstall "${RELEASE_NAME}" -n "${NAMESPACE}" || true
        kubectl delete namespace "${NAMESPACE}" || true
        log_info "Test resources cleaned up"
    else
        log_info "Test resources left for inspection (set CLEANUP=true to auto-cleanup)"
    fi
}

# Main execution
main() {
    log_info "Starting Kubernetes deployment validation tests..."
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    # Run all tests
    check_prerequisites
    create_namespace
    install_chart
    wait_for_deployment
    test_security
    test_functionality
    test_persistence
    test_network_policy
    run_helm_tests
    
    log_info "All tests passed! ✅"
}

# Run main function
main "$@"
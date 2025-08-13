# Quick Start Guide

Get MCP Airlock running in your Kubernetes cluster in under 10 minutes.

## Prerequisites

- Kubernetes cluster with kubectl access
- Helm 3.8+
- OIDC provider configured (we'll use a mock for this guide)

## Step 1: Add Helm Repository

```bash
helm repo add mcp-airlock https://charts.mcp-airlock.io
helm repo update
```

## Step 2: Create Namespace

```bash
kubectl create namespace mcp-airlock
```

## Step 3: Create Basic Configuration

Create `values-quickstart.yaml`:

```yaml
# Basic configuration for development/testing
server:
  replicas: 1
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi

auth:
  # For development only - use real OIDC in production
  oidc_issuer: "https://dev-auth.example.com/.well-known/openid-configuration"
  audience: "mcp-airlock-dev"
  # Mock validation for development
  mock_validation: true

policy:
  # Permissive policy for development
  inline: |
    package airlock.authz
    import rego.v1
    default allow := true  # Allow all for development

roots:
  - name: "demo-repo"
    type: "fs"
    virtual: "mcp://repo/"
    real: "/tmp/demo-repo"
    read_only: true

upstreams:
  - name: "demo-server"
    type: "stdio"
    command: ["echo", "Demo MCP server"]
    timeout: "10s"

audit:
  backend: "sqlite"
  retention: "7d"  # Short retention for development

ingress:
  enabled: true
  className: "nginx"
  hosts:
    - host: airlock-dev.local
      paths:
        - path: /
          pathType: Prefix
  tls: []

# Development-friendly settings
observability:
  logging:
    level: "debug"
  metrics:
    enabled: true
```

## Step 4: Deploy with Helm

```bash
helm install mcp-airlock mcp-airlock/airlock \
  --namespace mcp-airlock \
  --values values-quickstart.yaml \
  --wait
```

## Step 5: Verify Deployment

```bash
# Check pod status
kubectl get pods -n mcp-airlock

# Check service
kubectl get svc -n mcp-airlock

# Check ingress
kubectl get ingress -n mcp-airlock

# View logs
kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock
```

## Step 6: Test Connection

```bash
# Port forward for local testing
kubectl port-forward -n mcp-airlock svc/mcp-airlock 8080:80

# Test health endpoint
curl http://localhost:8080/health/live

# Test with mock authentication
curl -H "Authorization: Bearer mock-token" \
     http://localhost:8080/mcp/v1/initialize
```

## Next Steps

- Configure real OIDC authentication
- Set up proper TLS certificates
- Configure production-ready policies
- Add monitoring and alerting
- Follow the [Production Deployment Guide](production.md)

## Cleanup

```bash
helm uninstall mcp-airlock --namespace mcp-airlock
kubectl delete namespace mcp-airlock
```
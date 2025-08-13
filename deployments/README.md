# MCP Airlock Deployment Guide

This directory contains deployment examples and configurations for MCP Airlock in various environments.

## Overview

MCP Airlock can be deployed in several configurations depending on your infrastructure and requirements:

1. **AWS Single-VPC Deployment** - Production deployment in AWS with ALB ingress
2. **Sidecar Deployment** - MCP servers running as sidecars alongside Airlock
3. **HTTP Service Upstream** - MCP servers running as separate HTTP services
4. **EFS/S3 Integration** - Using AWS EFS for filesystem roots and S3 for object storage

## Prerequisites

- Kubernetes cluster (1.25+)
- Helm 3.14+
- kubectl configured to access your cluster
- For AWS deployments:
  - AWS Load Balancer Controller
  - EFS CSI Driver (for EFS integration)
  - IAM roles for service accounts (IRSA)

## Quick Start

### 1. Install with Default Configuration

```bash
# Add the Helm repository (when available)
helm repo add airlock https://ik-labs.github.io/mcp-airlock

# Install with default values
helm install airlock airlock/airlock \
  --namespace airlock \
  --create-namespace \
  --wait
```

### 2. Install from Source

```bash
# Clone the repository
git clone https://github.com/ik-labs/mcp-airlock.git
cd mcp-airlock

# Install with default values
helm install airlock helm/airlock \
  --namespace airlock \
  --create-namespace \
  --wait
```

## Deployment Examples

### AWS Single-VPC Production Deployment

This example shows a production-ready deployment in AWS with:
- ALB ingress with TLS termination
- EFS for shared filesystem access
- S3 for artifact storage
- Horizontal Pod Autoscaling
- Pod Disruption Budgets
- Network Policies

```bash
# Apply the AWS single-VPC example
kubectl apply -f deployments/examples/aws-single-vpc.yaml

# Or use Helm with production values
helm install airlock helm/airlock \
  --namespace airlock-production \
  --create-namespace \
  --values helm/airlock/values-production.yaml \
  --set ingress.hosts[0].host=airlock.yourdomain.com \
  --set config.auth.oidc_issuer=https://your-oidc-provider/.well-known/openid-configuration \
  --wait
```

### Sidecar Deployment

Deploy Airlock with MCP servers running as sidecars:

```bash
# Apply the sidecar deployment example
kubectl apply -f deployments/examples/sidecar-deployment.yaml
```

This configuration includes:
- Airlock gateway container
- Documentation MCP server sidecar
- Analytics MCP server sidecar
- Shared Unix socket communication
- Proper security contexts for all containers

### HTTP Service Upstream

Deploy Airlock connecting to MCP servers via HTTP:

```bash
# Apply the HTTP service upstream example
kubectl apply -f deployments/examples/http-service-upstream.yaml
```

This configuration includes:
- Airlock gateway connecting to HTTP services
- Separate MCP server deployments
- Service-to-service authentication
- Load balancing across MCP server replicas

### EFS and S3 Integration

Deploy Airlock with AWS EFS and S3 integration:

```bash
# Update the EFS filesystem ID in the example
sed -i 's/fs-0123456789abcdef0/your-efs-id/g' deployments/examples/efs-s3-integration.yaml

# Apply the EFS/S3 integration example
kubectl apply -f deployments/examples/efs-s3-integration.yaml
```

This configuration includes:
- EFS CSI driver integration
- Multiple EFS access points
- S3 bucket access via IRSA
- Read-only and read-write root mappings

## Configuration

### Environment-Specific Values

The Helm chart includes environment-specific value files:

- `values.yaml` - Default configuration for development/testing
- `values-staging.yaml` - Staging environment configuration
- `values-production.yaml` - Production environment configuration

### Key Configuration Options

#### Authentication

```yaml
config:
  auth:
    oidc_issuer: "https://your-oidc-provider/.well-known/openid-configuration"
    audience: "mcp-airlock"
    required_groups: ["mcp.users"]
```

#### Root Virtualization

```yaml
config:
  roots:
    - name: "repo-readonly"
      type: "fs"
      virtual: "mcp://repo/"
      real: "/mnt/repositories"
      read_only: true
    - name: "artifacts"
      type: "s3"
      virtual: "mcp://artifacts/"
      real: "s3://your-bucket/"
      read_only: false
```

#### Upstream Servers

```yaml
config:
  upstreams:
    - name: "docs-server"
      type: "unix"
      socket: "/run/mcp/docs.sock"
      timeout: "30s"
      allow_tools: ["search_docs", "read_file"]
```

#### Security Policies

```yaml
config:
  dlp:
    patterns:
      - name: "email"
        regex: '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
        replace: "[redacted-email]"
```

## Security Considerations

### Pod Security Standards

All deployments use Pod Security Admission (PSA) compliant configurations:

- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`
- `seccompProfile.type: RuntimeDefault`
- All capabilities dropped

### Network Policies

Network policies are enabled by default to restrict traffic:

```yaml
networkPolicy:
  enabled: true
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
  egress:
    - to: []
      ports:
        - protocol: TCP
          port: 443  # HTTPS only
```

### RBAC

Minimal RBAC permissions are granted:

```yaml
serviceAccount:
  create: true
  automountServiceAccountToken: false
```

## Monitoring and Observability

### Metrics

Prometheus metrics are exposed at `/metrics`:

```yaml
config:
  observability:
    metrics:
      enabled: true
      path: "/metrics"
```

### Tracing

OpenTelemetry tracing can be enabled:

```yaml
config:
  observability:
    tracing:
      enabled: true
      endpoint: "http://jaeger:14268/api/traces"
```

### Logging

Structured JSON logging is configured by default:

```yaml
config:
  observability:
    logging:
      level: "info"
      format: "json"
```

## Scaling and Performance

### Horizontal Pod Autoscaling

HPA is configured based on CPU and memory utilization:

```yaml
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 60
  targetMemoryUtilizationPercentage: 70
```

### Resource Limits

Production resource limits:

```yaml
resources:
  limits:
    cpu: 2000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 512Mi
```

### Pod Disruption Budgets

PDBs ensure availability during updates:

```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 1
```

## Backup and Disaster Recovery

### Audit Data Backup

Audit data can be exported to S3:

```yaml
config:
  audit:
    s3_export:
      enabled: true
      bucket: "your-audit-backup-bucket"
      prefix: "audit-logs/"
```

### Configuration Backup

Store Helm values and configurations in version control and backup:

```bash
# Export current configuration
helm get values airlock -n airlock-production > backup-values.yaml

# Backup secrets
kubectl get secrets -n airlock-production -o yaml > backup-secrets.yaml
```

## Troubleshooting

### Common Issues

1. **Pod Security Policy Violations**
   - Ensure all security contexts are properly configured
   - Check that containers run as non-root user

2. **Network Policy Blocking Traffic**
   - Verify ingress and egress rules
   - Check namespace labels for selectors

3. **OIDC Authentication Failures**
   - Verify OIDC issuer URL is accessible
   - Check JWT token format and claims

4. **Storage Issues**
   - Verify PVC is bound
   - Check storage class availability
   - For EFS: verify mount targets and security groups

### Debugging Commands

```bash
# Check pod status
kubectl get pods -n airlock-production -l app.kubernetes.io/name=airlock

# View logs
kubectl logs -n airlock-production -l app.kubernetes.io/name=airlock -f

# Check events
kubectl get events -n airlock-production --sort-by=.metadata.creationTimestamp

# Test connectivity
kubectl run debug --rm -i --tty --image=curlimages/curl -- sh

# Check configuration
kubectl get configmap airlock-config -n airlock-production -o yaml
```

### Health Checks

```bash
# Check liveness
kubectl exec -n airlock-production deployment/airlock -- curl -f http://localhost:8080/live

# Check readiness
kubectl exec -n airlock-production deployment/airlock -- curl -f http://localhost:8080/ready

# Check metrics
kubectl exec -n airlock-production deployment/airlock -- curl -s http://localhost:8080/metrics
```

## Upgrading

### Helm Upgrade

```bash
# Upgrade to latest version
helm upgrade airlock helm/airlock \
  --namespace airlock-production \
  --values values-production.yaml \
  --wait

# Rollback if needed
helm rollback airlock 1 -n airlock-production
```

### Zero-Downtime Updates

1. Ensure HPA is enabled with `minReplicas >= 2`
2. Configure PDB with `minAvailable: 1`
3. Use rolling update strategy (default)
4. Monitor during upgrade

## Support

For issues and questions:

1. Check the [troubleshooting guide](../docs/operations/troubleshooting.md)
2. Review [GitHub issues](https://github.com/ik-labs/mcp-airlock/issues)
3. Consult the [security documentation](../docs/security/README.md)

## Contributing

To contribute deployment examples or improvements:

1. Fork the repository
2. Create a feature branch
3. Add your deployment example with documentation
4. Test with the validation scripts
5. Submit a pull request
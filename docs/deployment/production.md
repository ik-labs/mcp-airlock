# Production Deployment Guide

This guide covers deploying MCP Airlock in a production environment with security hardening, high availability, and operational best practices.

## Architecture Overview

```
Internet → AWS ALB → Kubernetes Ingress → Airlock Pods → MCP Servers
                                      ↓
                                 PostgreSQL RDS
                                      ↓
                                 S3 Audit Export
```

## Prerequisites

### Infrastructure
- Kubernetes 1.24+ with Pod Security Standards enabled
- PostgreSQL database (RDS recommended)
- S3 bucket for audit log export
- Application Load Balancer with TLS termination
- OIDC provider (Auth0, Okta, Azure AD)
- Monitoring stack (Prometheus, Grafana)

### Security Requirements
- TLS certificates from trusted CA
- Network policies enabled
- Pod Security Admission configured
- Secrets management (AWS Secrets Manager, Vault)

## Step 1: Prepare Infrastructure

### Create Namespace with Security Policies

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: mcp-airlock
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mcp-airlock-network-policy
  namespace: mcp-airlock
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: airlock
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to: []  # Allow all egress for OIDC, database, etc.
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 5432
```

### Create Secrets

```bash
# Database connection
kubectl create secret generic airlock-database \
  --namespace mcp-airlock \
  --from-literal=url="postgresql://user:pass@rds-endpoint:5432/airlock"

# OIDC configuration
kubectl create secret generic airlock-oidc \
  --namespace mcp-airlock \
  --from-literal=client-secret="your-oidc-client-secret"

# S3 credentials for audit export
kubectl create secret generic airlock-s3 \
  --namespace mcp-airlock \
  --from-literal=access-key-id="AKIA..." \
  --from-literal=secret-access-key="..."
```

## Step 2: Production Helm Values

Create `values-production.yaml`:

```yaml
# Production configuration
image:
  repository: mcp-airlock/airlock
  tag: "v1.0.0"
  pullPolicy: IfNotPresent

server:
  replicas: 3
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi
  
  # Security context
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
    capabilities:
      drop:
      - ALL
    readOnlyRootFilesystem: true
    allowPrivilegeEscalation: false

  # Pod disruption budget
  podDisruptionBudget:
    enabled: true
    minAvailable: 2

  # Horizontal Pod Autoscaler
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80

auth:
  oidc_issuer: "https://your-org.auth0.com/.well-known/openid-configuration"
  audience: "mcp-airlock-prod"
  jwks_cache_ttl: "5m"
  clock_skew: "2m"
  required_groups: ["mcp.users"]
  
  # Reference to secret
  clientSecretRef:
    name: airlock-oidc
    key: client-secret

policy:
  # Production policy from ConfigMap
  configMapRef:
    name: airlock-policy
    key: policy.rego
  cache_ttl: "1m"
  reload_signal: "SIGHUP"

roots:
  - name: "repo-readonly"
    type: "fs"
    virtual: "mcp://repo/"
    real: "/mnt/efs/repositories"
    read_only: true
  - name: "artifacts"
    type: "s3"
    virtual: "mcp://artifacts/"
    real: "s3://your-org-mcp-artifacts/"
    read_only: false

dlp:
  patterns:
    - name: "email"
      regex: '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
      replace: "[redacted-email]"
    - name: "bearer_token"
      regex: '(?i)bearer\s+[a-z0-9._-]+'
      replace: "[redacted-token]"
    - name: "aws_key"
      regex: 'AKIA[0-9A-Z]{16}'
      replace: "[redacted-aws-key]"
    - name: "ssh_key"
      regex: '-----BEGIN [A-Z ]+PRIVATE KEY-----'
      replace: "[redacted-ssh-key]"

rate_limiting:
  per_token: "200/min"
  per_ip: "1000/min"
  burst: 50

upstreams:
  - name: "docs-server"
    type: "unix"
    socket: "/run/mcp/docs.sock"
    timeout: "30s"
    allow_tools: ["search_docs", "read_file"]
  - name: "code-server"
    type: "stdio"
    command: ["python", "-m", "mcp_server.code"]
    env:
      PYTHONPATH: "/opt/mcp-servers"
    timeout: "30s"

audit:
  backend: "postgresql"
  databaseSecretRef:
    name: airlock-database
    key: url
  retention: "90d"
  export_format: "jsonl"
  s3_export:
    enabled: true
    bucket: "your-org-audit-logs"
    prefix: "mcp-airlock/"
    secretRef:
      name: airlock-s3

observability:
  metrics:
    enabled: true
    path: "/metrics"
    serviceMonitor:
      enabled: true
      namespace: monitoring
  tracing:
    enabled: true
    endpoint: "http://jaeger-collector:14268/api/traces"
  logging:
    level: "info"
    format: "json"

ingress:
  enabled: true
  className: "alb"
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/ssl-redirect: "443"
    alb.ingress.kubernetes.io/certificate-arn: "arn:aws:acm:us-west-2:123456789012:certificate/..."
  hosts:
    - host: mcp-airlock.your-org.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: airlock-tls
      hosts:
        - mcp-airlock.your-org.com

# Persistent volumes for audit storage
persistence:
  enabled: true
  storageClass: "gp3"
  size: "100Gi"
  accessMode: ReadWriteOnce

# Service account with minimal permissions
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/mcp-airlock-role"
```

## Step 3: Create Production Policy

```yaml
# policy-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: airlock-policy
  namespace: mcp-airlock
data:
  policy.rego: |
    package airlock.authz
    import rego.v1
    
    # Default deny
    default allow := false
    
    # Allow authenticated users with proper groups
    allow if {
        input.groups[_] == "mcp.users"
        allowed_tool[input.tool]
        allowed_resource[input.resource]
        not rate_limited
    }
    
    # Tool allowlist by group
    allowed_tool contains tool if {
        tool := input.tool
        tool in ["search_docs", "read_file", "list_directory"]
        input.groups[_] == "mcp.users"
    }
    
    allowed_tool contains tool if {
        tool := input.tool
        tool in ["read_file", "write_file", "execute_command"]
        input.groups[_] == "mcp.power_users"
    }
    
    # Resource access controls
    allowed_resource contains resource if {
        resource := input.resource
        startswith(resource, "mcp://repo/")
        not contains(resource, "../")
        not contains(resource, ".git/")
    }
    
    allowed_resource contains resource if {
        resource := input.resource
        startswith(resource, "mcp://artifacts/")
        input.groups[_] in ["mcp.writers", "mcp.power_users"]
    }
    
    # Rate limiting check
    rate_limited if {
        input.metadata.requests_per_minute > 200
    }
    
    # Audit metadata
    audit_metadata := {
        "tenant": input.tenant,
        "tool": input.tool,
        "resource": input.resource,
        "decision": allow,
        "groups": input.groups
    }
```

## Step 4: Deploy to Production

```bash
# Apply namespace and network policies
kubectl apply -f namespace.yaml

# Create policy ConfigMap
kubectl apply -f policy-configmap.yaml

# Deploy with Helm
helm install mcp-airlock mcp-airlock/airlock \
  --namespace mcp-airlock \
  --values values-production.yaml \
  --wait \
  --timeout 10m

# Verify deployment
kubectl get pods -n mcp-airlock
kubectl get ingress -n mcp-airlock
```

## Step 5: Post-Deployment Verification

### Health Checks
```bash
# Check all pods are ready
kubectl get pods -n mcp-airlock -o wide

# Verify health endpoints
curl https://mcp-airlock.your-org.com/health/live
curl https://mcp-airlock.your-org.com/health/ready

# Check metrics endpoint
curl https://mcp-airlock.your-org.com/metrics
```

### Security Validation
```bash
# Verify TLS configuration
openssl s_client -connect mcp-airlock.your-org.com:443 -servername mcp-airlock.your-org.com

# Test authentication
curl -H "Authorization: Bearer invalid-token" \
     https://mcp-airlock.your-org.com/mcp/v1/initialize
# Should return 401

# Test with valid token
curl -H "Authorization: Bearer $VALID_TOKEN" \
     https://mcp-airlock.your-org.com/mcp/v1/initialize
```

### Performance Testing
```bash
# Load test with hey
hey -n 1000 -c 10 -H "Authorization: Bearer $VALID_TOKEN" \
    https://mcp-airlock.your-org.com/health/live

# Monitor metrics during load test
kubectl port-forward -n mcp-airlock svc/mcp-airlock 9090:9090
curl http://localhost:9090/metrics | grep airlock_
```

## Step 6: Monitoring and Alerting

### Prometheus Rules
```yaml
# prometheus-rules.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: mcp-airlock-alerts
  namespace: mcp-airlock
spec:
  groups:
  - name: mcp-airlock
    rules:
    - alert: AirlockHighErrorRate
      expr: rate(airlock_requests_total{status=~"5.."}[5m]) > 0.1
      for: 2m
      labels:
        severity: critical
      annotations:
        summary: "High error rate in MCP Airlock"
        description: "Error rate is {{ $value }} errors per second"
    
    - alert: AirlockHighLatency
      expr: histogram_quantile(0.95, rate(airlock_request_duration_seconds_bucket[5m])) > 0.1
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High latency in MCP Airlock"
        description: "95th percentile latency is {{ $value }}s"
    
    - alert: AirlockAuditStorageFailure
      expr: increase(airlock_audit_errors_total[5m]) > 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Audit storage failures detected"
        description: "{{ $value }} audit storage failures in the last 5 minutes"
```

### Grafana Dashboard
```json
{
  "dashboard": {
    "title": "MCP Airlock",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(airlock_requests_total[5m])",
            "legendFormat": "{{status}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(airlock_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Authentication Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(airlock_auth_success_total[5m]) / rate(airlock_auth_attempts_total[5m])",
            "legendFormat": "Success Rate"
          }
        ]
      }
    ]
  }
}
```

## Step 7: Backup and Disaster Recovery

### Database Backup
```bash
# Automated backup script
#!/bin/bash
pg_dump $DATABASE_URL | gzip > /backups/airlock-$(date +%Y%m%d).sql.gz
aws s3 cp /backups/airlock-$(date +%Y%m%d).sql.gz s3://your-backup-bucket/
```

### Configuration Backup
```bash
# Backup Helm values and policies
kubectl get configmap airlock-policy -n mcp-airlock -o yaml > policy-backup.yaml
helm get values mcp-airlock -n mcp-airlock > values-backup.yaml
```

## Maintenance

### Rolling Updates
```bash
# Update to new version
helm upgrade mcp-airlock mcp-airlock/airlock \
  --namespace mcp-airlock \
  --values values-production.yaml \
  --set image.tag=v1.1.0 \
  --wait

# Rollback if needed
helm rollback mcp-airlock --namespace mcp-airlock
```

### Policy Updates
```bash
# Update policy ConfigMap
kubectl apply -f policy-configmap.yaml

# Trigger policy reload
kubectl exec -n mcp-airlock deployment/mcp-airlock -- kill -HUP 1
```

### Certificate Rotation
```bash
# Update TLS certificate
kubectl create secret tls airlock-tls \
  --cert=new-cert.pem \
  --key=new-key.pem \
  --namespace mcp-airlock \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart pods to pick up new certificate
kubectl rollout restart deployment/mcp-airlock -n mcp-airlock
```

## Security Hardening Checklist

- [ ] Pod Security Standards enforced
- [ ] Network policies configured
- [ ] Non-root containers
- [ ] Read-only root filesystem
- [ ] Secrets properly managed
- [ ] TLS certificates from trusted CA
- [ ] Regular security scanning
- [ ] Audit logs encrypted and backed up
- [ ] Monitoring and alerting configured
- [ ] Incident response procedures documented
# Helm Chart Reference

Complete reference for MCP Airlock Helm chart configuration options.

## Chart Information

- **Chart Name**: `airlock`
- **Chart Version**: `1.0.0`
- **App Version**: `1.0.0`
- **Kubernetes Version**: `>=1.24.0`

## Installation

```bash
helm repo add mcp-airlock https://charts.mcp-airlock.io
helm install my-airlock mcp-airlock/airlock --namespace mcp-airlock --create-namespace
```

## Configuration Values

### Global Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.imageRegistry` | Global Docker image registry | `""` |
| `global.imagePullSecrets` | Global image pull secrets | `[]` |
| `global.storageClass` | Global storage class | `""` |

### Image Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Image repository | `mcp-airlock/airlock` |
| `image.tag` | Image tag | `"1.0.0"` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `image.pullSecrets` | Image pull secrets | `[]` |

### Server Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `server.replicas` | Number of replicas | `3` |
| `server.port` | Server port | `8080` |
| `server.resources.requests.cpu` | CPU request | `500m` |
| `server.resources.requests.memory` | Memory request | `512Mi` |
| `server.resources.limits.cpu` | CPU limit | `1000m` |
| `server.resources.limits.memory` | Memory limit | `1Gi` |

### Authentication Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `auth.oidc_issuer` | OIDC issuer URL | `""` |
| `auth.audience` | JWT audience | `"mcp-airlock"` |
| `auth.jwks_cache_ttl` | JWKS cache TTL | `"5m"` |
| `auth.clock_skew` | Clock skew tolerance | `"2m"` |
| `auth.required_groups` | Required user groups | `["mcp.users"]` |

### Policy Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `policy.configMapRef.name` | Policy ConfigMap name | `""` |
| `policy.configMapRef.key` | Policy ConfigMap key | `"policy.rego"` |
| `policy.inline` | Inline policy content | `""` |
| `policy.cache_ttl` | Policy cache TTL | `"1m"` |

### Complete Values Example

```yaml
# values.yaml
image:
  repository: mcp-airlock/airlock
  tag: "1.0.0"
  pullPolicy: IfNotPresent

server:
  replicas: 3
  port: 8080
  
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi
  
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

  podDisruptionBudget:
    enabled: true
    minAvailable: 2

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

policy:
  configMapRef:
    name: airlock-policy
    key: policy.rego
  cache_ttl: "1m"

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

rate_limiting:
  per_token: "200/min"
  per_ip: "1000/min"
  burst: 50

upstreams:
  - name: "docs-server"
    type: "unix"
    socket: "/run/mcp/docs.sock"
    timeout: "30s"
  - name: "code-server"
    type: "stdio"
    command: ["python", "-m", "mcp_server.code"]
    timeout: "30s"

audit:
  backend: "postgresql"
  databaseSecretRef:
    name: airlock-database
    key: url
  retention: "90d"
  export_format: "jsonl"

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
  className: "nginx"
  annotations: {}
  hosts:
    - host: mcp-airlock.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: airlock-tls
      hosts:
        - mcp-airlock.example.com

persistence:
  enabled: true
  storageClass: "gp3"
  size: "100Gi"
  accessMode: ReadWriteOnce

serviceAccount:
  create: true
  annotations: {}
  name: ""

networkPolicy:
  enabled: true
  ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            name: ingress-nginx
      ports:
      - protocol: TCP
        port: 8080
  egress:
    - to: []
      ports:
      - protocol: TCP
        port: 443
      - protocol: TCP
        port: 5432
```
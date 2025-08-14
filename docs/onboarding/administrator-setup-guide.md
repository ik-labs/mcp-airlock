# Administrator Setup Guide

This guide walks administrators through the complete setup process for MCP Airlock, from initial deployment to production readiness.

## Prerequisites

### Infrastructure Requirements

- **Kubernetes Cluster**: Version 1.24+ with Pod Security Standards
- **Helm**: Version 3.8+ for package management
- **kubectl**: Configured to access your Kubernetes cluster
- **Identity Provider**: OIDC-compatible (Okta, Auth0, Azure AD, etc.)
- **Certificate Management**: TLS certificates for HTTPS endpoints
- **Storage**: Persistent volume provisioner for audit logs

### Required Permissions

- Cluster admin access for initial setup
- Namespace admin access for ongoing operations
- Access to identity provider configuration
- DNS management for ingress configuration

## Quick Start (15 minutes)

### 1. Clone Repository and Prepare Environment

```bash
# Clone the repository
git clone https://github.com/your-org/mcp-airlock.git
cd mcp-airlock

# Set environment variables
export AIRLOCK_NAMESPACE="airlock-system"
export AIRLOCK_DOMAIN="airlock.your-company.com"
export OIDC_ISSUER="https://your-idp.com"
```

### 2. Create Namespace and Basic Configuration

```bash
# Create namespace with security labels
kubectl create namespace $AIRLOCK_NAMESPACE
kubectl label namespace $AIRLOCK_NAMESPACE \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# Create basic configuration
cat > values-production.yaml << EOF
global:
  domain: $AIRLOCK_DOMAIN
  namespace: $AIRLOCK_NAMESPACE

auth:
  oidc:
    issuer: $OIDC_ISSUER
    audience: "mcp-airlock"
    
ingress:
  enabled: true
  className: "alb"  # or "nginx", "traefik"
  tls:
    enabled: true
    
monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
EOF
```

### 3. Deploy with Helm

```bash
# Add any required Helm repositories
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update

# Install MCP Airlock
helm install airlock ./helm/airlock \
  -n $AIRLOCK_NAMESPACE \
  -f values-production.yaml \
  --wait --timeout=10m

# Verify deployment
kubectl get pods -n $AIRLOCK_NAMESPACE
kubectl get ingress -n $AIRLOCK_NAMESPACE
```

### 4. Initial Validation

```bash
# Test health endpoints
curl -f https://$AIRLOCK_DOMAIN/live
curl -f https://$AIRLOCK_DOMAIN/ready

# Test authentication (should return 401)
curl -X POST https://$AIRLOCK_DOMAIN/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"test","method":"tools/list"}'
```

## Detailed Configuration

### Identity Provider Setup

#### Okta Configuration

1. **Create Application in Okta**
   ```bash
   # In Okta Admin Console:
   # 1. Applications > Create App Integration
   # 2. Choose "OIDC - OpenID Connect"
   # 3. Choose "Web Application"
   # 4. Configure:
   #    - App integration name: "MCP Airlock"
   #    - Grant types: Authorization Code, Refresh Token
   #    - Sign-in redirect URIs: https://airlock.your-company.com/auth/callback
   #    - Assignments: Assign to appropriate groups
   ```

2. **Configure Groups and Claims**
   ```bash
   # In Okta Admin Console:
   # 1. Security > API > Authorization Servers > default
   # 2. Claims > Add Claim:
   #    - Name: groups
   #    - Include in token type: ID Token
   #    - Value type: Groups
   #    - Filter: Matches regex .*
   #    - Include in: Any scope
   ```

3. **Update Airlock Configuration**
   ```yaml
   auth:
     oidc:
       issuer: "https://your-org.okta.com/oauth2/default"
       audience: "0oa1234567890abcdef"  # Your Okta Client ID
       requiredGroups: ["mcp.users", "developers"]
       clockSkew: "2m"
       jwksCacheTTL: "5m"
   ```

#### Azure AD Configuration

1. **Register Application in Azure AD**
   ```bash
   # In Azure Portal:
   # 1. Azure Active Directory > App registrations > New registration
   # 2. Configure:
   #    - Name: MCP Airlock
   #    - Redirect URI: https://airlock.your-company.com/auth/callback
   #    - Account types: Accounts in this organizational directory only
   ```

2. **Configure API Permissions and Groups**
   ```bash
   # In Azure Portal:
   # 1. API permissions > Add permission > Microsoft Graph
   # 2. Add: User.Read, GroupMember.Read.All
   # 3. Grant admin consent
   # 4. Token configuration > Add groups claim
   ```

3. **Update Airlock Configuration**
   ```yaml
   auth:
     oidc:
       issuer: "https://login.microsoftonline.com/your-tenant-id/v2.0"
       audience: "your-client-id"
       requiredGroups: ["mcp-users", "developers"]
   ```

### Policy Configuration

#### Basic Policy Setup

1. **Create Policy File**
   ```rego
   # policy.rego
   package airlock.authz

   import rego.v1

   # Default deny
   default allow := false

   # Allow if user has required group and tool is permitted
   allow if {
       input.groups[_] == "mcp.users"
       allowed_tool[input.tool]
       allowed_resource[input.resource]
   }

   # Define allowed tools per group
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

   # Define allowed resources with path restrictions
   allowed_resource contains resource if {
       resource := input.resource
       startswith(resource, "mcp://repo/")
       not contains(resource, "../")
   }

   allowed_resource contains resource if {
       resource := input.resource
       startswith(resource, "mcp://artifacts/")
       input.groups[_] == "mcp.writers"
   }
   ```

2. **Create ConfigMap for Policy**
   ```bash
   kubectl create configmap airlock-policy \
     --from-file=policy.rego=policy.rego \
     -n $AIRLOCK_NAMESPACE
   ```

3. **Update Helm Values**
   ```yaml
   policy:
     engine: "opa"
     configMap: "airlock-policy"
     cacheTTL: "1m"
     reloadSignal: "SIGHUP"
   ```

#### Advanced Policy Examples

**Time-based Access Control**
```rego
# Allow access only during business hours
allow if {
    input.groups[_] == "mcp.users"
    allowed_tool[input.tool]
    business_hours
}

business_hours if {
    now := time.now_ns()
    day := time.weekday(now)
    hour := time.clock(now)[0]
    
    # Monday-Friday (1-5), 9 AM - 5 PM
    day >= 1
    day <= 5
    hour >= 9
    hour < 17
}
```

**Resource Quota Enforcement**
```rego
# Enforce resource quotas per tenant
allow if {
    input.groups[_] == "mcp.users"
    allowed_tool[input.tool]
    within_quota
}

within_quota if {
    tenant_usage := data.usage[input.tenant]
    tenant_limit := data.limits[input.tenant]
    tenant_usage < tenant_limit
}
```

### Virtual Root Configuration

#### Filesystem Roots

1. **Configure Filesystem Mounts**
   ```yaml
   roots:
     - name: "documentation"
       type: "fs"
       virtual: "mcp://docs/"
       real: "/mnt/docs"
       readOnly: true
       securityContext:
         runAsNonRoot: true
         readOnlyRootFilesystem: true
   
     - name: "user-workspace"
       type: "fs"
       virtual: "mcp://workspace/"
       real: "/mnt/workspace"
       readOnly: false
       pathSandboxing: true
   ```

2. **Create Persistent Volumes**
   ```bash
   # Create PVC for documentation
   cat > docs-pvc.yaml << EOF
   apiVersion: v1
   kind: PersistentVolumeClaim
   metadata:
     name: airlock-docs
     namespace: $AIRLOCK_NAMESPACE
   spec:
     accessModes:
       - ReadOnlyMany
     resources:
       requests:
         storage: 10Gi
     storageClassName: efs-sc
   EOF
   
   kubectl apply -f docs-pvc.yaml
   ```

#### S3 Integration

1. **Configure S3 Roots**
   ```yaml
   roots:
     - name: "artifacts"
       type: "s3"
       virtual: "mcp://artifacts/"
       real: "s3://your-bucket/artifacts/"
       readOnly: false
       allowedPrefixes:
         - "uploads/"
         - "reports/"
       
   s3:
     region: "us-west-2"
     credentialsSource: "iam"  # or "secret"
     encryption:
       enabled: true
       kmsKeyId: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
   ```

2. **Configure IAM Permissions**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "s3:GetObject",
           "s3:PutObject",
           "s3:DeleteObject",
           "s3:ListBucket"
         ],
         "Resource": [
           "arn:aws:s3:::your-bucket/artifacts/*",
           "arn:aws:s3:::your-bucket"
         ]
       }
     ]
   }
   ```

### DLP and Redaction Configuration

#### Configure Redaction Patterns

1. **Create Redaction Configuration**
   ```yaml
   dlp:
     enabled: true
     patterns:
       - name: "ssn"
         regex: '\b\d{3}-\d{2}-\d{4}\b'
         replace: "[REDACTED-SSN]"
         
       - name: "email"
         regex: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
         replace: "[REDACTED-EMAIL]"
         
       - name: "credit_card"
         regex: '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
         replace: "[REDACTED-CC]"
         
       - name: "bearer_token"
         regex: '(?i)bearer\s+[a-z0-9._-]+'
         replace: "[REDACTED-TOKEN]"
         
       - name: "api_key"
         regex: '(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?[a-z0-9]{20,}["\']?'
         replace: "[REDACTED-API-KEY]"
   
     monitoring:
       enabled: true
       falsePositiveThreshold: 0.05  # 5% false positive budget
   ```

2. **Test Redaction Patterns**
   ```bash
   # Create test script
   cat > test-redaction.sh << EOF
   #!/bin/bash
   
   # Test data with sensitive information
   TEST_DATA='{"user": "john.doe@company.com", "ssn": "123-45-6789", "api_key": "sk_live_abcdef123456789"}'
   
   # Send test request
   curl -X POST https://$AIRLOCK_DOMAIN/mcp \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer \$TEST_TOKEN" \
     -d "{\"jsonrpc\":\"2.0\",\"id\":\"redaction-test\",\"method\":\"tools/call\",\"params\":{\"name\":\"process_data\",\"arguments\":{\"data\":\"$TEST_DATA\"}}}"
   EOF
   
   chmod +x test-redaction.sh
   ./test-redaction.sh
   ```

### Monitoring and Observability

#### Prometheus Integration

1. **Configure ServiceMonitor**
   ```yaml
   monitoring:
     prometheus:
       enabled: true
       serviceMonitor:
         enabled: true
         interval: "30s"
         scrapeTimeout: "10s"
         labels:
           app: "airlock"
           
     metrics:
       enabled: true
       path: "/metrics"
       port: 8080
   ```

2. **Import Grafana Dashboard**
   ```bash
   # Download dashboard JSON
   curl -o airlock-dashboard.json \
     https://raw.githubusercontent.com/your-org/mcp-airlock/main/configs/dashboards/grafana-dashboard.json
   
   # Import to Grafana (via UI or API)
   curl -X POST http://grafana:3000/api/dashboards/db \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $GRAFANA_API_KEY" \
     -d @airlock-dashboard.json
   ```

#### Alert Configuration

1. **Configure AlertManager Rules**
   ```yaml
   # airlock-alerts.yaml
   groups:
     - name: airlock
       rules:
         - alert: AirlockHighErrorRate
           expr: rate(airlock_requests_failed_total[5m]) > 0.1
           for: 2m
           labels:
             severity: warning
           annotations:
             summary: "High error rate in MCP Airlock"
             description: "Error rate is {{ $value }} errors per second"
             
         - alert: AirlockAuthenticationFailures
           expr: rate(airlock_auth_failures_total[5m]) > 0.5
           for: 1m
           labels:
             severity: critical
           annotations:
             summary: "High authentication failure rate"
             description: "Authentication failure rate is {{ $value }} per second"
             
         - alert: AirlockPolicyEngineDown
           expr: airlock_policy_engine_up == 0
           for: 30s
           labels:
             severity: critical
           annotations:
             summary: "Policy engine is down"
             description: "MCP Airlock policy engine is not responding"
   ```

2. **Apply Alert Rules**
   ```bash
   kubectl create configmap airlock-alerts \
     --from-file=airlock-alerts.yaml \
     -n monitoring
   ```

### Backup and Recovery

#### Configure Backup

1. **Audit Log Backup**
   ```yaml
   audit:
     storage:
       type: "sqlite"
       path: "/var/lib/airlock/audit.db"
       backup:
         enabled: true
         schedule: "0 2 * * *"  # Daily at 2 AM
         retention: "30d"
         destination: "s3://backup-bucket/airlock/audit/"
   ```

2. **Configuration Backup**
   ```bash
   # Create backup script
   cat > backup-config.sh << EOF
   #!/bin/bash
   
   BACKUP_DIR="/tmp/airlock-backup-\$(date +%Y%m%d-%H%M%S)"
   mkdir -p \$BACKUP_DIR
   
   # Backup Kubernetes resources
   kubectl get all -n $AIRLOCK_NAMESPACE -o yaml > \$BACKUP_DIR/resources.yaml
   kubectl get configmaps -n $AIRLOCK_NAMESPACE -o yaml > \$BACKUP_DIR/configmaps.yaml
   kubectl get secrets -n $AIRLOCK_NAMESPACE -o yaml > \$BACKUP_DIR/secrets.yaml
   
   # Backup Helm values
   helm get values airlock -n $AIRLOCK_NAMESPACE > \$BACKUP_DIR/helm-values.yaml
   
   # Create archive
   tar -czf airlock-backup-\$(date +%Y%m%d-%H%M%S).tar.gz -C /tmp \$(basename \$BACKUP_DIR)
   
   # Upload to S3 (optional)
   aws s3 cp airlock-backup-*.tar.gz s3://backup-bucket/airlock/config/
   EOF
   
   chmod +x backup-config.sh
   ```

## Upstream MCP Server Configuration

### Sidecar Pattern

1. **Configure Sidecar Deployment**
   ```yaml
   upstreams:
     - name: "docs-server"
       type: "unix"
       socket: "/run/mcp/docs.sock"
       deployment:
         type: "sidecar"
         image: "your-org/docs-mcp-server:latest"
         command: ["python", "-m", "docs_server"]
         env:
           - name: "DOCS_PATH"
             value: "/mnt/docs"
         volumeMounts:
           - name: "mcp-socket"
             mountPath: "/run/mcp"
           - name: "docs-volume"
             mountPath: "/mnt/docs"
   ```

2. **Create Sidecar Container**
   ```dockerfile
   # Dockerfile for docs MCP server
   FROM python:3.11-slim
   
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install -r requirements.txt
   
   COPY docs_server/ ./docs_server/
   
   USER 1000:1000
   CMD ["python", "-m", "docs_server", "--socket", "/run/mcp/docs.sock"]
   ```

### HTTP Service Pattern

1. **Configure HTTP Upstream**
   ```yaml
   upstreams:
     - name: "analytics-server"
       type: "http"
       url: "http://analytics-mcp-server:8080"
       timeout: "30s"
       healthCheck:
         enabled: true
         path: "/health"
         interval: "30s"
   ```

2. **Deploy Separate Service**
   ```yaml
   # analytics-deployment.yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: analytics-mcp-server
     namespace: airlock-system
   spec:
     replicas: 2
     selector:
       matchLabels:
         app: analytics-mcp-server
     template:
       metadata:
         labels:
           app: analytics-mcp-server
       spec:
         containers:
         - name: analytics-server
           image: your-org/analytics-mcp-server:latest
           ports:
           - containerPort: 8080
           env:
           - name: DATABASE_URL
             valueFrom:
               secretKeyRef:
                 name: analytics-db-secret
                 key: url
   ```

## Testing and Validation

### Automated Testing

1. **Create Test Suite**
   ```bash
   # Run integration tests
   cd tests/integration
   go test -v ./... -tags=integration
   
   # Run security tests
   cd ../security
   SECURITY_TESTING=true go test -v ./...
   
   # Run performance tests
   cd ../performance
   go test -v ./... -run=TestPerformance
   ```

2. **Load Testing**
   ```bash
   # Install hey for load testing
   go install github.com/rakyll/hey@latest
   
   # Run load test
   hey -n 1000 -c 10 -H "Authorization: Bearer $TEST_TOKEN" \
     -m POST -D test-request.json \
     https://$AIRLOCK_DOMAIN/mcp
   ```

### Manual Testing

1. **Authentication Flow**
   ```bash
   # Test OIDC flow (manual browser test)
   echo "Visit: https://$AIRLOCK_DOMAIN/auth/login"
   echo "Expected: Redirect to identity provider"
   echo "After login: Redirect back with valid token"
   ```

2. **MCP Tool Testing**
   ```bash
   # Test tool discovery
   curl -X POST https://$AIRLOCK_DOMAIN/mcp \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TEST_TOKEN" \
     -d '{"jsonrpc":"2.0","id":"1","method":"tools/list"}'
   
   # Test tool execution
   curl -X POST https://$AIRLOCK_DOMAIN/mcp \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $TEST_TOKEN" \
     -d '{"jsonrpc":"2.0","id":"2","method":"tools/call","params":{"name":"search_docs","arguments":{"query":"authentication"}}}'
   ```

## Troubleshooting

### Common Issues

#### Pod Startup Issues

**Problem**: Pods stuck in `CrashLoopBackOff`
```bash
# Check logs
kubectl logs -n $AIRLOCK_NAMESPACE -l app.kubernetes.io/name=airlock --previous

# Common causes and solutions:
# 1. Configuration errors - check ConfigMap
kubectl get configmap -n $AIRLOCK_NAMESPACE
kubectl describe configmap airlock-config -n $AIRLOCK_NAMESPACE

# 2. Secret issues - check secrets
kubectl get secrets -n $AIRLOCK_NAMESPACE
kubectl describe secret airlock-tls -n $AIRLOCK_NAMESPACE

# 3. Resource constraints - check limits
kubectl describe pod -n $AIRLOCK_NAMESPACE -l app.kubernetes.io/name=airlock
```

#### Authentication Issues

**Problem**: JWT validation failures
```bash
# Check OIDC configuration
curl -s $OIDC_ISSUER/.well-known/openid-configuration | jq .

# Verify JWKS endpoint
curl -s $OIDC_ISSUER/.well-known/jwks.json | jq .

# Test token manually
echo $JWT_TOKEN | cut -d. -f2 | base64 -d | jq .

# Check Airlock logs for auth errors
kubectl logs -n $AIRLOCK_NAMESPACE -l app.kubernetes.io/name=airlock | grep -i auth
```

#### Policy Issues

**Problem**: Policy evaluation errors
```bash
# Check policy compilation
kubectl logs -n $AIRLOCK_NAMESPACE -l app.kubernetes.io/name=airlock | grep -i policy

# Test policy locally
opa eval -d policy.rego "data.airlock.authz.allow" --input test-input.json

# Validate policy syntax
opa fmt policy.rego
opa test policy.rego policy_test.rego
```

### Performance Issues

**Problem**: High response times
```bash
# Check resource usage
kubectl top pods -n $AIRLOCK_NAMESPACE

# Check metrics
curl -s https://$AIRLOCK_DOMAIN/metrics | grep -E "(request_duration|memory|cpu)"

# Check for resource constraints
kubectl describe pod -n $AIRLOCK_NAMESPACE -l app.kubernetes.io/name=airlock | grep -A 5 -B 5 -i limit
```

### Getting Help

- **Documentation**: Check the [troubleshooting guide](../operations/troubleshooting.md)
- **Logs**: Always include relevant logs when reporting issues
- **Configuration**: Sanitize and include configuration files
- **Environment**: Provide Kubernetes version, Helm version, and cluster details

## Next Steps

After completing the administrator setup:

1. **Developer Onboarding**: Share the [Developer Onboarding Guide](developer-onboarding.md)
2. **User Training**: Conduct training sessions for end users
3. **Monitoring Setup**: Configure dashboards and alerts
4. **Security Review**: Conduct security assessment
5. **Performance Tuning**: Optimize based on actual usage patterns

## Maintenance

### Regular Tasks

- **Weekly**: Review logs and metrics
- **Monthly**: Update security patches, review policies
- **Quarterly**: Capacity planning, security assessment
- **Annually**: Full security audit, disaster recovery testing

### Updates and Upgrades

```bash
# Update Helm chart
helm repo update
helm upgrade airlock ./helm/airlock \
  -n $AIRLOCK_NAMESPACE \
  -f values-production.yaml

# Verify upgrade
kubectl rollout status deployment/airlock -n $AIRLOCK_NAMESPACE
```

For detailed operational procedures, see the [Operations Guide](../operations/README.md).
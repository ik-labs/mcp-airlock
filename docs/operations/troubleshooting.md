# Troubleshooting Guide

This guide provides solutions for common issues encountered with MCP Airlock, organized by category with step-by-step resolution procedures.

## Quick Diagnosis

### Health Check Commands

```bash
# Basic connectivity
curl -f https://airlock.your-company.com/live
curl -f https://airlock.your-company.com/ready

# Service status
kubectl get pods -n airlock-system -l app.kubernetes.io/name=airlock
kubectl get svc -n airlock-system -l app.kubernetes.io/name=airlock

# Recent logs
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock --tail=100

# Resource usage
kubectl top pods -n airlock-system
```

### Common Error Patterns

| Error Pattern | Likely Cause | Quick Fix |
|---------------|--------------|-----------|
| `connection refused` | Service not running | Check pod status |
| `401 Unauthorized` | Authentication issue | Verify token |
| `403 Forbidden` | Policy denial | Check permissions |
| `429 Too Many Requests` | Rate limiting | Implement backoff |
| `500 Internal Server Error` | System error | Check logs |
| `timeout` | Performance issue | Check resources |

## Authentication Issues

### JWT Token Validation Failures

#### Symptoms
- HTTP 401 responses
- "Invalid token" errors
- Authentication logs showing validation failures

#### Diagnosis
```bash
# Check token format and claims
echo $JWT_TOKEN | cut -d. -f2 | base64 -d | jq .

# Verify token expiration
TOKEN_EXP=$(echo $JWT_TOKEN | cut -d. -f2 | base64 -d | jq -r .exp)
CURRENT_TIME=$(date +%s)
echo "Token expires: $(date -d @$TOKEN_EXP)"
echo "Current time: $(date -d @$CURRENT_TIME)"

# Check OIDC configuration
curl -s https://your-idp.com/.well-known/openid-configuration | jq .

# Verify JWKS endpoint
curl -s https://your-idp.com/.well-known/jwks.json | jq .
```

#### Solutions

**Expired Token**
```bash
# Refresh token using OIDC flow
kubelogin get-token \
  --oidc-issuer-url=https://your-idp.com \
  --oidc-client-id=your-client-id \
  --oidc-extra-scope=groups

# Update environment variable
export AIRLOCK_TOKEN="new-token-here"
```

**Invalid Issuer/Audience**
```bash
# Check Airlock configuration
kubectl get configmap airlock-config -n airlock-system -o yaml

# Verify issuer matches IdP
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -i "oidc\|issuer"

# Update configuration if needed
kubectl patch configmap airlock-config -n airlock-system --patch '
data:
  config.yaml: |
    auth:
      oidc:
        issuer: "https://correct-idp.com"
        audience: "correct-client-id"
'
```

**JWKS Fetch Failures**
```bash
# Check network connectivity from pods
kubectl exec -n airlock-system deployment/airlock -- \
  curl -s https://your-idp.com/.well-known/jwks.json

# Check DNS resolution
kubectl exec -n airlock-system deployment/airlock -- \
  nslookup your-idp.com

# Verify firewall/network policies
kubectl get networkpolicy -n airlock-system
```

### OIDC Configuration Issues

#### Symptoms
- "OIDC discovery failed" errors
- "Unable to fetch JWKS" messages
- Inconsistent authentication behavior

#### Diagnosis
```bash
# Test OIDC endpoints manually
curl -v https://your-idp.com/.well-known/openid-configuration
curl -v https://your-idp.com/.well-known/jwks.json

# Check Airlock OIDC configuration
kubectl describe configmap airlock-config -n airlock-system

# Review authentication logs
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -i oidc
```

#### Solutions

**Update OIDC Configuration**
```yaml
# config.yaml
auth:
  oidc:
    issuer: "https://your-idp.com"  # Must match IdP exactly
    audience: "your-client-id"      # Must match registered client
    clockSkew: "2m"                 # Allow for time differences
    jwksCacheTTL: "5m"             # Cache JWKS for performance
    requiredGroups: ["mcp.users"]  # Enforce group membership
```

**Network Connectivity Issues**
```bash
# Add network policy for OIDC access
kubectl apply -f - << EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: airlock-oidc-access
  namespace: airlock-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: airlock
  policyTypes:
  - Egress
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 80
EOF
```

## Authorization and Policy Issues

### Policy Evaluation Failures

#### Symptoms
- HTTP 403 responses with policy denial messages
- "Policy engine unavailable" errors
- Inconsistent access decisions

#### Diagnosis
```bash
# Check policy engine status
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -i policy

# Verify policy configuration
kubectl get configmap airlock-policy -n airlock-system -o yaml

# Test policy locally
opa eval -d policy.rego "data.airlock.authz.allow" --input test-input.json

# Check policy compilation
opa fmt policy.rego
opa test policy.rego policy_test.rego
```

#### Solutions

**Policy Compilation Errors**
```bash
# Validate policy syntax
opa fmt policy.rego

# Fix common syntax issues
# 1. Missing import statements
# 2. Incorrect rule syntax
# 3. Undefined variables

# Test policy with sample input
cat > test-input.json << EOF
{
  "subject": "user@company.com",
  "tenant": "test-tenant",
  "groups": ["mcp.users"],
  "tool": "read_file",
  "resource": "mcp://repo/README.md",
  "method": "GET"
}
EOF

opa eval -d policy.rego "data.airlock.authz.allow" --input test-input.json
```

**Policy Hot-Reload Issues**
```bash
# Trigger policy reload
kubectl exec -n airlock-system deployment/airlock -- kill -HUP 1

# Or use admin endpoint
curl -X POST https://airlock.your-company.com/admin/policy/reload \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Verify reload success
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -i "policy.*reload"
```

**Last-Known-Good Fallback**
```bash
# Check if LKG is active
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -i "last.*known.*good"

# Force policy update
kubectl create configmap airlock-policy-new \
  --from-file=policy.rego=fixed-policy.rego \
  -n airlock-system

kubectl patch deployment airlock -n airlock-system --patch '
spec:
  template:
    spec:
      containers:
      - name: airlock
        env:
        - name: POLICY_CONFIGMAP
          value: "airlock-policy-new"
'
```

### Permission Denied Errors

#### Symptoms
- Users getting 403 errors for allowed operations
- Inconsistent access patterns
- Group membership not recognized

#### Diagnosis
```bash
# Check user token claims
echo $USER_TOKEN | cut -d. -f2 | base64 -d | jq .

# Verify group membership
echo $USER_TOKEN | cut -d. -f2 | base64 -d | jq .groups

# Test policy decision manually
cat > user-input.json << EOF
{
  "subject": "$(echo $USER_TOKEN | cut -d. -f2 | base64 -d | jq -r .sub)",
  "tenant": "$(echo $USER_TOKEN | cut -d. -f2 | base64 -d | jq -r .tid)",
  "groups": $(echo $USER_TOKEN | cut -d. -f2 | base64 -d | jq .groups),
  "tool": "read_file",
  "resource": "mcp://repo/README.md"
}
EOF

opa eval -d policy.rego "data.airlock.authz.allow" --input user-input.json
```

#### Solutions

**Update Group Mappings**
```rego
# policy.rego - Add missing group mappings
allowed_tool contains tool if {
    tool := input.tool
    tool in ["read_file", "search_docs"]
    input.groups[_] == "developers"  # Add missing group
}
```

**Fix IdP Group Claims**
```bash
# In your IdP (Okta example):
# 1. Go to Applications > Your App > Sign On
# 2. Edit OIDC Settings
# 3. Add groups claim to ID token
# 4. Ensure groups are included in token

# Verify groups in token
curl -X POST https://airlock.your-company.com/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"debug","method":"debug/token"}' | jq .
```

## Performance Issues

### High Response Times

#### Symptoms
- Requests taking > 1 second
- Timeouts on normal operations
- Users reporting slow performance

#### Diagnosis
```bash
# Check resource usage
kubectl top pods -n airlock-system

# Review performance metrics
curl -s https://airlock.your-company.com/metrics | grep -E "(duration|latency)"

# Check for resource constraints
kubectl describe pod -n airlock-system -l app.kubernetes.io/name=airlock | grep -A 5 -B 5 -i limit

# Analyze request patterns
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -E "(duration|latency)" | tail -20
```

#### Solutions

**Increase Resource Limits**
```yaml
# values.yaml
resources:
  limits:
    cpu: "2000m"      # Increase from 1000m
    memory: "1Gi"     # Increase from 512Mi
  requests:
    cpu: "500m"
    memory: "256Mi"
```

**Optimize Policy Evaluation**
```rego
# Optimize policy rules for performance
package airlock.authz

import rego.v1

# Use indexed lookups instead of iterations
allowed_tools := {
    "mcp.users": ["read_file", "search_docs"],
    "developers": ["read_file", "write_file", "analyze_code"]
}

allow if {
    user_tools := allowed_tools[input.groups[_]]
    input.tool in user_tools
}
```

**Enable Caching**
```yaml
# config.yaml
policy:
  cacheTTL: "5m"        # Cache policy decisions
  cacheSize: 10000      # Increase cache size

auth:
  jwksCacheTTL: "10m"   # Cache JWKS longer
```

### Memory Issues

#### Symptoms
- Pods being OOMKilled
- High memory usage in metrics
- Performance degradation over time

#### Diagnosis
```bash
# Check memory usage trends
kubectl top pods -n airlock-system --containers

# Look for memory limit hits
kubectl get events -n airlock-system | grep -i memory

# Check for memory leaks
kubectl exec -n airlock-system deployment/airlock -- \
  curl -s localhost:6060/debug/pprof/heap > heap.prof

# Analyze with go tool pprof
go tool pprof heap.prof
```

#### Solutions

**Increase Memory Limits**
```yaml
resources:
  limits:
    memory: "2Gi"     # Increase limit
  requests:
    memory: "512Mi"   # Increase request
```

**Optimize Memory Usage**
```yaml
# config.yaml
audit:
  bufferSize: 1000    # Reduce buffer size
  flushInterval: "30s" # Flush more frequently

policy:
  cacheSize: 5000     # Reduce cache size if needed
```

**Enable Memory Profiling**
```yaml
# Enable pprof endpoint for debugging
server:
  debug:
    enabled: true
    port: 6060
```

## Connectivity Issues

### Upstream Server Connection Failures

#### Symptoms
- "Connection refused" to upstream servers
- Timeouts when calling MCP tools
- Intermittent connectivity issues

#### Diagnosis
```bash
# Check upstream server status
kubectl get pods -n airlock-system -l app=upstream-server

# Test connectivity from Airlock pod
kubectl exec -n airlock-system deployment/airlock -- \
  nc -zv upstream-server 8080

# Check service discovery
kubectl get svc -n airlock-system
kubectl get endpoints -n airlock-system

# Review upstream configuration
kubectl get configmap airlock-config -n airlock-system -o yaml | grep -A 10 upstreams
```

#### Solutions

**Fix Service Configuration**
```yaml
# Correct upstream configuration
upstreams:
  - name: "docs-server"
    type: "http"
    url: "http://docs-server.airlock-system.svc.cluster.local:8080"
    timeout: "30s"
    healthCheck:
      enabled: true
      path: "/health"
      interval: "30s"
```

**Network Policy Issues**
```bash
# Allow traffic to upstream services
kubectl apply -f - << EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: airlock-upstream-access
  namespace: airlock-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: airlock
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: upstream-server
    ports:
    - protocol: TCP
      port: 8080
EOF
```

### TLS/Certificate Issues

#### Symptoms
- "Certificate verification failed" errors
- TLS handshake failures
- Browser certificate warnings

#### Diagnosis
```bash
# Check certificate validity
openssl s_client -connect airlock.your-company.com:443 -servername airlock.your-company.com

# Verify certificate chain
curl -vI https://airlock.your-company.com/live

# Check certificate in Kubernetes
kubectl get secret airlock-tls -n airlock-system -o yaml

# Decode certificate
kubectl get secret airlock-tls -n airlock-system -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout
```

#### Solutions

**Update Certificate**
```bash
# Create new certificate secret
kubectl create secret tls airlock-tls-new \
  --cert=new-cert.pem \
  --key=new-key.pem \
  -n airlock-system

# Update ingress to use new certificate
kubectl patch ingress airlock -n airlock-system --patch '
spec:
  tls:
  - hosts:
    - airlock.your-company.com
    secretName: airlock-tls-new
'
```

**Certificate Auto-Renewal**
```yaml
# cert-manager Certificate resource
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: airlock-tls
  namespace: airlock-system
spec:
  secretName: airlock-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
  - airlock.your-company.com
```

## Data and Storage Issues

### Audit Log Storage Problems

#### Symptoms
- "Audit storage unavailable" errors
- Missing audit entries
- Disk space warnings

#### Diagnosis
```bash
# Check PVC status
kubectl get pvc -n airlock-system

# Check disk usage
kubectl exec -n airlock-system deployment/airlock -- df -h /var/lib/airlock

# Review audit configuration
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -i audit

# Check SQLite database
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db ".schema"
```

#### Solutions

**Expand Storage**
```bash
# Increase PVC size
kubectl patch pvc airlock-audit -n airlock-system --patch '
spec:
  resources:
    requests:
      storage: 20Gi
'
```

**Configure Retention**
```yaml
# config.yaml
audit:
  retention: "7d"       # Reduce retention period
  cleanup:
    enabled: true
    schedule: "0 2 * * *"  # Daily cleanup at 2 AM
```

**Enable S3 Export**
```yaml
audit:
  export:
    enabled: true
    format: "jsonl"
    destination: "s3://audit-bucket/airlock/"
    schedule: "0 1 * * *"  # Daily export at 1 AM
```

### Virtual Root Access Issues

#### Symptoms
- "Path not found" errors
- Permission denied on file access
- Path traversal security violations

#### Diagnosis
```bash
# Check root mappings
kubectl get configmap airlock-config -n airlock-system -o yaml | grep -A 20 roots

# Test path resolution
kubectl exec -n airlock-system deployment/airlock -- \
  ls -la /mnt/repo

# Check mount points
kubectl exec -n airlock-system deployment/airlock -- mount | grep /mnt

# Review security violations
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -i "path.*traversal"
```

#### Solutions

**Fix Mount Configuration**
```yaml
# Correct volume mounts in deployment
volumeMounts:
- name: repo-volume
  mountPath: /mnt/repo
  readOnly: true
- name: workspace-volume
  mountPath: /mnt/workspace
  readOnly: false

volumes:
- name: repo-volume
  persistentVolumeClaim:
    claimName: repo-pvc
- name: workspace-volume
  persistentVolumeClaim:
    claimName: workspace-pvc
```

**Update Root Mappings**
```yaml
# config.yaml
roots:
  - name: "repository"
    type: "fs"
    virtual: "mcp://repo/"
    real: "/mnt/repo"
    readOnly: true
    pathSandboxing: true
```

## Monitoring and Alerting Issues

### Missing Metrics

#### Symptoms
- Grafana dashboards showing no data
- Prometheus not scraping metrics
- Missing alerts

#### Diagnosis
```bash
# Check metrics endpoint
curl -s https://airlock.your-company.com/metrics

# Verify ServiceMonitor
kubectl get servicemonitor -n airlock-system

# Check Prometheus targets
curl -s http://prometheus:9090/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job=="airlock")'

# Review Prometheus configuration
kubectl get prometheus -o yaml
```

#### Solutions

**Fix ServiceMonitor**
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: airlock
  namespace: airlock-system
  labels:
    app.kubernetes.io/name: airlock
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: airlock
  endpoints:
  - port: http-metrics
    interval: 30s
    path: /metrics
```

**Update Prometheus Config**
```yaml
# Ensure namespace is monitored
spec:
  serviceMonitorNamespaceSelector:
    matchLabels:
      name: airlock-system
```

### Alert Fatigue

#### Symptoms
- Too many alerts firing
- Important alerts being ignored
- Alert storms during incidents

#### Solutions

**Tune Alert Thresholds**
```yaml
# Adjust alert sensitivity
- alert: AirlockHighErrorRate
  expr: rate(airlock_requests_failed_total[5m]) > 0.05  # Increase threshold
  for: 5m  # Increase duration

- alert: AirlockHighLatency
  expr: histogram_quantile(0.95, airlock_request_duration_seconds_bucket) > 0.1  # Increase threshold
  for: 2m
```

**Implement Alert Grouping**
```yaml
# alertmanager.yml
route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h
```

## Emergency Procedures

### Service Outage Response

#### Immediate Actions
1. **Assess Impact**
   ```bash
   # Check service status
   kubectl get pods -n airlock-system
   curl -f https://airlock.your-company.com/live
   ```

2. **Gather Information**
   ```bash
   # Collect logs
   kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock --previous > airlock-logs.txt
   
   # Get events
   kubectl get events -n airlock-system --sort-by='.lastTimestamp' > events.txt
   
   # Check resource usage
   kubectl top pods -n airlock-system > resource-usage.txt
   ```

3. **Implement Workarounds**
   ```bash
   # Scale up replicas
   kubectl scale deployment airlock -n airlock-system --replicas=3
   
   # Restart pods
   kubectl rollout restart deployment/airlock -n airlock-system
   ```

### Rollback Procedures

#### Helm Rollback
```bash
# List releases
helm list -n airlock-system

# Check rollback history
helm history airlock -n airlock-system

# Rollback to previous version
helm rollback airlock -n airlock-system

# Verify rollback
kubectl get pods -n airlock-system -l app.kubernetes.io/name=airlock
```

#### Configuration Rollback
```bash
# Restore previous configuration
kubectl apply -f backup-config.yaml -n airlock-system

# Restart to pick up changes
kubectl rollout restart deployment/airlock -n airlock-system
```

### Data Recovery

#### Audit Log Recovery
```bash
# Restore from backup
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db ".restore /backup/audit-backup.db"

# Verify integrity
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db "PRAGMA integrity_check;"
```

## Prevention and Best Practices

### Monitoring Best Practices

1. **Set Up Comprehensive Monitoring**
   - Monitor all key metrics (latency, errors, throughput)
   - Set up alerts for critical conditions
   - Use dashboards for operational visibility

2. **Implement Health Checks**
   - Configure liveness and readiness probes
   - Monitor dependency health
   - Set up synthetic monitoring

3. **Log Management**
   - Centralize log collection
   - Set up log retention policies
   - Implement log analysis and alerting

### Operational Best Practices

1. **Regular Maintenance**
   - Update security patches monthly
   - Review and update policies quarterly
   - Conduct disaster recovery tests annually

2. **Change Management**
   - Use staging environments for testing
   - Implement gradual rollouts
   - Maintain rollback procedures

3. **Documentation**
   - Keep runbooks up to date
   - Document all procedures
   - Maintain incident post-mortems

### Security Best Practices

1. **Access Control**
   - Use least privilege principles
   - Regularly review permissions
   - Implement multi-factor authentication

2. **Network Security**
   - Use network policies
   - Implement TLS everywhere
   - Regular security assessments

3. **Data Protection**
   - Encrypt data at rest and in transit
   - Implement proper backup procedures
   - Regular compliance audits

## Getting Additional Help

### Internal Resources
- **Documentation**: Check the complete documentation set
- **Logs**: Always include relevant logs when reporting issues
- **Metrics**: Use monitoring dashboards for diagnosis

### External Resources
- **Kubernetes Documentation**: For cluster-related issues
- **Helm Documentation**: For deployment issues
- **OPA Documentation**: For policy-related issues

### Escalation Procedures
1. **Level 1**: Check this troubleshooting guide
2. **Level 2**: Contact your system administrator
3. **Level 3**: Engage vendor support with detailed information

---

**Remember**: When in doubt, check the logs first. Most issues can be diagnosed from the application logs combined with Kubernetes events and metrics.
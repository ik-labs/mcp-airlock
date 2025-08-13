# Troubleshooting Runbook

This runbook covers common operational issues and their solutions for MCP Airlock.

## Quick Diagnosis

### 1. Check Overall Health
```bash
# Pod status
kubectl get pods -n mcp-airlock

# Service status
kubectl get svc -n mcp-airlock

# Ingress status
kubectl get ingress -n mcp-airlock

# Recent events
kubectl get events -n mcp-airlock --sort-by='.lastTimestamp'
```

### 2. Check Application Health
```bash
# Health endpoints
curl https://your-airlock-domain/health/live
curl https://your-airlock-domain/health/ready

# Metrics endpoint
curl https://your-airlock-domain/metrics
```

## Common Issues

### Authentication Issues

#### Symptom: 401 Unauthorized responses
```json
{
  "error": {
    "code": "InvalidRequest",
    "message": "Authentication failed",
    "data": {
      "reason": "invalid_token",
      "www_authenticate": "Bearer realm=\"mcp-airlock\"",
      "correlation_id": "abc123"
    }
  }
}
```

**Diagnosis:**
```bash
# Check OIDC configuration
kubectl get secret airlock-oidc -n mcp-airlock -o yaml

# Check JWKS cache status in logs
kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock | grep "jwks"

# Test OIDC endpoint connectivity
kubectl exec -n mcp-airlock deployment/mcp-airlock -- \
  curl -v https://your-oidc-provider/.well-known/openid-configuration
```

**Solutions:**
1. **Invalid OIDC configuration:**
   ```bash
   # Update OIDC secret
   kubectl create secret generic airlock-oidc \
     --namespace mcp-airlock \
     --from-literal=issuer="https://correct-issuer.com" \
     --dry-run=client -o yaml | kubectl apply -f -
   
   # Restart pods
   kubectl rollout restart deployment/mcp-airlock -n mcp-airlock
   ```

2. **JWKS fetch failure:**
   ```bash
   # Check network connectivity
   kubectl exec -n mcp-airlock deployment/mcp-airlock -- \
     nslookup your-oidc-provider.com
   
   # Force JWKS refresh
   kubectl exec -n mcp-airlock deployment/mcp-airlock -- \
     kill -USR1 1
   ```

3. **Clock skew issues:**
   ```bash
   # Check pod time
   kubectl exec -n mcp-airlock deployment/mcp-airlock -- date
   
   # Compare with OIDC provider time
   curl -I https://your-oidc-provider.com
   ```

#### Symptom: Token validation errors
```bash
# Check token claims
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." | base64 -d | jq .

# Verify token hasn't expired
date -d @$(echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." | base64 -d | jq -r .exp)
```

### Policy Issues

#### Symptom: 403 Forbidden responses
```json
{
  "error": {
    "code": "Forbidden",
    "message": "Policy denied request",
    "data": {
      "reason": "tool 'read_file' not allowed",
      "rule_id": "airlock.authz.allowed_tool",
      "tenant": "tenant-123",
      "correlation_id": "def456"
    }
  }
}
```

**Diagnosis:**
```bash
# Check current policy
kubectl get configmap airlock-policy -n mcp-airlock -o yaml

# Check policy compilation logs
kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock | grep "policy"

# Test policy evaluation
kubectl exec -n mcp-airlock deployment/mcp-airlock -- \
  opa eval -d /etc/policy/policy.rego "data.airlock.authz.allow" \
  --input '{"sub":"user@example.com","groups":["mcp.users"],"tool":"read_file"}'
```

**Solutions:**
1. **Policy compilation error:**
   ```bash
   # Validate policy syntax
   opa fmt configs/policy.rego
   opa test configs/policy.rego
   
   # Update policy ConfigMap
   kubectl create configmap airlock-policy \
     --from-file=policy.rego=configs/policy.rego \
     --namespace mcp-airlock \
     --dry-run=client -o yaml | kubectl apply -f -
   
   # Reload policy
   kubectl exec -n mcp-airlock deployment/mcp-airlock -- kill -HUP 1
   ```

2. **User missing required groups:**
   ```bash
   # Check user's JWT claims
   echo $JWT_TOKEN | jwt decode -
   
   # Update policy to include user's groups
   # Or update user's groups in OIDC provider
   ```

### Upstream Connection Issues

#### Symptom: 502 Bad Gateway responses
```json
{
  "error": {
    "code": "InternalError",
    "message": "Upstream server error",
    "data": {
      "upstream_status": "connection_refused",
      "correlation_id": "ghi789"
    }
  }
}
```

**Diagnosis:**
```bash
# Check upstream configuration
kubectl get configmap airlock-config -n mcp-airlock -o yaml | grep -A 10 upstreams

# Check if upstream services are running
kubectl get pods -n mcp-airlock -l app=mcp-server

# Test upstream connectivity
kubectl exec -n mcp-airlock deployment/mcp-airlock -- \
  nc -zv mcp-server-service 8080
```

**Solutions:**
1. **Upstream service down:**
   ```bash
   # Check upstream pod logs
   kubectl logs -n mcp-airlock -l app=mcp-server
   
   # Restart upstream service
   kubectl rollout restart deployment/mcp-server -n mcp-airlock
   ```

2. **Network connectivity issues:**
   ```bash
   # Check network policies
   kubectl get networkpolicy -n mcp-airlock
   
   # Test DNS resolution
   kubectl exec -n mcp-airlock deployment/mcp-airlock -- \
     nslookup mcp-server-service.mcp-airlock.svc.cluster.local
   ```

### Performance Issues

#### Symptom: High latency (p95 > 100ms)
**Diagnosis:**
```bash
# Check metrics
curl https://your-airlock-domain/metrics | grep airlock_request_duration

# Check resource usage
kubectl top pods -n mcp-airlock

# Check for CPU throttling
kubectl describe pods -n mcp-airlock | grep -A 5 -B 5 throttl
```

**Solutions:**
1. **Resource constraints:**
   ```bash
   # Increase resource limits
   kubectl patch deployment mcp-airlock -n mcp-airlock -p '
   {
     "spec": {
       "template": {
         "spec": {
           "containers": [{
             "name": "airlock",
             "resources": {
               "limits": {"cpu": "1000m", "memory": "1Gi"},
               "requests": {"cpu": "500m", "memory": "512Mi"}
             }
           }]
         }
       }
     }
   }'
   ```

2. **Scale horizontally:**
   ```bash
   # Increase replica count
   kubectl scale deployment mcp-airlock -n mcp-airlock --replicas=5
   
   # Enable HPA if not already enabled
   kubectl autoscale deployment mcp-airlock -n mcp-airlock \
     --cpu-percent=70 --min=3 --max=10
   ```

#### Symptom: High memory usage
**Diagnosis:**
```bash
# Check memory metrics
kubectl top pods -n mcp-airlock

# Check for memory leaks in logs
kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock | grep -i "memory\|oom"

# Get heap profile
kubectl port-forward -n mcp-airlock deployment/mcp-airlock 6060:6060
curl http://localhost:6060/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

### Audit System Issues

#### Symptom: Audit storage failures
```bash
# Check audit logs
kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock | grep "audit"

# Check database connectivity
kubectl exec -n mcp-airlock deployment/mcp-airlock -- \
  pg_isready -h $DB_HOST -p $DB_PORT -U $DB_USER
```

**Solutions:**
1. **Database connection issues:**
   ```bash
   # Check database secret
   kubectl get secret airlock-database -n mcp-airlock -o yaml
   
   # Test database connection
   kubectl run -it --rm debug --image=postgres:13 --restart=Never -- \
     psql $DATABASE_URL -c "SELECT 1;"
   ```

2. **Disk space issues (SQLite):**
   ```bash
   # Check PVC usage
   kubectl exec -n mcp-airlock deployment/mcp-airlock -- df -h /var/lib/airlock
   
   # Clean up old audit logs
   kubectl exec -n mcp-airlock deployment/mcp-airlock -- \
     find /var/lib/airlock -name "*.db-wal" -mtime +7 -delete
   ```

### TLS/Certificate Issues

#### Symptom: TLS handshake failures
**Diagnosis:**
```bash
# Check certificate validity
openssl s_client -connect your-airlock-domain:443 -servername your-airlock-domain

# Check certificate in Kubernetes
kubectl get secret airlock-tls -n mcp-airlock -o yaml | \
  grep tls.crt | awk '{print $2}' | base64 -d | \
  openssl x509 -text -noout
```

**Solutions:**
1. **Certificate expired:**
   ```bash
   # Renew certificate (example with cert-manager)
   kubectl delete certificaterequest -n mcp-airlock --all
   kubectl annotate certificate airlock-tls -n mcp-airlock \
     cert-manager.io/issue-temporary-certificate-
   ```

2. **Certificate mismatch:**
   ```bash
   # Update certificate with correct SAN
   # This depends on your certificate provider
   ```

## Escalation Procedures

### Severity Levels

**P0 - Critical (Service Down)**
- Complete service outage
- Security breach
- Data loss

**Actions:**
1. Page on-call engineer immediately
2. Create incident in PagerDuty
3. Notify security team if security-related
4. Begin incident response procedures

**P1 - High (Degraded Service)**
- High error rates (>5%)
- High latency (p95 >200ms)
- Authentication issues affecting multiple users

**Actions:**
1. Create incident ticket
2. Notify on-call engineer
3. Begin troubleshooting
4. Update status page

**P2 - Medium (Minor Issues)**
- Individual user issues
- Non-critical feature failures
- Performance degradation <5% users

**Actions:**
1. Create support ticket
2. Investigate during business hours
3. Document in knowledge base

### Emergency Procedures

#### Complete Service Outage
1. **Immediate Response (0-5 minutes):**
   ```bash
   # Check basic infrastructure
   kubectl get nodes
   kubectl get pods -n mcp-airlock
   kubectl get events -n mcp-airlock --sort-by='.lastTimestamp'
   ```

2. **Quick Recovery Attempts (5-15 minutes):**
   ```bash
   # Restart deployment
   kubectl rollout restart deployment/mcp-airlock -n mcp-airlock
   
   # Scale up if resource constrained
   kubectl scale deployment mcp-airlock -n mcp-airlock --replicas=5
   
   # Check ingress
   kubectl get ingress -n mcp-airlock
   ```

3. **Detailed Investigation (15+ minutes):**
   ```bash
   # Collect logs
   kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock --previous
   
   # Check resource usage
   kubectl top nodes
   kubectl top pods -n mcp-airlock
   
   # Check external dependencies
   curl -v https://your-oidc-provider/.well-known/openid-configuration
   ```

#### Security Incident
1. **Immediate Actions:**
   - Isolate affected systems
   - Preserve logs and evidence
   - Notify security team
   - Document timeline

2. **Investigation:**
   ```bash
   # Check audit logs for suspicious activity
   kubectl exec -n mcp-airlock deployment/mcp-airlock -- \
     sqlite3 /var/lib/airlock/audit.db \
     "SELECT * FROM audit_events WHERE timestamp > datetime('now', '-1 hour') ORDER BY timestamp DESC;"
   
   # Check authentication failures
   kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock | \
     grep "authentication_failed" | tail -100
   ```

3. **Recovery:**
   - Apply security patches
   - Rotate credentials
   - Update policies
   - Monitor for continued threats

## Monitoring and Alerting

### Key Metrics to Monitor

1. **Request Rate and Errors:**
   - `airlock_requests_total`
   - `airlock_request_duration_seconds`
   - `airlock_errors_total`

2. **Authentication:**
   - `airlock_auth_attempts_total`
   - `airlock_auth_success_total`
   - `airlock_auth_failures_total`

3. **Policy Decisions:**
   - `airlock_policy_decisions_total`
   - `airlock_policy_evaluation_duration_seconds`

4. **System Health:**
   - `airlock_upstream_connections`
   - `airlock_audit_events_total`
   - `airlock_memory_usage_bytes`

### Alert Thresholds

```yaml
# High error rate
rate(airlock_errors_total[5m]) > 0.05

# High latency
histogram_quantile(0.95, rate(airlock_request_duration_seconds_bucket[5m])) > 0.1

# Authentication failures
rate(airlock_auth_failures_total[5m]) > 0.1

# Audit system failures
increase(airlock_audit_errors_total[5m]) > 0

# Memory usage
airlock_memory_usage_bytes / airlock_memory_limit_bytes > 0.9
```

## Log Analysis

### Log Formats
All logs are structured JSON with these common fields:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "info",
  "msg": "request processed",
  "correlation_id": "abc123",
  "tenant": "tenant-1",
  "user": "user@example.com",
  "tool": "read_file",
  "decision": "allow",
  "latency_ms": 45
}
```

### Useful Log Queries
```bash
# Find all requests for a specific user
kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock | \
  jq 'select(.user == "user@example.com")'

# Find all policy denials
kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock | \
  jq 'select(.decision == "deny")'

# Find high-latency requests
kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock | \
  jq 'select(.latency_ms > 100)'

# Trace a specific request
kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock | \
  jq 'select(.correlation_id == "abc123")'
```
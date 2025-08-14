# Production Deployment Checklist

This checklist ensures that MCP Airlock is properly configured and secured for production deployment.

## Pre-Deployment Checklist

### Infrastructure Requirements

- [ ] **Kubernetes Cluster**
  - [ ] Kubernetes version 1.24+ with Pod Security Standards enabled
  - [ ] Network policies supported and enabled
  - [ ] Persistent volume provisioner configured
  - [ ] Ingress controller deployed (ALB, NGINX, or Traefik)
  - [ ] Certificate management configured (cert-manager or manual)

- [ ] **Resource Planning**
  - [ ] CPU and memory requirements calculated based on expected load
  - [ ] Storage requirements planned for audit logs and configuration
  - [ ] Network bandwidth requirements assessed
  - [ ] Backup and disaster recovery strategy defined

- [ ] **Security Infrastructure**
  - [ ] OIDC/OAuth2 identity provider configured
  - [ ] TLS certificates obtained and validated
  - [ ] Network security groups/firewalls configured
  - [ ] Secrets management solution deployed (Kubernetes secrets, Vault, etc.)

### Configuration Preparation

- [ ] **Helm Values Configuration**
  - [ ] Production values file created from template
  - [ ] Resource limits and requests configured
  - [ ] Replica count set based on availability requirements
  - [ ] Ingress configuration completed
  - [ ] TLS configuration validated

- [ ] **Security Configuration**
  - [ ] OIDC issuer URL and audience configured
  - [ ] JWT validation parameters set (clock skew, cache TTL)
  - [ ] Policy files prepared and validated
  - [ ] DLP redaction patterns configured
  - [ ] Rate limiting parameters tuned

- [ ] **Monitoring Configuration**
  - [ ] Prometheus ServiceMonitor configured
  - [ ] Grafana dashboards imported
  - [ ] Alert rules configured in AlertManager
  - [ ] Log aggregation configured (ELK, Loki, etc.)

## Deployment Process

### Initial Deployment

- [ ] **Namespace Preparation**
  ```bash
  kubectl create namespace airlock-system
  kubectl label namespace airlock-system pod-security.kubernetes.io/enforce=restricted
  ```

- [ ] **Secret Creation**
  ```bash
  # Create TLS secrets
  kubectl create secret tls airlock-tls \
    --cert=path/to/tls.crt \
    --key=path/to/tls.key \
    -n airlock-system

  # Create configuration secrets
  kubectl create secret generic airlock-config \
    --from-file=policy.rego=path/to/policy.rego \
    --from-file=config.yaml=path/to/config.yaml \
    -n airlock-system
  ```

- [ ] **Helm Deployment**
  ```bash
  helm install airlock ./helm/airlock \
    -n airlock-system \
    -f values-production.yaml \
    --wait --timeout=10m
  ```

- [ ] **Deployment Verification**
  ```bash
  # Check pod status
  kubectl get pods -n airlock-system -l app.kubernetes.io/name=airlock

  # Check service status
  kubectl get svc -n airlock-system -l app.kubernetes.io/name=airlock

  # Check ingress status
  kubectl get ingress -n airlock-system
  ```

### Post-Deployment Validation

- [ ] **Health Check Validation**
  ```bash
  # Test liveness endpoint
  curl -f https://airlock.example.com/live

  # Test readiness endpoint
  curl -f https://airlock.example.com/ready

  # Test info endpoint
  curl -s https://airlock.example.com/info | jq .
  ```

- [ ] **Authentication Testing**
  ```bash
  # Test unauthenticated request (should return 401)
  curl -X POST https://airlock.example.com/mcp \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":"test","method":"tools/list"}'

  # Test authenticated request
  curl -X POST https://airlock.example.com/mcp \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TEST_TOKEN" \
    -d '{"jsonrpc":"2.0","id":"test","method":"tools/list"}'
  ```

- [ ] **TLS Configuration Validation**
  ```bash
  # Test TLS configuration
  openssl s_client -connect airlock.example.com:443 -servername airlock.example.com

  # Test cipher suites
  nmap --script ssl-enum-ciphers -p 443 airlock.example.com
  ```

## Security Validation

### Authentication and Authorization

- [ ] **JWT Validation**
  - [ ] OIDC discovery endpoint accessible
  - [ ] JWKS endpoint returns valid keys
  - [ ] Token validation working with correct issuer/audience
  - [ ] Clock skew tolerance configured appropriately
  - [ ] Token expiration handling working

- [ ] **Policy Engine**
  - [ ] Policy compilation successful
  - [ ] Test policy decisions for various scenarios
  - [ ] Policy hot-reload functionality working
  - [ ] Last-Known-Good fallback tested
  - [ ] Policy decision caching working

- [ ] **Rate Limiting**
  - [ ] Per-token rate limits enforced
  - [ ] Per-IP rate limits enforced (if configured)
  - [ ] Rate limit headers returned correctly
  - [ ] Brute force protection working

### Data Protection

- [ ] **DLP Redaction**
  - [ ] Redaction patterns loaded successfully
  - [ ] Test redaction on sample sensitive data
  - [ ] Redaction count tracking working
  - [ ] Performance impact within acceptable limits

- [ ] **Root Virtualization**
  - [ ] Virtual root mappings configured correctly
  - [ ] Path traversal protection working
  - [ ] Read-only enforcement working
  - [ ] S3 integration working (if configured)

- [ ] **Audit Logging**
  - [ ] Audit events being generated
  - [ ] Hash chaining working correctly
  - [ ] Audit storage working (SQLite/PostgreSQL)
  - [ ] Retention policies configured
  - [ ] Export functionality working

### Network Security

- [ ] **Network Policies**
  - [ ] Ingress rules allowing only necessary traffic
  - [ ] Egress rules restricting outbound connections
  - [ ] Pod-to-pod communication restricted appropriately
  - [ ] DNS resolution working for required services

- [ ] **TLS Security**
  - [ ] TLS 1.2+ enforced
  - [ ] Strong cipher suites configured
  - [ ] Certificate chain valid
  - [ ] HSTS headers configured
  - [ ] HTTP to HTTPS redirect working

## Performance Validation

### Load Testing

- [ ] **Baseline Performance**
  ```bash
  # Run load test
  hey -n 1000 -c 10 -H "Authorization: Bearer $TEST_TOKEN" \
    -m POST -D test-request.json \
    https://airlock.example.com/mcp
  ```

- [ ] **Performance Metrics**
  - [ ] p95 response time < 60ms for simple requests
  - [ ] Throughput ≥ 1000 messages/minute
  - [ ] Memory usage stable under load
  - [ ] CPU usage within limits
  - [ ] No memory leaks detected

- [ ] **Stress Testing**
  - [ ] System handles expected peak load
  - [ ] Graceful degradation under overload
  - [ ] Recovery after load reduction
  - [ ] Rate limiting prevents system overload

### Resource Monitoring

- [ ] **Kubernetes Resources**
  - [ ] Pod resource limits appropriate
  - [ ] HPA scaling working correctly
  - [ ] PVC storage sufficient
  - [ ] Network bandwidth adequate

- [ ] **Application Metrics**
  - [ ] Prometheus metrics being collected
  - [ ] Grafana dashboards showing data
  - [ ] Alert rules firing appropriately
  - [ ] Log aggregation working

## Operational Readiness

### Monitoring and Alerting

- [ ] **Health Monitoring**
  - [ ] Liveness and readiness probes configured
  - [ ] Service health alerts configured
  - [ ] Dependency health monitoring
  - [ ] Performance degradation alerts

- [ ] **Security Monitoring**
  - [ ] Authentication failure alerts
  - [ ] Authorization violation alerts
  - [ ] Rate limiting alerts
  - [ ] Security violation alerts
  - [ ] Audit system failure alerts

- [ ] **Business Monitoring**
  - [ ] Request volume monitoring
  - [ ] Error rate monitoring
  - [ ] Response time monitoring
  - [ ] User activity monitoring

### Backup and Recovery

- [ ] **Data Backup**
  - [ ] Audit log backup configured
  - [ ] Configuration backup automated
  - [ ] Persistent volume backup working
  - [ ] Backup retention policy configured

- [ ] **Disaster Recovery**
  - [ ] Recovery procedures documented
  - [ ] RTO/RPO requirements defined
  - [ ] Backup restoration tested
  - [ ] Failover procedures tested

### Documentation and Training

- [ ] **Operational Documentation**
  - [ ] Deployment procedures documented
  - [ ] Configuration management documented
  - [ ] Troubleshooting guide available
  - [ ] Incident response procedures defined

- [ ] **Team Training**
  - [ ] Operations team trained on system
  - [ ] Security team briefed on controls
  - [ ] Development team understands integration
  - [ ] On-call procedures established

## Go-Live Checklist

### Final Validation

- [ ] **End-to-End Testing**
  - [ ] Complete user workflow tested
  - [ ] All MCP tools accessible
  - [ ] Error handling working correctly
  - [ ] Performance within SLA requirements

- [ ] **Security Validation**
  - [ ] Penetration testing completed
  - [ ] Security scan results reviewed
  - [ ] Vulnerability assessment passed
  - [ ] Compliance requirements met

- [ ] **Operational Readiness**
  - [ ] Monitoring dashboards configured
  - [ ] Alert rules tested and validated
  - [ ] On-call rotation established
  - [ ] Incident response procedures ready

### Production Cutover

- [ ] **Pre-Cutover**
  - [ ] Maintenance window scheduled
  - [ ] Rollback plan prepared
  - [ ] Stakeholders notified
  - [ ] Change management approval obtained

- [ ] **Cutover Process**
  - [ ] DNS/load balancer updated
  - [ ] Traffic routing verified
  - [ ] Health checks passing
  - [ ] User acceptance testing completed

- [ ] **Post-Cutover**
  - [ ] System monitoring for 24 hours
  - [ ] Performance metrics within normal range
  - [ ] No critical alerts triggered
  - [ ] User feedback collected

## Post-Deployment Tasks

### Ongoing Maintenance

- [ ] **Regular Tasks**
  - [ ] Security patches applied monthly
  - [ ] Configuration reviews quarterly
  - [ ] Performance reviews monthly
  - [ ] Capacity planning quarterly

- [ ] **Compliance**
  - [ ] Audit log reviews monthly
  - [ ] Security assessments annually
  - [ ] Compliance reporting as required
  - [ ] Policy updates as needed

### Continuous Improvement

- [ ] **Performance Optimization**
  - [ ] Regular performance reviews
  - [ ] Capacity planning updates
  - [ ] Configuration tuning
  - [ ] Resource optimization

- [ ] **Security Enhancement**
  - [ ] Threat model updates
  - [ ] Security control reviews
  - [ ] Vulnerability management
  - [ ] Incident lessons learned

## Troubleshooting Common Issues

### Deployment Issues

**Pod CrashLoopBackOff**
```bash
# Check pod logs
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock --previous

# Check events
kubectl get events -n airlock-system --sort-by='.lastTimestamp'

# Check resource constraints
kubectl describe pod -n airlock-system -l app.kubernetes.io/name=airlock
```

**Service Not Accessible**
```bash
# Check service endpoints
kubectl get endpoints -n airlock-system

# Check ingress configuration
kubectl describe ingress -n airlock-system

# Test service directly
kubectl port-forward -n airlock-system svc/airlock 8080:8080
```

### Authentication Issues

**JWT Validation Failures**
```bash
# Check OIDC configuration
curl -s https://your-oidc-provider/.well-known/openid-configuration

# Verify JWKS endpoint
curl -s https://your-oidc-provider/.well-known/jwks.json

# Check token claims
echo $JWT_TOKEN | cut -d. -f2 | base64 -d | jq .
```

**Policy Evaluation Errors**
```bash
# Check policy compilation
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -i policy

# Test policy with sample input
opa eval -d policy.rego "data.airlock.authz.allow" --input input.json
```

### Performance Issues

**High Response Times**
```bash
# Check resource usage
kubectl top pods -n airlock-system

# Check for resource constraints
kubectl describe pod -n airlock-system -l app.kubernetes.io/name=airlock

# Review performance metrics
curl -s https://airlock.example.com/metrics | grep airlock_request_duration
```

**Memory Leaks**
```bash
# Monitor memory usage over time
kubectl top pods -n airlock-system --containers

# Check for memory limit hits
kubectl get events -n airlock-system | grep -i memory
```

## Emergency Procedures

### Incident Response

1. **Immediate Response**
   - Assess impact and severity
   - Notify stakeholders
   - Implement immediate mitigation

2. **Investigation**
   - Collect logs and metrics
   - Identify root cause
   - Document findings

3. **Resolution**
   - Implement fix
   - Verify resolution
   - Monitor for recurrence

4. **Post-Incident**
   - Conduct post-mortem
   - Update procedures
   - Implement preventive measures

### Rollback Procedures

**Helm Rollback**
```bash
# List releases
helm list -n airlock-system

# Rollback to previous version
helm rollback airlock -n airlock-system

# Verify rollback
kubectl get pods -n airlock-system -l app.kubernetes.io/name=airlock
```

**Configuration Rollback**
```bash
# Restore previous configuration
kubectl apply -f previous-config.yaml -n airlock-system

# Restart pods to pick up changes
kubectl rollout restart deployment/airlock -n airlock-system
```

## Compliance and Audit

### Audit Requirements

- [ ] **Access Logging**
  - All authentication attempts logged
  - All authorization decisions logged
  - All data access logged
  - Log integrity maintained

- [ ] **Data Protection**
  - PII redaction working correctly
  - Data retention policies enforced
  - Data subject erasure capability
  - Encryption at rest and in transit

- [ ] **Security Controls**
  - Multi-factor authentication enforced
  - Least privilege access implemented
  - Regular security assessments conducted
  - Incident response procedures tested

### Reporting

- [ ] **Regular Reports**
  - Monthly security metrics
  - Quarterly compliance reports
  - Annual security assessments
  - Incident reports as needed

- [ ] **Audit Trail**
  - Complete audit trail maintained
  - Hash chaining for integrity
  - Tamper detection implemented
  - Long-term retention configured

---

**Note**: This checklist should be customized based on your specific environment, compliance requirements, and organizational policies. Regular reviews and updates of this checklist are recommended to ensure it remains current with best practices and requirements.
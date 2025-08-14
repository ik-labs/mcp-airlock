# Incident Response Playbook

This playbook provides step-by-step procedures for responding to incidents involving MCP Airlock, from initial detection through resolution and post-incident review.

## Incident Classification

### Severity Levels

| Severity | Description | Response Time | Examples |
|----------|-------------|---------------|----------|
| **P0 - Critical** | Complete service outage | 15 minutes | Service down, security breach |
| **P1 - High** | Major functionality impaired | 1 hour | Authentication failures, policy engine down |
| **P2 - Medium** | Minor functionality impaired | 4 hours | Performance degradation, non-critical errors |
| **P3 - Low** | Cosmetic or documentation issues | 24 hours | UI issues, documentation errors |

### Incident Types

- **Service Outage**: Complete or partial service unavailability
- **Security Incident**: Unauthorized access, data breach, or security control failure
- **Performance Degradation**: Slow response times or resource exhaustion
- **Authentication Issues**: OIDC failures, token validation problems
- **Policy Failures**: Authorization errors, policy engine issues
- **Data Issues**: Audit log corruption, data loss, backup failures

## Initial Response Procedures

### Step 1: Incident Detection and Triage (0-15 minutes)

#### Detection Sources
- **Monitoring Alerts**: Prometheus/AlertManager notifications
- **User Reports**: Support tickets or direct reports
- **Health Check Failures**: Kubernetes liveness/readiness probe failures
- **Security Alerts**: SIEM or security monitoring system alerts

#### Immediate Actions
```bash
# 1. Verify incident scope
kubectl get pods -n airlock-system -l app.kubernetes.io/name=airlock
curl -f https://airlock.your-company.com/live
curl -f https://airlock.your-company.com/ready

# 2. Check recent events
kubectl get events -n airlock-system --sort-by='.lastTimestamp' | head -20

# 3. Review recent logs
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock --tail=100

# 4. Check resource usage
kubectl top pods -n airlock-system
kubectl describe pod -n airlock-system -l app.kubernetes.io/name=airlock | grep -A 5 -B 5 -i limit
```

#### Triage Checklist
- [ ] Determine incident severity using classification matrix
- [ ] Identify affected users/tenants
- [ ] Assess security implications
- [ ] Estimate business impact
- [ ] Assign incident commander
- [ ] Create incident tracking ticket

### Step 2: Incident Declaration and Communication (15-30 minutes)

#### Incident Declaration
```bash
# Create incident tracking
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
echo "Incident ID: $INCIDENT_ID"

# Document initial findings
cat > incident-$INCIDENT_ID.md << EOF
# Incident Report: $INCIDENT_ID

**Severity**: [P0/P1/P2/P3]
**Type**: [Service Outage/Security/Performance/etc.]
**Start Time**: $(date -u)
**Incident Commander**: [Name]
**Status**: INVESTIGATING

## Initial Symptoms
- [Describe what was observed]

## Impact Assessment
- Affected Users: [Number/Groups]
- Affected Services: [List services]
- Business Impact: [Description]

## Timeline
- $(date -u): Incident detected
EOF
```

#### Communication Templates

**P0/P1 Incident Notification**
```
Subject: [P0/P1] MCP Airlock Incident - $INCIDENT_ID

We are investigating an incident affecting MCP Airlock service.

Incident ID: $INCIDENT_ID
Severity: [P0/P1]
Start Time: [UTC Time]
Current Status: INVESTIGATING

Impact:
- [Describe user impact]
- [Affected functionality]

We will provide updates every 30 minutes until resolved.

Incident Commander: [Name]
Status Page: [URL if available]
```

**Internal Team Notification**
```
🚨 MCP Airlock Incident - $INCIDENT_ID

Severity: [P0/P1]
Type: [Incident Type]
Commander: [Name]

Quick Status:
- Service Status: [UP/DOWN/DEGRADED]
- User Impact: [Description]
- ETA: [If known]

War Room: [Slack channel/Teams room]
Bridge: [Conference bridge if needed]

All hands on deck for P0/P1 incidents.
```

## Service Outage Response

### Complete Service Outage (P0)

#### Immediate Actions (0-15 minutes)
```bash
# 1. Check pod status
kubectl get pods -n airlock-system -l app.kubernetes.io/name=airlock

# 2. If pods are down, check deployment
kubectl describe deployment airlock -n airlock-system

# 3. Check for resource constraints
kubectl describe nodes | grep -A 5 -B 5 -i "pressure\|insufficient"

# 4. Check persistent volumes
kubectl get pvc -n airlock-system
kubectl describe pvc -n airlock-system

# 5. Review recent changes
kubectl rollout history deployment/airlock -n airlock-system
```

#### Recovery Actions
```bash
# Option 1: Restart pods
kubectl rollout restart deployment/airlock -n airlock-system
kubectl rollout status deployment/airlock -n airlock-system --timeout=300s

# Option 2: Scale up replicas
kubectl scale deployment airlock -n airlock-system --replicas=3

# Option 3: Rollback recent deployment
helm rollback airlock -n airlock-system
kubectl rollout status deployment/airlock -n airlock-system --timeout=300s

# Option 4: Emergency pod recreation
kubectl delete pods -n airlock-system -l app.kubernetes.io/name=airlock
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=airlock -n airlock-system --timeout=300s
```

#### Verification
```bash
# Verify service recovery
curl -f https://airlock.your-company.com/live
curl -f https://airlock.your-company.com/ready

# Test basic functionality
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TEST_TOKEN" \
  -d '{"jsonrpc":"2.0","id":"recovery-test","method":"tools/list"}'

# Check metrics
curl -s https://airlock.your-company.com/metrics | grep -E "(up|ready)"
```

### Partial Service Outage (P1)

#### Authentication Service Down
```bash
# 1. Check OIDC connectivity
kubectl exec -n airlock-system deployment/airlock -- \
  curl -s https://your-idp.com/.well-known/openid-configuration

# 2. Check JWKS endpoint
kubectl exec -n airlock-system deployment/airlock -- \
  curl -s https://your-idp.com/.well-known/jwks.json

# 3. Review authentication logs
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -i "auth\|oidc\|jwt"

# 4. Check network policies
kubectl get networkpolicy -n airlock-system
kubectl describe networkpolicy -n airlock-system
```

#### Policy Engine Failure
```bash
# 1. Check policy compilation
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -i policy

# 2. Verify policy ConfigMap
kubectl get configmap airlock-policy -n airlock-system -o yaml

# 3. Test policy locally
kubectl cp airlock-system/$(kubectl get pod -n airlock-system -l app.kubernetes.io/name=airlock -o jsonpath='{.items[0].metadata.name}'):/etc/policy/policy.rego ./policy.rego
opa fmt policy.rego
opa test policy.rego

# 4. Reload policy
kubectl exec -n airlock-system deployment/airlock -- kill -HUP 1
```

## Security Incident Response

### Security Breach Detection

#### Immediate Containment (0-15 minutes)
```bash
# 1. Identify compromised accounts/tokens
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -E "(401|403|security_violation)"

# 2. Block suspicious IPs (if admin endpoint available)
curl -X POST https://airlock.your-company.com/admin/security/block \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"ip_addresses":["suspicious.ip.address"],"duration":"1h"}'

# 3. Increase rate limiting
kubectl patch configmap airlock-config -n airlock-system --patch '
data:
  config.yaml: |
    rate_limiting:
      per_token: "10/min"
      per_ip: "50/min"
'
kubectl rollout restart deployment/airlock -n airlock-system

# 4. Enable enhanced logging
kubectl patch configmap airlock-config -n airlock-system --patch '
data:
  config.yaml: |
    logging:
      level: "debug"
      audit_all_requests: true
'
```

#### Investigation (15-60 minutes)
```bash
# 1. Extract audit logs for analysis
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  ".output /tmp/security-audit.csv" \
  ".mode csv" \
  "SELECT * FROM audit_events WHERE timestamp > datetime('now', '-2 hours');"

kubectl cp airlock-system/$(kubectl get pod -n airlock-system -l app.kubernetes.io/name=airlock -o jsonpath='{.items[0].metadata.name}'):/tmp/security-audit.csv ./security-audit.csv

# 2. Analyze attack patterns
sqlite3 security-audit.db << EOF
.import security-audit.csv audit_events
SELECT 
  COUNT(*) as attempts,
  subject,
  json_extract(metadata, '$.source_ip') as source_ip,
  action,
  decision
FROM audit_events 
WHERE decision = 'deny'
GROUP BY subject, source_ip, action
ORDER BY attempts DESC;
EOF

# 3. Check for privilege escalation attempts
grep -i "admin\|escalat\|privile" security-audit.csv

# 4. Verify data integrity
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db "PRAGMA integrity_check;"
```

#### Evidence Preservation
```bash
# 1. Create forensic backup
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db ".backup /tmp/forensic-backup-$(date +%Y%m%d-%H%M%S).db"

# 2. Export logs
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock --since=2h > incident-logs-$INCIDENT_ID.txt

# 3. Capture system state
kubectl get all -n airlock-system -o yaml > system-state-$INCIDENT_ID.yaml
kubectl describe pods -n airlock-system > pod-details-$INCIDENT_ID.txt

# 4. Hash evidence files
sha256sum incident-logs-$INCIDENT_ID.txt system-state-$INCIDENT_ID.yaml > evidence-hashes-$INCIDENT_ID.txt
```

### Data Breach Response

#### Immediate Actions
```bash
# 1. Identify affected data
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -E "(redact|pii|sensitive)"

# 2. Check redaction effectiveness
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT COUNT(*) as redaction_events, 
          SUM(redaction_count) as total_redactions
   FROM audit_events 
   WHERE action = 'redact_data' 
   AND timestamp > datetime('now', '-24 hours');"

# 3. Verify no sensitive data in logs
grep -E "(ssn|social|credit.*card|password)" incident-logs-$INCIDENT_ID.txt || echo "No sensitive data found in logs"

# 4. Check audit log integrity
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT COUNT(*) as broken_chains
   FROM audit_events a1
   LEFT JOIN audit_events a2 ON a1.previous_hash = a2.hash
   WHERE a1.previous_hash IS NOT NULL AND a2.hash IS NULL;"
```

#### Notification Requirements
```bash
# Generate breach notification report
cat > breach-report-$INCIDENT_ID.md << EOF
# Data Breach Report: $INCIDENT_ID

**Incident Type**: Data Breach
**Discovery Date**: $(date -u)
**Estimated Start**: [Time]
**Affected Systems**: MCP Airlock

## Data Involved
- Data Types: [List types of data potentially accessed]
- Number of Records: [Estimate if possible]
- Sensitivity Level: [Classification]

## Affected Individuals
- Internal Users: [Count]
- External Customers: [Count]
- Geographic Scope: [Regions]

## Containment Actions
- [List actions taken]

## Regulatory Notifications Required
- [ ] GDPR (72 hours)
- [ ] CCPA (As required)
- [ ] SOX (If applicable)
- [ ] Industry-specific regulations

## Next Steps
- [List planned actions]
EOF
```

## Performance Incident Response

### High Latency Issues

#### Diagnosis
```bash
# 1. Check current performance metrics
curl -s https://airlock.your-company.com/metrics | grep -E "(duration|latency)"

# 2. Analyze request patterns
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -E "duration|latency" | tail -50

# 3. Check resource utilization
kubectl top pods -n airlock-system
kubectl top nodes

# 4. Review slow queries/operations
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock | grep -E "(slow|timeout)" | tail -20
```

#### Mitigation
```bash
# 1. Scale up resources
kubectl patch deployment airlock -n airlock-system --patch '
spec:
  replicas: 5
  template:
    spec:
      containers:
      - name: airlock
        resources:
          limits:
            cpu: "2000m"
            memory: "2Gi"
          requests:
            cpu: "1000m"
            memory: "1Gi"
'

# 2. Optimize policy cache
kubectl patch configmap airlock-config -n airlock-system --patch '
data:
  config.yaml: |
    policy:
      cacheTTL: "10m"
      cacheSize: 20000
'

# 3. Increase connection limits
kubectl patch configmap airlock-config -n airlock-system --patch '
data:
  config.yaml: |
    server:
      maxConnections: 1000
      maxClients: 500
'
```

### Memory Issues

#### Out of Memory Response
```bash
# 1. Check memory usage patterns
kubectl top pods -n airlock-system --containers

# 2. Look for memory leaks
kubectl exec -n airlock-system deployment/airlock -- \
  curl -s localhost:6060/debug/pprof/heap > heap-$INCIDENT_ID.prof

# 3. Analyze memory allocation
go tool pprof heap-$INCIDENT_ID.prof

# 4. Emergency memory increase
kubectl patch deployment airlock -n airlock-system --patch '
spec:
  template:
    spec:
      containers:
      - name: airlock
        resources:
          limits:
            memory: "4Gi"
          requests:
            memory: "2Gi"
'
```

## Communication Procedures

### Status Updates

#### Update Schedule
- **P0**: Every 15 minutes until resolved
- **P1**: Every 30 minutes until resolved
- **P2**: Every 2 hours until resolved
- **P3**: Daily until resolved

#### Update Template
```
Subject: [UPDATE] MCP Airlock Incident - $INCIDENT_ID

Incident ID: $INCIDENT_ID
Status: [INVESTIGATING/IDENTIFIED/MONITORING/RESOLVED]
Next Update: [Time]

Current Situation:
- [Brief description of current status]

Actions Taken:
- [List recent actions]

Next Steps:
- [Planned actions]

Impact:
- [Current user impact]
- [Services affected]

ETA: [If available]
```

### Resolution Communication

#### Resolution Notification
```
Subject: [RESOLVED] MCP Airlock Incident - $INCIDENT_ID

The MCP Airlock incident has been resolved.

Incident ID: $INCIDENT_ID
Resolution Time: $(date -u)
Duration: [Total duration]

Root Cause:
- [Brief description]

Resolution:
- [Actions that resolved the issue]

Preventive Measures:
- [Actions to prevent recurrence]

Post-Incident Review:
- Scheduled for: [Date/Time]
- Meeting Link: [URL]

Thank you for your patience during this incident.
```

## Post-Incident Procedures

### Immediate Post-Resolution (0-2 hours)

#### Service Verification
```bash
# 1. Comprehensive health check
curl -f https://airlock.your-company.com/live
curl -f https://airlock.your-company.com/ready
curl -f https://airlock.your-company.com/metrics

# 2. End-to-end functionality test
./scripts/e2e-test.sh

# 3. Performance validation
./scripts/performance-test.sh

# 4. Security control verification
./scripts/security-test.sh
```

#### Monitoring Setup
```bash
# 1. Enable enhanced monitoring temporarily
kubectl patch configmap airlock-config -n airlock-system --patch '
data:
  config.yaml: |
    monitoring:
      enhanced: true
      duration: "24h"
'

# 2. Set up incident-specific alerts
kubectl apply -f - << EOF
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: post-incident-monitoring
  namespace: airlock-system
spec:
  groups:
  - name: post-incident
    rules:
    - alert: PostIncidentAnomalousActivity
      expr: rate(airlock_requests_failed_total[5m]) > 0.01
      for: 1m
      labels:
        severity: warning
        incident: "$INCIDENT_ID"
EOF
```

### Post-Incident Review (24-72 hours)

#### Data Collection
```bash
# 1. Collect incident timeline
cat > incident-timeline-$INCIDENT_ID.md << EOF
# Incident Timeline: $INCIDENT_ID

## Detection
- **Time**: [UTC]
- **Source**: [How detected]
- **Initial Symptoms**: [Description]

## Response
- **Time to Acknowledge**: [Duration]
- **Time to Engage**: [Duration]
- **Time to Mitigate**: [Duration]
- **Time to Resolve**: [Duration]

## Actions Taken
$(grep -E "^[0-9]{2}:[0-9]{2}" incident-$INCIDENT_ID.md)

## Lessons Learned
- What went well:
  - [List positive aspects]
- What could be improved:
  - [List improvement areas]
EOF
```

#### Root Cause Analysis
```bash
# 1. Technical analysis
cat > rca-$INCIDENT_ID.md << EOF
# Root Cause Analysis: $INCIDENT_ID

## Problem Statement
[Clear description of what happened]

## Root Cause
[Primary cause of the incident]

## Contributing Factors
- [Factor 1]
- [Factor 2]

## Why Analysis
1. Why did the incident occur?
   - [Answer]
2. Why wasn't it prevented?
   - [Answer]
3. Why wasn't it detected sooner?
   - [Answer]
4. Why did it take so long to resolve?
   - [Answer]
5. Why don't we have better monitoring?
   - [Answer]

## Action Items
- [ ] [Action 1] - Owner: [Name] - Due: [Date]
- [ ] [Action 2] - Owner: [Name] - Due: [Date]
EOF
```

### Improvement Implementation

#### Technical Improvements
```bash
# 1. Update monitoring
kubectl apply -f improved-monitoring-rules.yaml

# 2. Enhance alerting
kubectl apply -f enhanced-alerts.yaml

# 3. Update runbooks
git add docs/operations/
git commit -m "Update runbooks based on incident $INCIDENT_ID"

# 4. Implement preventive measures
kubectl apply -f preventive-measures.yaml
```

#### Process Improvements
- Update incident response procedures
- Enhance monitoring and alerting
- Improve documentation
- Conduct team training
- Review and update SLAs

## Escalation Procedures

### Internal Escalation

1. **Level 1**: On-call engineer
2. **Level 2**: Senior engineer/Team lead
3. **Level 3**: Engineering manager
4. **Level 4**: Director of Engineering
5. **Level 5**: CTO/VP Engineering

### External Escalation

1. **Vendor Support**: For infrastructure or third-party service issues
2. **Security Team**: For security incidents
3. **Legal Team**: For compliance or legal implications
4. **Executive Team**: For business-critical incidents

### Escalation Triggers

- **Time-based**: P0 after 1 hour, P1 after 4 hours
- **Impact-based**: Customer-facing issues, security breaches
- **Complexity-based**: Unknown root cause, multiple system involvement

## Contact Information

### Emergency Contacts

```yaml
# Store in secure location, update regularly
contacts:
  on_call:
    primary: "+1-555-0101"
    secondary: "+1-555-0102"
  
  management:
    engineering_manager: "+1-555-0201"
    director: "+1-555-0301"
  
  external:
    security_team: "security@company.com"
    legal_team: "legal@company.com"
  
  vendors:
    cloud_provider: "+1-800-SUPPORT"
    monitoring_vendor: "support@monitoring.com"
```

### Communication Channels

- **War Room**: #incident-response-$INCIDENT_ID
- **Status Updates**: #status-updates
- **Executive Updates**: #exec-incidents
- **Customer Communication**: status.company.com

---

**Remember**: This playbook should be regularly reviewed and updated based on lessons learned from actual incidents. Conduct regular drills to ensure team familiarity with procedures.
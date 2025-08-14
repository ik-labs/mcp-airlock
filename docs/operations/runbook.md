# Operational Runbook

This runbook provides comprehensive operational procedures for managing MCP Airlock in production environments.

## Daily Operations

### Morning Health Check (15 minutes)

```bash
#!/bin/bash
# daily-health-check.sh

echo "=== MCP Airlock Daily Health Check - $(date) ==="

# 1. Service Status
echo "1. Checking service status..."
kubectl get pods -n airlock-system -l app.kubernetes.io/name=airlock
kubectl get svc -n airlock-system -l app.kubernetes.io/name=airlock

# 2. Health Endpoints
echo "2. Testing health endpoints..."
curl -f https://airlock.your-company.com/live || echo "❌ Liveness check failed"
curl -f https://airlock.your-company.com/ready || echo "❌ Readiness check failed"

# 3. Resource Usage
echo "3. Checking resource usage..."
kubectl top pods -n airlock-system
kubectl top nodes | head -5

# 4. Recent Errors
echo "4. Checking for recent errors..."
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock --since=24h | grep -i error | tail -10

# 5. Certificate Expiry
echo "5. Checking certificate expiry..."
echo | openssl s_client -connect airlock.your-company.com:443 2>/dev/null | openssl x509 -noout -dates

# 6. Disk Usage
echo "6. Checking disk usage..."
kubectl exec -n airlock-system deployment/airlock -- df -h | grep -E "(audit|data)"

# 7. Authentication Health
echo "7. Testing authentication..."
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HEALTH_CHECK_TOKEN" \
  -d '{"jsonrpc":"2.0","id":"health","method":"tools/list"}' | jq -r '.result.tools | length' | xargs echo "Available tools:"

echo "=== Health check completed ==="
```

### Log Review Process

```bash
#!/bin/bash
# daily-log-review.sh

LOG_DATE=$(date -d "yesterday" +%Y-%m-%d)
NAMESPACE="airlock-system"

echo "=== Daily Log Review for $LOG_DATE ==="

# 1. Error Summary
echo "1. Error Summary:"
kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=airlock --since=24h | \
  grep -i error | \
  awk '{print $NF}' | \
  sort | uniq -c | sort -nr | head -10

# 2. Authentication Failures
echo "2. Authentication Failures:"
kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=airlock --since=24h | \
  grep -i "auth.*fail" | wc -l | xargs echo "Total auth failures:"

# 3. Policy Denials
echo "3. Policy Denials:"
kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=airlock --since=24h | \
  grep -i "policy.*deny" | wc -l | xargs echo "Total policy denials:"

# 4. Rate Limiting Events
echo "4. Rate Limiting:"
kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=airlock --since=24h | \
  grep -i "rate.*limit" | wc -l | xargs echo "Rate limit hits:"

# 5. Security Violations
echo "5. Security Violations:"
kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=airlock --since=24h | \
  grep -i "security.*violation" | wc -l | xargs echo "Security violations:"

# 6. Performance Issues
echo "6. Performance Issues:"
kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=airlock --since=24h | \
  grep -E "(slow|timeout|latency)" | wc -l | xargs echo "Performance issues:"

echo "=== Log review completed ==="
```

## Weekly Operations

### Weekly Maintenance (30 minutes)

```bash
#!/bin/bash
# weekly-maintenance.sh

echo "=== Weekly Maintenance - $(date) ==="

# 1. Update Health Check
echo "1. Running comprehensive health check..."
./daily-health-check.sh

# 2. Backup Verification
echo "2. Verifying backups..."
kubectl get cronjob -n airlock-system
kubectl get job -n airlock-system | grep backup

# 3. Certificate Status
echo "3. Checking certificate status..."
kubectl get certificates -n airlock-system
kubectl describe certificates -n airlock-system | grep -E "(Ready|Renewal)"

# 4. Policy Review
echo "4. Reviewing policy effectiveness..."
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT action, decision, COUNT(*) as count 
   FROM audit_events 
   WHERE timestamp > datetime('now', '-7 days')
   GROUP BY action, decision
   ORDER BY count DESC;"

# 5. Performance Metrics
echo "5. Weekly performance summary..."
curl -s https://airlock.your-company.com/metrics | \
  grep -E "(request_duration|requests_total)" | \
  head -10

# 6. Storage Usage
echo "6. Storage usage trends..."
kubectl exec -n airlock-system deployment/airlock -- \
  du -sh /var/lib/airlock/*

# 7. Update Check
echo "7. Checking for updates..."
helm repo update
helm search repo airlock --versions | head -5

echo "=== Weekly maintenance completed ==="
```

### Security Review

```bash
#!/bin/bash
# weekly-security-review.sh

echo "=== Weekly Security Review - $(date) ==="

# 1. Failed Authentication Analysis
echo "1. Authentication failure analysis..."
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT 
     json_extract(metadata, '$.source_ip') as source_ip,
     COUNT(*) as failures,
     MIN(timestamp) as first_attempt,
     MAX(timestamp) as last_attempt
   FROM audit_events 
   WHERE action = 'token_validate' 
   AND decision = 'deny' 
   AND timestamp > datetime('now', '-7 days')
   GROUP BY source_ip
   HAVING failures > 10
   ORDER BY failures DESC;"

# 2. Policy Violation Patterns
echo "2. Policy violation patterns..."
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT 
     reason,
     COUNT(*) as violations
   FROM audit_events 
   WHERE action = 'policy_evaluate' 
   AND decision = 'deny' 
   AND timestamp > datetime('now', '-7 days')
   GROUP BY reason
   ORDER BY violations DESC;"

# 3. Unusual Access Patterns
echo "3. Unusual access patterns..."
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT 
     subject,
     COUNT(DISTINCT json_extract(metadata, '$.source_ip')) as unique_ips,
     COUNT(*) as total_requests
   FROM audit_events 
   WHERE timestamp > datetime('now', '-7 days')
   GROUP BY subject
   HAVING unique_ips > 5
   ORDER BY unique_ips DESC;"

# 4. Privilege Escalation Attempts
echo "4. Checking for privilege escalation attempts..."
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock --since=168h | \
  grep -i -E "(admin|root|sudo|escalat)" | wc -l | \
  xargs echo "Potential escalation attempts:"

# 5. Data Access Patterns
echo "5. Sensitive data access patterns..."
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT 
     COUNT(*) as redaction_events,
     SUM(redaction_count) as total_redactions,
     AVG(redaction_count) as avg_redactions_per_event
   FROM audit_events 
   WHERE action = 'redact_data' 
   AND timestamp > datetime('now', '-7 days');"

echo "=== Security review completed ==="
```

## Monthly Operations

### Monthly Review and Optimization

```bash
#!/bin/bash
# monthly-review.sh

echo "=== Monthly Review - $(date) ==="

# 1. Capacity Planning
echo "1. Capacity planning analysis..."
kubectl top pods -n airlock-system --containers | \
  awk 'NR>1 {cpu+=$2; mem+=$3} END {print "Average CPU:", cpu/NR "m, Average Memory:", mem/NR "Mi"}'

# 2. Performance Trends
echo "2. Performance trend analysis..."
curl -s "http://prometheus:9090/api/v1/query_range?query=histogram_quantile(0.95,airlock_request_duration_seconds_bucket)&start=$(date -d '30 days ago' +%s)&end=$(date +%s)&step=86400" | \
  jq -r '.data.result[0].values[] | @csv'

# 3. User Activity Summary
echo "3. User activity summary..."
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT 
     COUNT(DISTINCT subject) as unique_users,
     COUNT(*) as total_requests,
     COUNT(DISTINCT DATE(timestamp)) as active_days
   FROM audit_events 
   WHERE timestamp > datetime('now', '-30 days');"

# 4. Tool Usage Statistics
echo "4. Tool usage statistics..."
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT 
     json_extract(metadata, '$.tool') as tool,
     COUNT(*) as usage_count
   FROM audit_events 
   WHERE action = 'tool_call' 
   AND timestamp > datetime('now', '-30 days')
   GROUP BY tool
   ORDER BY usage_count DESC
   LIMIT 10;"

# 5. Error Rate Analysis
echo "5. Error rate analysis..."
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT 
     DATE(timestamp) as date,
     COUNT(CASE WHEN decision = 'deny' THEN 1 END) as errors,
     COUNT(*) as total,
     ROUND(100.0 * COUNT(CASE WHEN decision = 'deny' THEN 1 END) / COUNT(*), 2) as error_rate
   FROM audit_events 
   WHERE timestamp > datetime('now', '-30 days')
   GROUP BY DATE(timestamp)
   ORDER BY date DESC
   LIMIT 30;"

echo "=== Monthly review completed ==="
```

### Policy Optimization

```bash
#!/bin/bash
# monthly-policy-optimization.sh

echo "=== Monthly Policy Optimization - $(date) ==="

# 1. Policy Hit Analysis
echo "1. Policy rule effectiveness..."
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT 
     json_extract(metadata, '$.rule_id') as rule_id,
     decision,
     COUNT(*) as hits
   FROM audit_events 
   WHERE action = 'policy_evaluate' 
   AND timestamp > datetime('now', '-30 days')
   GROUP BY rule_id, decision
   ORDER BY hits DESC;"

# 2. Unused Policy Rules
echo "2. Identifying unused policy rules..."
# This would require policy analysis tools
opa test policy.rego policy_test.rego --coverage --format=json | \
  jq '.coverage.files[] | select(.coverage < 50) | .filename'

# 3. Policy Performance
echo "3. Policy evaluation performance..."
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock --since=720h | \
  grep "policy.*duration" | \
  awk '{print $NF}' | \
  sort -n | \
  awk '{sum+=$1; count++} END {print "Average policy evaluation time:", sum/count "ms"}'

# 4. Recommended Optimizations
echo "4. Policy optimization recommendations..."
cat > policy-recommendations.md << EOF
# Policy Optimization Recommendations

Based on 30-day analysis:

## High-Impact Rules
$(kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT rule_id, COUNT(*) FROM audit_events 
   WHERE action = 'policy_evaluate' 
   AND timestamp > datetime('now', '-30 days')
   GROUP BY rule_id ORDER BY COUNT(*) DESC LIMIT 5;" | \
  sed 's/^/- /')

## Recommendations
- Consider caching for high-impact rules
- Review unused rules for removal
- Optimize complex rule logic
- Consider rule ordering optimization
EOF

echo "=== Policy optimization completed ==="
```

## Scaling Operations

### Horizontal Scaling

```bash
#!/bin/bash
# scale-airlock.sh

NAMESPACE="airlock-system"
CURRENT_REPLICAS=$(kubectl get deployment airlock -n $NAMESPACE -o jsonpath='{.spec.replicas}')
TARGET_REPLICAS=${1:-$((CURRENT_REPLICAS + 1))}

echo "Scaling Airlock from $CURRENT_REPLICAS to $TARGET_REPLICAS replicas..."

# 1. Pre-scaling checks
echo "1. Pre-scaling health check..."
kubectl get pods -n $NAMESPACE -l app.kubernetes.io/name=airlock
kubectl top pods -n $NAMESPACE

# 2. Scale deployment
echo "2. Scaling deployment..."
kubectl scale deployment airlock -n $NAMESPACE --replicas=$TARGET_REPLICAS

# 3. Wait for rollout
echo "3. Waiting for rollout to complete..."
kubectl rollout status deployment/airlock -n $NAMESPACE --timeout=300s

# 4. Verify scaling
echo "4. Verifying scaled deployment..."
kubectl get pods -n $NAMESPACE -l app.kubernetes.io/name=airlock
kubectl get endpoints -n $NAMESPACE

# 5. Health check
echo "5. Post-scaling health check..."
sleep 30
curl -f https://airlock.your-company.com/live
curl -f https://airlock.your-company.com/ready

echo "Scaling completed successfully"
```

### Vertical Scaling

```bash
#!/bin/bash
# vertical-scale.sh

NAMESPACE="airlock-system"
CPU_LIMIT=${1:-"2000m"}
MEMORY_LIMIT=${2:-"2Gi"}

echo "Vertically scaling Airlock resources..."
echo "CPU Limit: $CPU_LIMIT, Memory Limit: $MEMORY_LIMIT"

# 1. Current resource usage
echo "1. Current resource usage..."
kubectl top pods -n $NAMESPACE -l app.kubernetes.io/name=airlock --containers

# 2. Update resource limits
echo "2. Updating resource limits..."
kubectl patch deployment airlock -n $NAMESPACE --patch "
spec:
  template:
    spec:
      containers:
      - name: airlock
        resources:
          limits:
            cpu: '$CPU_LIMIT'
            memory: '$MEMORY_LIMIT'
          requests:
            cpu: '$(echo $CPU_LIMIT | sed 's/000m/00m/')'
            memory: '$(echo $MEMORY_LIMIT | sed 's/Gi/00Mi/' | sed 's/2000Mi/1Gi/')'
"

# 3. Wait for rollout
echo "3. Waiting for rollout..."
kubectl rollout status deployment/airlock -n $NAMESPACE --timeout=300s

# 4. Verify new limits
echo "4. Verifying new resource limits..."
kubectl describe pod -n $NAMESPACE -l app.kubernetes.io/name=airlock | grep -A 10 "Limits:"

echo "Vertical scaling completed"
```

## Backup and Recovery

### Backup Procedures

```bash
#!/bin/bash
# backup-airlock.sh

BACKUP_DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/backup/airlock-$BACKUP_DATE"
NAMESPACE="airlock-system"

echo "Starting Airlock backup - $BACKUP_DATE"

mkdir -p $BACKUP_DIR

# 1. Kubernetes Resources
echo "1. Backing up Kubernetes resources..."
kubectl get all -n $NAMESPACE -o yaml > $BACKUP_DIR/k8s-resources.yaml
kubectl get configmaps -n $NAMESPACE -o yaml > $BACKUP_DIR/configmaps.yaml
kubectl get secrets -n $NAMESPACE -o yaml > $BACKUP_DIR/secrets.yaml
kubectl get pvc -n $NAMESPACE -o yaml > $BACKUP_DIR/pvc.yaml

# 2. Helm Configuration
echo "2. Backing up Helm configuration..."
helm get values airlock -n $NAMESPACE > $BACKUP_DIR/helm-values.yaml
helm get manifest airlock -n $NAMESPACE > $BACKUP_DIR/helm-manifest.yaml

# 3. Audit Database
echo "3. Backing up audit database..."
kubectl exec -n $NAMESPACE deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db ".backup /tmp/audit-backup-$BACKUP_DATE.db"
kubectl cp $NAMESPACE/$(kubectl get pod -n $NAMESPACE -l app.kubernetes.io/name=airlock -o jsonpath='{.items[0].metadata.name}'):/tmp/audit-backup-$BACKUP_DATE.db $BACKUP_DIR/audit.db

# 4. Configuration Files
echo "4. Backing up configuration files..."
kubectl exec -n $NAMESPACE deployment/airlock -- tar -czf /tmp/config-backup.tar.gz /etc/airlock/
kubectl cp $NAMESPACE/$(kubectl get pod -n $NAMESPACE -l app.kubernetes.io/name=airlock -o jsonpath='{.items[0].metadata.name}'):/tmp/config-backup.tar.gz $BACKUP_DIR/config.tar.gz

# 5. Create backup archive
echo "5. Creating backup archive..."
tar -czf airlock-backup-$BACKUP_DATE.tar.gz -C /backup airlock-$BACKUP_DATE

# 6. Upload to S3 (if configured)
if [ -n "$BACKUP_S3_BUCKET" ]; then
  echo "6. Uploading to S3..."
  aws s3 cp airlock-backup-$BACKUP_DATE.tar.gz s3://$BACKUP_S3_BUCKET/airlock/
fi

# 7. Cleanup old backups
echo "7. Cleaning up old backups..."
find /backup -name "airlock-backup-*.tar.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR"
```

### Recovery Procedures

```bash
#!/bin/bash
# restore-airlock.sh

BACKUP_FILE=${1:-"latest"}
NAMESPACE="airlock-system"

if [ "$BACKUP_FILE" = "latest" ]; then
  BACKUP_FILE=$(ls -t airlock-backup-*.tar.gz | head -1)
fi

echo "Restoring Airlock from backup: $BACKUP_FILE"

# 1. Extract backup
echo "1. Extracting backup..."
tar -xzf $BACKUP_FILE
BACKUP_DIR=$(tar -tzf $BACKUP_FILE | head -1 | cut -f1 -d"/")

# 2. Restore Kubernetes resources
echo "2. Restoring Kubernetes resources..."
kubectl apply -f $BACKUP_DIR/k8s-resources.yaml
kubectl apply -f $BACKUP_DIR/configmaps.yaml
kubectl apply -f $BACKUP_DIR/pvc.yaml

# 3. Restore secrets (carefully)
echo "3. Restoring secrets..."
kubectl apply -f $BACKUP_DIR/secrets.yaml

# 4. Wait for pods to be ready
echo "4. Waiting for pods to be ready..."
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=airlock -n $NAMESPACE --timeout=300s

# 5. Restore audit database
echo "5. Restoring audit database..."
kubectl cp $BACKUP_DIR/audit.db $NAMESPACE/$(kubectl get pod -n $NAMESPACE -l app.kubernetes.io/name=airlock -o jsonpath='{.items[0].metadata.name}'):/tmp/audit-restore.db
kubectl exec -n $NAMESPACE deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db ".restore /tmp/audit-restore.db"

# 6. Restore configuration
echo "6. Restoring configuration..."
kubectl cp $BACKUP_DIR/config.tar.gz $NAMESPACE/$(kubectl get pod -n $NAMESPACE -l app.kubernetes.io/name=airlock -o jsonpath='{.items[0].metadata.name}'):/tmp/config-restore.tar.gz
kubectl exec -n $NAMESPACE deployment/airlock -- \
  tar -xzf /tmp/config-restore.tar.gz -C /

# 7. Restart services
echo "7. Restarting services..."
kubectl rollout restart deployment/airlock -n $NAMESPACE
kubectl rollout status deployment/airlock -n $NAMESPACE --timeout=300s

# 8. Verify restoration
echo "8. Verifying restoration..."
curl -f https://airlock.your-company.com/live
curl -f https://airlock.your-company.com/ready

echo "Restoration completed successfully"
```

## Monitoring and Alerting

### Custom Metrics Collection

```bash
#!/bin/bash
# collect-custom-metrics.sh

NAMESPACE="airlock-system"
METRICS_FILE="/tmp/airlock-metrics-$(date +%Y%m%d-%H%M%S).json"

echo "Collecting custom metrics..."

# 1. Service Metrics
echo "1. Collecting service metrics..."
curl -s https://airlock.your-company.com/metrics > /tmp/prometheus-metrics.txt

# 2. Audit Metrics
echo "2. Collecting audit metrics..."
kubectl exec -n $NAMESPACE deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT 
     'requests_by_hour' as metric,
     strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
     COUNT(*) as value
   FROM audit_events 
   WHERE timestamp > datetime('now', '-24 hours')
   GROUP BY strftime('%Y-%m-%d %H:00:00', timestamp)
   ORDER BY hour;" > /tmp/audit-metrics.csv

# 3. Performance Metrics
echo "3. Collecting performance metrics..."
kubectl top pods -n $NAMESPACE --containers | \
  awk 'NR>1 {print "{\"pod\":\""$1"\",\"container\":\""$2"\",\"cpu\":\""$3"\",\"memory\":\""$4"\"}"}' > /tmp/resource-metrics.json

# 4. Error Metrics
echo "4. Collecting error metrics..."
kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=airlock --since=1h | \
  grep -i error | \
  awk '{print $1, $2}' | \
  sort | uniq -c > /tmp/error-metrics.txt

# 5. Combine metrics
echo "5. Creating combined metrics report..."
cat > $METRICS_FILE << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "service_status": "$(curl -s https://airlock.your-company.com/live && echo 'healthy' || echo 'unhealthy')",
  "pod_count": $(kubectl get pods -n $NAMESPACE -l app.kubernetes.io/name=airlock --no-headers | wc -l),
  "error_count_1h": $(kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=airlock --since=1h | grep -i error | wc -l),
  "request_count_1h": $(kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=airlock --since=1h | grep -E "(POST|GET)" | wc -l)
}
EOF

echo "Metrics collected: $METRICS_FILE"
```

### Alert Response Procedures

```bash
#!/bin/bash
# alert-response.sh

ALERT_NAME=$1
SEVERITY=$2

echo "Responding to alert: $ALERT_NAME (Severity: $SEVERITY)"

case $ALERT_NAME in
  "AirlockDown")
    echo "Service is down - running emergency recovery..."
    kubectl get pods -n airlock-system -l app.kubernetes.io/name=airlock
    kubectl rollout restart deployment/airlock -n airlock-system
    ;;
    
  "AirlockHighErrorRate")
    echo "High error rate detected - investigating..."
    kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock --tail=100 | grep -i error
    ;;
    
  "AirlockHighLatency")
    echo "High latency detected - checking resources..."
    kubectl top pods -n airlock-system
    kubectl describe pod -n airlock-system -l app.kubernetes.io/name=airlock | grep -A 5 -B 5 -i limit
    ;;
    
  "AirlockCertificateExpiring")
    echo "Certificate expiring - checking renewal..."
    kubectl get certificates -n airlock-system
    kubectl describe certificates -n airlock-system
    ;;
    
  *)
    echo "Unknown alert: $ALERT_NAME"
    echo "Running general diagnostics..."
    ./daily-health-check.sh
    ;;
esac

echo "Alert response completed"
```

## Configuration Management

### Configuration Updates

```bash
#!/bin/bash
# update-config.sh

CONFIG_TYPE=$1  # policy, auth, dlp, etc.
CONFIG_FILE=$2

echo "Updating $CONFIG_TYPE configuration..."

case $CONFIG_TYPE in
  "policy")
    echo "Updating policy configuration..."
    # Validate policy first
    opa fmt $CONFIG_FILE
    opa test $CONFIG_FILE
    
    # Update ConfigMap
    kubectl create configmap airlock-policy-new \
      --from-file=policy.rego=$CONFIG_FILE \
      -n airlock-system \
      --dry-run=client -o yaml | kubectl apply -f -
    
    # Trigger reload
    kubectl exec -n airlock-system deployment/airlock -- kill -HUP 1
    ;;
    
  "auth")
    echo "Updating authentication configuration..."
    kubectl patch configmap airlock-config -n airlock-system \
      --patch-file $CONFIG_FILE
    kubectl rollout restart deployment/airlock -n airlock-system
    ;;
    
  "dlp")
    echo "Updating DLP configuration..."
    kubectl patch configmap airlock-config -n airlock-system \
      --patch-file $CONFIG_FILE
    kubectl rollout restart deployment/airlock -n airlock-system
    ;;
    
  *)
    echo "Unknown configuration type: $CONFIG_TYPE"
    exit 1
    ;;
esac

# Wait for rollout if needed
kubectl rollout status deployment/airlock -n airlock-system --timeout=300s

# Verify configuration
echo "Verifying configuration update..."
sleep 30
curl -f https://airlock.your-company.com/live
curl -f https://airlock.your-company.com/ready

echo "Configuration update completed"
```

### Environment Promotion

```bash
#!/bin/bash
# promote-config.sh

SOURCE_ENV=$1  # staging, dev, etc.
TARGET_ENV=$2  # production

echo "Promoting configuration from $SOURCE_ENV to $TARGET_ENV..."

# 1. Export source configuration
echo "1. Exporting source configuration..."
kubectl get configmap airlock-config -n airlock-$SOURCE_ENV -o yaml > /tmp/config-$SOURCE_ENV.yaml
kubectl get configmap airlock-policy -n airlock-$SOURCE_ENV -o yaml > /tmp/policy-$SOURCE_ENV.yaml

# 2. Validate configuration
echo "2. Validating configuration..."
# Add validation logic here

# 3. Create backup of target
echo "3. Creating backup of target configuration..."
kubectl get configmap airlock-config -n airlock-$TARGET_ENV -o yaml > /tmp/config-$TARGET_ENV-backup.yaml
kubectl get configmap airlock-policy -n airlock-$TARGET_ENV -o yaml > /tmp/policy-$TARGET_ENV-backup.yaml

# 4. Apply new configuration
echo "4. Applying new configuration to $TARGET_ENV..."
sed "s/namespace: airlock-$SOURCE_ENV/namespace: airlock-$TARGET_ENV/g" /tmp/config-$SOURCE_ENV.yaml | kubectl apply -f -
sed "s/namespace: airlock-$SOURCE_ENV/namespace: airlock-$TARGET_ENV/g" /tmp/policy-$SOURCE_ENV.yaml | kubectl apply -f -

# 5. Restart services
echo "5. Restarting services in $TARGET_ENV..."
kubectl rollout restart deployment/airlock -n airlock-$TARGET_ENV
kubectl rollout status deployment/airlock -n airlock-$TARGET_ENV --timeout=300s

# 6. Verify promotion
echo "6. Verifying promotion..."
sleep 30
if [ "$TARGET_ENV" = "production" ]; then
  curl -f https://airlock.your-company.com/live
else
  curl -f https://airlock-$TARGET_ENV.your-company.com/live
fi

echo "Configuration promotion completed"
```

## Performance Tuning

### Performance Analysis

```bash
#!/bin/bash
# performance-analysis.sh

echo "=== Performance Analysis - $(date) ==="

# 1. Response Time Analysis
echo "1. Response time analysis..."
curl -s https://airlock.your-company.com/metrics | \
  grep airlock_request_duration_seconds | \
  grep -E "(0\.5|0\.95|0\.99)" | \
  awk '{print $1, $2}'

# 2. Throughput Analysis
echo "2. Throughput analysis..."
curl -s https://airlock.your-company.com/metrics | \
  grep airlock_requests_total | \
  tail -5

# 3. Resource Utilization
echo "3. Resource utilization..."
kubectl top pods -n airlock-system --containers

# 4. Cache Hit Rates
echo "4. Cache performance..."
curl -s https://airlock.your-company.com/metrics | \
  grep -E "(cache_hit|cache_miss)" | \
  awk '{print $1, $2}'

# 5. Database Performance
echo "5. Database performance..."
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "EXPLAIN QUERY PLAN SELECT * FROM audit_events WHERE timestamp > datetime('now', '-1 hour');"

echo "=== Performance analysis completed ==="
```

### Optimization Recommendations

```bash
#!/bin/bash
# generate-optimization-recommendations.sh

echo "=== Optimization Recommendations - $(date) ==="

# 1. Resource Optimization
echo "1. Resource optimization recommendations..."
CURRENT_CPU=$(kubectl get deployment airlock -n airlock-system -o jsonpath='{.spec.template.spec.containers[0].resources.limits.cpu}')
CURRENT_MEM=$(kubectl get deployment airlock -n airlock-system -o jsonpath='{.spec.template.spec.containers[0].resources.limits.memory}')
ACTUAL_CPU=$(kubectl top pod -n airlock-system -l app.kubernetes.io/name=airlock --no-headers | awk '{sum+=$2} END {print sum/NR}')
ACTUAL_MEM=$(kubectl top pod -n airlock-system -l app.kubernetes.io/name=airlock --no-headers | awk '{sum+=$3} END {print sum/NR}')

echo "Current limits: CPU=$CURRENT_CPU, Memory=$CURRENT_MEM"
echo "Actual usage: CPU=${ACTUAL_CPU}m, Memory=${ACTUAL_MEM}Mi"

# 2. Cache Optimization
echo "2. Cache optimization recommendations..."
CACHE_HIT_RATE=$(curl -s https://airlock.your-company.com/metrics | grep cache_hit_rate | awk '{print $2}')
echo "Current cache hit rate: $CACHE_HIT_RATE"

if (( $(echo "$CACHE_HIT_RATE < 0.8" | bc -l) )); then
  echo "Recommendation: Increase cache size or TTL"
fi

# 3. Database Optimization
echo "3. Database optimization recommendations..."
DB_SIZE=$(kubectl exec -n airlock-system deployment/airlock -- \
  du -sh /var/lib/airlock/audit.db | awk '{print $1}')
echo "Current database size: $DB_SIZE"

# 4. Policy Optimization
echo "4. Policy optimization recommendations..."
POLICY_EVAL_TIME=$(kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock --since=1h | \
  grep "policy.*duration" | \
  awk '{sum+=$NF; count++} END {print sum/count}')
echo "Average policy evaluation time: ${POLICY_EVAL_TIME}ms"

if (( $(echo "$POLICY_EVAL_TIME > 10" | bc -l) )); then
  echo "Recommendation: Optimize policy rules or increase cache"
fi

echo "=== Recommendations completed ==="
```

## Disaster Recovery

### Disaster Recovery Plan

```bash
#!/bin/bash
# disaster-recovery.sh

RECOVERY_TYPE=$1  # full, partial, data-only
BACKUP_LOCATION=$2

echo "Starting disaster recovery: $RECOVERY_TYPE"

case $RECOVERY_TYPE in
  "full")
    echo "Full disaster recovery..."
    # 1. Restore infrastructure
    kubectl create namespace airlock-system
    
    # 2. Restore from backup
    ./restore-airlock.sh $BACKUP_LOCATION
    
    # 3. Verify services
    ./daily-health-check.sh
    ;;
    
  "partial")
    echo "Partial disaster recovery..."
    # Restore specific components
    ;;
    
  "data-only")
    echo "Data-only recovery..."
    # Restore only data components
    ;;
    
  *)
    echo "Unknown recovery type: $RECOVERY_TYPE"
    exit 1
    ;;
esac

echo "Disaster recovery completed"
```

## Maintenance Windows

### Planned Maintenance

```bash
#!/bin/bash
# planned-maintenance.sh

MAINTENANCE_TYPE=$1  # update, patch, config-change
MAINTENANCE_WINDOW=$2  # duration in minutes

echo "Starting planned maintenance: $MAINTENANCE_TYPE"
echo "Maintenance window: $MAINTENANCE_WINDOW minutes"

# 1. Pre-maintenance checks
echo "1. Pre-maintenance health check..."
./daily-health-check.sh

# 2. Create maintenance notification
echo "2. Creating maintenance notification..."
# Update status page or send notifications

# 3. Perform maintenance
case $MAINTENANCE_TYPE in
  "update")
    echo "Performing system update..."
    helm upgrade airlock ./helm/airlock -n airlock-system -f values-production.yaml
    ;;
    
  "patch")
    echo "Applying security patches..."
    kubectl patch deployment airlock -n airlock-system --patch-file security-patch.yaml
    ;;
    
  "config-change")
    echo "Applying configuration changes..."
    kubectl apply -f new-config.yaml
    kubectl rollout restart deployment/airlock -n airlock-system
    ;;
esac

# 4. Post-maintenance verification
echo "4. Post-maintenance verification..."
kubectl rollout status deployment/airlock -n airlock-system --timeout=300s
./daily-health-check.sh

# 5. Clear maintenance notification
echo "5. Clearing maintenance notification..."
# Update status page

echo "Planned maintenance completed"
```

---

This runbook provides comprehensive operational procedures for managing MCP Airlock in production. Regular review and updates based on operational experience are recommended to keep procedures current and effective.
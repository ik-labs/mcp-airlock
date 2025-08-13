# Monitoring Guide

Comprehensive monitoring and observability setup for MCP Airlock.

## Overview

MCP Airlock provides extensive monitoring capabilities through:
- Prometheus metrics
- OpenTelemetry tracing  
- Structured logging
- Health check endpoints
- Custom dashboards and alerts

## Metrics

### Core Metrics

#### Request Metrics
```
# Total requests by status code
airlock_requests_total{method="POST", status="200", endpoint="/mcp/v1/tools/call"}

# Request duration histogram
airlock_request_duration_seconds{method="POST", endpoint="/mcp/v1/tools/call"}

# Request size histogram
airlock_request_size_bytes{method="POST", endpoint="/mcp/v1/tools/call"}

# Response size histogram  
airlock_response_size_bytes{method="POST", endpoint="/mcp/v1/tools/call"}
```

#### Authentication Metrics
```
# Authentication attempts
airlock_auth_attempts_total{result="success"}
airlock_auth_attempts_total{result="failure", reason="invalid_token"}

# JWT validation duration
airlock_jwt_validation_duration_seconds

# JWKS cache metrics
airlock_jwks_cache_hits_total
airlock_jwks_cache_misses_total
airlock_jwks_refresh_duration_seconds
```

#### Authorization Metrics
```
# Policy decisions
airlock_policy_decisions_total{decision="allow", tenant="tenant-1"}
airlock_policy_decisions_total{decision="deny", tenant="tenant-1", reason="tool_not_allowed"}

# Policy evaluation duration
airlock_policy_evaluation_duration_seconds

# Policy cache metrics
airlock_policy_cache_hits_total
airlock_policy_cache_misses_total
```

#### Data Protection Metrics
```
# Redaction events
airlock_redaction_events_total{pattern="email", tenant="tenant-1"}

# Redaction processing time
airlock_redaction_duration_seconds

# Bytes processed for redaction
airlock_redaction_bytes_processed_total
```

#### System Metrics
```
# Memory usage
airlock_memory_usage_bytes
airlock_memory_limit_bytes

# CPU usage
airlock_cpu_usage_seconds_total

# Goroutine count
airlock_goroutines_active

# File descriptor usage
airlock_file_descriptors_open
airlock_file_descriptors_limit
```

#### Audit Metrics
```
# Audit events
airlock_audit_events_total{type="authentication", result="success"}

# Audit storage metrics
airlock_audit_storage_size_bytes
airlock_audit_storage_errors_total

# Audit export metrics
airlock_audit_exports_total{format="jsonl", destination="s3"}
```

### Metrics Collection

#### Prometheus Configuration
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'mcp-airlock'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - mcp-airlock
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
```

#### ServiceMonitor (Prometheus Operator)
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: mcp-airlock
  namespace: mcp-airlock
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: airlock
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s
```

## Alerting

### Critical Alerts

#### High Error Rate
```yaml
- alert: AirlockHighErrorRate
  expr: |
    (
      rate(airlock_requests_total{status=~"5.."}[5m]) /
      rate(airlock_requests_total[5m])
    ) > 0.05
  for: 2m
  labels:
    severity: critical
    service: mcp-airlock
  annotations:
    summary: "MCP Airlock high error rate"
    description: "Error rate is {{ $value | humanizePercentage }} over the last 5 minutes"
    runbook_url: "https://docs.example.com/runbooks/airlock-high-error-rate"
```

#### Authentication Failures
```yaml
- alert: AirlockAuthFailureSpike
  expr: rate(airlock_auth_attempts_total{result="failure"}[5m]) > 0.1
  for: 2m
  labels:
    severity: warning
    service: mcp-airlock
  annotations:
    summary: "MCP Airlock authentication failure spike"
    description: "{{ $value }} authentication failures per second over the last 5 minutes"
```

#### High Latency
```yaml
- alert: AirlockHighLatency
  expr: |
    histogram_quantile(0.95, 
      rate(airlock_request_duration_seconds_bucket[5m])
    ) > 0.1
  for: 5m
  labels:
    severity: warning
    service: mcp-airlock
  annotations:
    summary: "MCP Airlock high latency"
    description: "95th percentile latency is {{ $value }}s"
```

#### Audit System Failure
```yaml
- alert: AirlockAuditFailure
  expr: increase(airlock_audit_storage_errors_total[5m]) > 0
  for: 1m
  labels:
    severity: critical
    service: mcp-airlock
  annotations:
    summary: "MCP Airlock audit system failure"
    description: "{{ $value }} audit storage errors in the last 5 minutes"
```

#### Memory Usage
```yaml
- alert: AirlockHighMemoryUsage
  expr: |
    (
      airlock_memory_usage_bytes / 
      airlock_memory_limit_bytes
    ) > 0.9
  for: 5m
  labels:
    severity: warning
    service: mcp-airlock
  annotations:
    summary: "MCP Airlock high memory usage"
    description: "Memory usage is {{ $value | humanizePercentage }}"
```

### Warning Alerts

#### Policy Cache Miss Rate
```yaml
- alert: AirlockPolicyCacheMissRate
  expr: |
    (
      rate(airlock_policy_cache_misses_total[5m]) /
      (rate(airlock_policy_cache_hits_total[5m]) + rate(airlock_policy_cache_misses_total[5m]))
    ) > 0.5
  for: 10m
  labels:
    severity: warning
    service: mcp-airlock
  annotations:
    summary: "MCP Airlock high policy cache miss rate"
    description: "Policy cache miss rate is {{ $value | humanizePercentage }}"
```

#### JWKS Refresh Failures
```yaml
- alert: AirlockJWKSRefreshFailure
  expr: increase(airlock_jwks_refresh_errors_total[10m]) > 0
  for: 1m
  labels:
    severity: warning
    service: mcp-airlock
  annotations:
    summary: "MCP Airlock JWKS refresh failures"
    description: "{{ $value }} JWKS refresh failures in the last 10 minutes"
```

## Dashboards

### Grafana Dashboard

```json
{
  "dashboard": {
    "id": null,
    "title": "MCP Airlock",
    "tags": ["mcp", "airlock", "security"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(airlock_requests_total[5m])",
            "legendFormat": "{{status}} - {{method}}"
          }
        ],
        "yAxes": [
          {
            "label": "Requests/sec",
            "min": 0
          }
        ]
      },
      {
        "id": 2,
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(airlock_request_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          },
          {
            "expr": "histogram_quantile(0.95, rate(airlock_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.99, rate(airlock_request_duration_seconds_bucket[5m]))",
            "legendFormat": "99th percentile"
          }
        ],
        "yAxes": [
          {
            "label": "Seconds",
            "min": 0
          }
        ]
      },
      {
        "id": 3,
        "title": "Authentication Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(airlock_auth_attempts_total{result=\"success\"}[5m]) / rate(airlock_auth_attempts_total[5m])",
            "legendFormat": "Success Rate"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percentunit",
            "min": 0,
            "max": 1,
            "thresholds": {
              "steps": [
                {"color": "red", "value": 0},
                {"color": "yellow", "value": 0.9},
                {"color": "green", "value": 0.95}
              ]
            }
          }
        }
      },
      {
        "id": 4,
        "title": "Policy Decisions",
        "type": "piechart",
        "targets": [
          {
            "expr": "rate(airlock_policy_decisions_total[5m])",
            "legendFormat": "{{decision}}"
          }
        ]
      },
      {
        "id": 5,
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "airlock_memory_usage_bytes",
            "legendFormat": "Used"
          },
          {
            "expr": "airlock_memory_limit_bytes",
            "legendFormat": "Limit"
          }
        ],
        "yAxes": [
          {
            "label": "Bytes",
            "min": 0
          }
        ]
      },
      {
        "id": 6,
        "title": "Active Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "airlock_active_connections",
            "legendFormat": "Connections"
          }
        ]
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "30s"
  }
}
```

## Tracing

### OpenTelemetry Configuration

```yaml
# otel-collector.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: otel-collector-config
data:
  config.yaml: |
    receivers:
      otlp:
        protocols:
          grpc:
            endpoint: 0.0.0.0:4317
          http:
            endpoint: 0.0.0.0:4318
    
    processors:
      batch:
        timeout: 1s
        send_batch_size: 1024
      
      resource:
        attributes:
          - key: service.name
            value: mcp-airlock
            action: upsert
    
    exporters:
      jaeger:
        endpoint: jaeger-collector:14250
        tls:
          insecure: true
      
      logging:
        loglevel: debug
    
    service:
      pipelines:
        traces:
          receivers: [otlp]
          processors: [resource, batch]
          exporters: [jaeger, logging]
```

### Trace Attributes

Airlock includes these trace attributes:
- `tenant` - Tenant ID from JWT
- `user` - User subject from JWT  
- `tool` - MCP tool being called
- `resource` - Resource being accessed
- `decision` - Policy decision (allow/deny)
- `correlation_id` - Request correlation ID
- `upstream` - Upstream server name

### Trace Analysis Queries

```sql
-- Find slow requests
SELECT trace_id, duration_ms, operation_name
FROM traces 
WHERE service_name = 'mcp-airlock' 
  AND duration_ms > 100
ORDER BY duration_ms DESC
LIMIT 10;

-- Find policy denials
SELECT trace_id, tags
FROM traces
WHERE service_name = 'mcp-airlock'
  AND tags LIKE '%decision=deny%'
ORDER BY start_time DESC
LIMIT 20;

-- Analyze authentication patterns
SELECT 
  DATE_TRUNC('hour', start_time) as hour,
  COUNT(*) as auth_attempts,
  COUNT(CASE WHEN tags LIKE '%auth_result=success%' THEN 1 END) as successes
FROM traces
WHERE service_name = 'mcp-airlock'
  AND operation_name = 'authenticate'
GROUP BY hour
ORDER BY hour DESC;
```

## Logging

### Log Structure

All logs are structured JSON with consistent fields:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "info",
  "msg": "request processed",
  "correlation_id": "abc123-def456-ghi789",
  "tenant": "tenant-1",
  "user": "user@example.com",
  "tool": "read_file",
  "resource": "mcp://repo/README.md",
  "decision": "allow",
  "latency_ms": 45,
  "request_size": 256,
  "response_size": 1024
}
```

### Log Aggregation

#### Fluentd Configuration
```yaml
<source>
  @type kubernetes_metadata
  @id input_kubernetes
  
  <parse>
    @type json
    time_key timestamp
    time_format %Y-%m-%dT%H:%M:%S%z
  </parse>
</source>

<filter kubernetes.**>
  @type grep
  <regexp>
    key $.kubernetes.labels.app_kubernetes_io/name
    pattern ^airlock$
  </regexp>
</filter>

<match kubernetes.**>
  @type elasticsearch
  host elasticsearch.logging.svc.cluster.local
  port 9200
  index_name airlock-logs
  type_name _doc
  
  <buffer>
    @type file
    path /var/log/fluentd-buffers/kubernetes.system.buffer
    flush_mode interval
    retry_type exponential_backoff
    flush_thread_count 2
    flush_interval 5s
    retry_forever
    retry_max_interval 30
    chunk_limit_size 2M
    queue_limit_length 8
    overflow_action block
  </buffer>
</match>
```

### Log Analysis Queries

#### Elasticsearch/Kibana Queries

```json
// Authentication failures by user
{
  "query": {
    "bool": {
      "must": [
        {"term": {"level": "error"}},
        {"term": {"msg": "authentication_failed"}},
        {"range": {"timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "aggs": {
    "users": {
      "terms": {"field": "user.keyword"}
    }
  }
}

// Policy denials by reason
{
  "query": {
    "bool": {
      "must": [
        {"term": {"decision": "deny"}},
        {"range": {"timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "aggs": {
    "reasons": {
      "terms": {"field": "reason.keyword"}
    }
  }
}

// High latency requests
{
  "query": {
    "bool": {
      "must": [
        {"range": {"latency_ms": {"gte": 100}}},
        {"range": {"timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "sort": [
    {"latency_ms": {"order": "desc"}}
  ]
}
```

## Health Checks

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
```

### Health Check Responses

#### Liveness Probe (`/health/live`)
```json
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00Z",
  "uptime": "2h15m30s"
}
```

#### Readiness Probe (`/health/ready`)
```json
{
  "status": "ready",
  "timestamp": "2024-01-15T10:30:00Z",
  "checks": {
    "jwks_cache": "ok",
    "policy_engine": "ok",
    "audit_storage": "ok",
    "upstream_connectivity": "ok"
  }
}
```

#### Detailed Health (`/admin/health`)
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "uptime": "2h15m30s",
  "checks": {
    "jwks_cache": {
      "status": "ok",
      "last_refresh": "2024-01-15T10:25:00Z",
      "keys_count": 2
    },
    "policy_engine": {
      "status": "ok",
      "policy_version": "v1.2.3",
      "last_reload": "2024-01-15T09:00:00Z"
    },
    "audit_storage": {
      "status": "ok",
      "backend": "postgresql",
      "connection_pool": "8/10"
    },
    "upstreams": {
      "docs-server": "connected",
      "code-server": "connected"
    }
  },
  "metrics": {
    "requests_per_second": 45.2,
    "error_rate": 0.001,
    "avg_latency_ms": 23,
    "memory_usage_mb": 256,
    "goroutines": 42
  }
}
```

## Performance Monitoring

### SLI/SLO Definitions

#### Service Level Indicators (SLIs)
- **Availability**: Percentage of successful health checks
- **Latency**: 95th percentile response time
- **Error Rate**: Percentage of 5xx responses
- **Throughput**: Requests per second

#### Service Level Objectives (SLOs)
- **Availability**: 99.9% uptime
- **Latency**: 95th percentile < 100ms
- **Error Rate**: < 0.1% of requests
- **Throughput**: Handle 1000+ requests/minute

### Performance Alerts

```yaml
# SLO violation alerts
- alert: AirlockSLOViolationLatency
  expr: |
    histogram_quantile(0.95, 
      rate(airlock_request_duration_seconds_bucket[5m])
    ) > 0.1
  for: 5m
  labels:
    severity: critical
    slo: latency
  annotations:
    summary: "MCP Airlock SLO violation - latency"
    description: "95th percentile latency {{ $value }}s exceeds SLO of 100ms"

- alert: AirlockSLOViolationErrorRate
  expr: |
    (
      rate(airlock_requests_total{status=~"5.."}[5m]) /
      rate(airlock_requests_total[5m])
    ) > 0.001
  for: 2m
  labels:
    severity: critical
    slo: error_rate
  annotations:
    summary: "MCP Airlock SLO violation - error rate"
    description: "Error rate {{ $value | humanizePercentage }} exceeds SLO of 0.1%"
```

This monitoring guide provides comprehensive observability for MCP Airlock, enabling proactive issue detection and performance optimization.
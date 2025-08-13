# Operations Documentation

This section contains operational procedures, troubleshooting guides, and runbooks for MCP Airlock.

## Available Documentation

- [Troubleshooting Runbook](troubleshooting.md) - Common issues and solutions
- [Monitoring Guide](monitoring.md) - Observability and alerting setup
- [Incident Response](incident-response.md) - Emergency procedures
- [Maintenance Procedures](maintenance.md) - Routine operational tasks
- [Performance Tuning](performance-tuning.md) - Optimization guidelines

## Quick Reference

### Health Check Endpoints
- `/health/live` - Liveness probe (always returns 200 if process is running)
- `/health/ready` - Readiness probe (returns 200 when JWKS fetched + policy compiled)
- `/metrics` - Prometheus metrics

### Log Correlation
All requests include a `correlation_id` for tracing across components:
```bash
kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock | grep "correlation_id=abc123"
```

### Emergency Contacts
- **On-call Engineer**: Use PagerDuty escalation
- **Security Team**: security@your-org.com
- **Platform Team**: platform@your-org.com

## Common Commands

```bash
# Check pod status
kubectl get pods -n mcp-airlock

# View recent logs
kubectl logs -n mcp-airlock -l app.kubernetes.io/name=airlock --tail=100

# Check configuration
kubectl get configmap airlock-config -n mcp-airlock -o yaml

# Reload policy
kubectl exec -n mcp-airlock deployment/mcp-airlock -- kill -HUP 1

# Scale deployment
kubectl scale deployment mcp-airlock -n mcp-airlock --replicas=5
```
# Deployment Guide

This section contains comprehensive deployment guides for MCP Airlock.

## Available Guides

- [Quick Start](quickstart.md) - Get up and running quickly
- [Production Deployment](production.md) - Production-ready deployment with security hardening
- [Helm Chart Reference](helm-reference.md) - Complete Helm chart configuration options
- [AWS Deployment](aws-deployment.md) - AWS-specific deployment patterns
- [Configuration Examples](examples/) - Sample configurations for common scenarios

## Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- OIDC provider (Auth0, Okta, Azure AD, etc.)
- Persistent storage for audit logs
- Load balancer with TLS termination

## Architecture Overview

```
Internet → ALB/Ingress → Airlock Pods → MCP Servers (sidecars/services)
                    ↓
                Audit Storage (SQLite PVC / PostgreSQL)
```

## Next Steps

1. Start with the [Quick Start Guide](quickstart.md) for development
2. Follow the [Production Deployment Guide](production.md) for production environments
3. Review [Configuration Examples](examples/) for your specific use case
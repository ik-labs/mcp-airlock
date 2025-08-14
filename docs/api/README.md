# MCP Airlock API Documentation

This document provides comprehensive API documentation for MCP Airlock, including MCP protocol endpoints, administrative endpoints, and monitoring interfaces.

## Overview

MCP Airlock provides several API interfaces:

- **MCP Protocol API**: Standard Model Context Protocol endpoints
- **Administrative API**: Management and configuration endpoints
- **Health Check API**: Service health and readiness endpoints
- **Metrics API**: Prometheus-compatible metrics endpoint

## Base URLs

- **Production**: `https://airlock.your-company.com`
- **Staging**: `https://airlock-staging.your-company.com`
- **Development**: `https://airlock-dev.your-company.com`

## Authentication

All API endpoints (except health checks) require authentication via JWT Bearer tokens obtained from your organization's OIDC provider.

```http
Authorization: Bearer <jwt-token>
```

### Token Requirements

- **Issuer**: Must match configured OIDC issuer
- **Audience**: Must match configured audience (typically `mcp-airlock`)
- **Claims**: Must include required claims (`sub`, `tid`, `groups`)
- **Expiration**: Token must not be expired (with clock skew tolerance)

## MCP Protocol API

### Base Endpoint

```
POST /mcp
Content-Type: application/json
Authorization: Bearer <token>
```

### MCP Message Format

All MCP requests follow the JSON-RPC 2.0 specification:

```json
{
  "jsonrpc": "2.0",
  "id": "unique-request-id",
  "method": "method-name",
  "params": {
    // method-specific parameters
  }
}
```

### Core MCP Methods

#### Initialize Connection

Establish an MCP session with capability negotiation.

```http
POST /mcp
```

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "init-1",
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "roots": {
        "listChanged": true
      },
      "sampling": {}
    },
    "clientInfo": {
      "name": "MyMCPClient",
      "version": "1.0.0"
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "init-1",
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "logging": {},
      "tools": {
        "listChanged": true
      },
      "resources": {
        "subscribe": true,
        "listChanged": true
      }
    },
    "serverInfo": {
      "name": "MCP Airlock",
      "version": "1.0.0"
    }
  }
}
```

#### List Available Tools

Discover tools available to the authenticated user.

```http
POST /mcp
```

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "tools-list-1",
  "method": "tools/list"
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "tools-list-1",
  "result": {
    "tools": [
      {
        "name": "search_docs",
        "description": "Search through documentation",
        "inputSchema": {
          "type": "object",
          "properties": {
            "query": {
              "type": "string",
              "description": "Search query"
            },
            "max_results": {
              "type": "number",
              "description": "Maximum number of results",
              "default": 10
            }
          },
          "required": ["query"]
        }
      },
      {
        "name": "read_file",
        "description": "Read file contents",
        "inputSchema": {
          "type": "object",
          "properties": {
            "path": {
              "type": "string",
              "description": "Virtual file path (e.g., mcp://repo/README.md)"
            }
          },
          "required": ["path"]
        }
      }
    ]
  }
}
```

#### Call Tool

Execute a specific tool with provided arguments.

```http
POST /mcp
```

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "tool-call-1",
  "method": "tools/call",
  "params": {
    "name": "search_docs",
    "arguments": {
      "query": "authentication setup",
      "max_results": 5
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "tool-call-1",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Found 3 documentation entries matching 'authentication setup':\n\n1. Authentication Setup Guide\n   Path: /docs/auth/setup.md\n   Summary: Complete guide for setting up authentication...\n\n2. OIDC Configuration\n   Path: /docs/auth/oidc.md\n   Summary: How to configure OIDC providers...\n\n3. Troubleshooting Authentication\n   Path: /docs/auth/troubleshooting.md\n   Summary: Common authentication issues and solutions..."
      }
    ],
    "isError": false
  }
}
```

#### List Resources

Discover available resources.

```http
POST /mcp
```

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "resources-list-1",
  "method": "resources/list"
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "resources-list-1",
  "result": {
    "resources": [
      {
        "uri": "mcp://repo/README.md",
        "name": "Project README",
        "description": "Main project documentation",
        "mimeType": "text/markdown"
      },
      {
        "uri": "mcp://docs/api/authentication.md",
        "name": "Authentication API Documentation",
        "description": "API authentication guide",
        "mimeType": "text/markdown"
      }
    ]
  }
}
```

#### Read Resource

Read the contents of a specific resource.

```http
POST /mcp
```

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "resource-read-1",
  "method": "resources/read",
  "params": {
    "uri": "mcp://repo/README.md"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "resource-read-1",
  "result": {
    "contents": [
      {
        "uri": "mcp://repo/README.md",
        "mimeType": "text/markdown",
        "text": "# Project Name\n\nThis is the main project documentation...\n\n## Getting Started\n\n..."
      }
    ]
  }
}
```

### Error Responses

All errors follow the JSON-RPC 2.0 error format:

```json
{
  "jsonrpc": "2.0",
  "id": "request-id",
  "error": {
    "code": -32603,
    "message": "Internal error",
    "data": {
      "correlation_id": "abc123def456",
      "reason": "detailed_error_reason"
    }
  }
}
```

#### Standard Error Codes

| Code | Name | Description |
|------|------|-------------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid Request | Invalid JSON-RPC request |
| -32601 | Method not found | Method does not exist |
| -32602 | Invalid params | Invalid method parameters |
| -32603 | Internal error | Internal JSON-RPC error |
| -32000 | Server error | Server-specific error |

#### Airlock-Specific Error Codes

| Code | Name | Description | HTTP Status |
|------|------|-------------|-------------|
| -32600 | Invalid Request | Authentication failed | 401 |
| -32603 | Forbidden | Policy denied request | 403 |
| -32000 | Request Too Large | Message size exceeded | 413 |
| -32000 | Rate Limited | Rate limit exceeded | 429 |
| -32603 | Internal Error | Server error | 500 |
| -32000 | Upstream Error | Upstream server error | 502 |

## Administrative API

Administrative endpoints require elevated privileges (typically `mcp.admins` group).

### Base Endpoint

```
/admin/*
Authorization: Bearer <admin-token>
```

### System Information

#### Get System Status

```http
GET /admin/status
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "build_time": "2024-01-15T10:30:00Z",
  "uptime": "72h30m15s",
  "components": {
    "authentication": "healthy",
    "policy_engine": "healthy",
    "audit_system": "healthy",
    "upstream_servers": "healthy"
  },
  "metrics": {
    "requests_per_minute": 150,
    "active_connections": 25,
    "error_rate": 0.02
  }
}
```

#### Get Configuration

```http
GET /admin/config
```

**Response:**
```json
{
  "auth": {
    "oidc_issuer": "https://your-idp.com",
    "audience": "mcp-airlock",
    "clock_skew": "2m",
    "jwks_cache_ttl": "5m"
  },
  "policy": {
    "engine": "opa",
    "cache_ttl": "1m",
    "last_reload": "2024-01-15T10:00:00Z"
  },
  "rate_limiting": {
    "per_token": "200/min",
    "per_ip": "1000/min"
  }
}
```

### Policy Management

#### Reload Policy

```http
POST /admin/policy/reload
```

**Request:**
```json
{
  "validate_only": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Policy reloaded successfully",
  "timestamp": "2024-01-15T10:30:00Z",
  "validation_result": {
    "valid": true,
    "rules_count": 15,
    "warnings": []
  }
}
```

#### Validate Policy

```http
POST /admin/policy/validate
```

**Request:**
```json
{
  "policy": "package airlock.authz\n\ndefault allow := false\n\nallow if {\n    input.groups[_] == \"users\"\n}"
}
```

**Response:**
```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    "Rule 'allow' could be more specific"
  ],
  "rules_count": 2
}
```

### User Management

#### List Active Users

```http
GET /admin/users/active
```

**Query Parameters:**
- `since`: Time period (e.g., "1h", "24h", "7d")
- `limit`: Maximum number of results (default: 100)

**Response:**
```json
{
  "users": [
    {
      "subject": "user@company.com",
      "tenant": "company-tenant",
      "groups": ["mcp.users", "developers"],
      "last_activity": "2024-01-15T10:25:00Z",
      "request_count": 45,
      "error_count": 2
    }
  ],
  "total": 1,
  "period": "24h"
}
```

#### Get User Activity

```http
GET /admin/users/{subject}/activity
```

**Query Parameters:**
- `since`: Time period (default: "24h")
- `include_errors`: Include error events (default: false)

**Response:**
```json
{
  "subject": "user@company.com",
  "tenant": "company-tenant",
  "activity": [
    {
      "timestamp": "2024-01-15T10:25:00Z",
      "action": "tool_call",
      "tool": "search_docs",
      "decision": "allow",
      "latency_ms": 45
    }
  ],
  "summary": {
    "total_requests": 45,
    "successful_requests": 43,
    "failed_requests": 2,
    "avg_latency_ms": 52
  }
}
```

### Audit Management

#### Query Audit Logs

```http
GET /admin/audit/query
```

**Query Parameters:**
- `since`: Start time (ISO 8601 or relative like "1h")
- `until`: End time (ISO 8601, default: now)
- `subject`: Filter by user subject
- `tenant`: Filter by tenant
- `action`: Filter by action type
- `decision`: Filter by decision (allow/deny)
- `limit`: Maximum results (default: 100)
- `offset`: Pagination offset (default: 0)

**Response:**
```json
{
  "events": [
    {
      "id": "audit-123456",
      "timestamp": "2024-01-15T10:25:00Z",
      "correlation_id": "req-abc123",
      "subject": "user@company.com",
      "tenant": "company-tenant",
      "action": "tool_call",
      "decision": "allow",
      "reason": "policy_allowed",
      "latency_ms": 45,
      "redaction_count": 0,
      "metadata": {
        "tool": "search_docs",
        "source_ip": "192.168.1.100"
      }
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

#### Export Audit Logs

```http
POST /admin/audit/export
```

**Request:**
```json
{
  "format": "jsonl",
  "since": "2024-01-01T00:00:00Z",
  "until": "2024-01-15T23:59:59Z",
  "filters": {
    "tenant": "company-tenant",
    "actions": ["tool_call", "policy_evaluate"]
  }
}
```

**Response:**
```json
{
  "export_id": "export-789",
  "status": "processing",
  "download_url": "/admin/audit/export/export-789/download",
  "expires_at": "2024-01-16T10:30:00Z"
}
```

### Security Management

#### Block IP Address

```http
POST /admin/security/block
```

**Request:**
```json
{
  "ip_addresses": ["192.168.1.100", "10.0.0.50"],
  "duration": "1h",
  "reason": "Suspicious activity detected"
}
```

**Response:**
```json
{
  "success": true,
  "blocked_ips": ["192.168.1.100", "10.0.0.50"],
  "expires_at": "2024-01-15T11:30:00Z"
}
```

#### List Security Violations

```http
GET /admin/security/violations
```

**Query Parameters:**
- `since`: Time period (default: "24h")
- `severity`: Filter by severity (low/medium/high/critical)
- `type`: Filter by violation type

**Response:**
```json
{
  "violations": [
    {
      "id": "violation-456",
      "timestamp": "2024-01-15T10:20:00Z",
      "type": "path_traversal",
      "severity": "high",
      "subject": "attacker@evil.com",
      "source_ip": "192.168.1.100",
      "details": {
        "attempted_path": "mcp://repo/../../../etc/passwd",
        "blocked": true
      }
    }
  ],
  "total": 1
}
```

## Health Check API

Health check endpoints are publicly accessible and don't require authentication.

### Liveness Check

```http
GET /live
```

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Readiness Check

```http
GET /ready
```

**Response:**
```json
{
  "status": "ready",
  "timestamp": "2024-01-15T10:30:00Z",
  "checks": {
    "database": "ok",
    "policy_engine": "ok",
    "upstream_servers": "ok",
    "oidc_provider": "ok"
  }
}
```

### Service Information

```http
GET /info
```

**Response:**
```json
{
  "name": "MCP Airlock",
  "version": "1.0.0",
  "build_time": "2024-01-15T10:00:00Z",
  "git_commit": "abc123def456",
  "go_version": "go1.21.5",
  "uptime": "72h30m15s"
}
```

## Metrics API

Prometheus-compatible metrics endpoint.

### Get Metrics

```http
GET /metrics
```

**Response:**
```
# HELP airlock_requests_total Total number of requests
# TYPE airlock_requests_total counter
airlock_requests_total{method="tools/call",status="success"} 1234
airlock_requests_total{method="tools/call",status="error"} 56

# HELP airlock_request_duration_seconds Request duration in seconds
# TYPE airlock_request_duration_seconds histogram
airlock_request_duration_seconds_bucket{method="tools/call",le="0.01"} 100
airlock_request_duration_seconds_bucket{method="tools/call",le="0.05"} 500
airlock_request_duration_seconds_bucket{method="tools/call",le="0.1"} 800
airlock_request_duration_seconds_bucket{method="tools/call",le="+Inf"} 1000
airlock_request_duration_seconds_sum{method="tools/call"} 45.5
airlock_request_duration_seconds_count{method="tools/call"} 1000

# HELP airlock_active_connections Current number of active connections
# TYPE airlock_active_connections gauge
airlock_active_connections 25

# HELP airlock_policy_evaluations_total Total number of policy evaluations
# TYPE airlock_policy_evaluations_total counter
airlock_policy_evaluations_total{decision="allow"} 2000
airlock_policy_evaluations_total{decision="deny"} 100

# HELP airlock_redaction_events_total Total number of redaction events
# TYPE airlock_redaction_events_total counter
airlock_redaction_events_total{pattern="email"} 50
airlock_redaction_events_total{pattern="ssn"} 25
```

## Rate Limiting

All API endpoints are subject to rate limiting based on:

- **Per-token limits**: Default 200 requests/minute
- **Per-IP limits**: Default 1000 requests/minute
- **Burst allowance**: Configurable burst capacity

### Rate Limit Headers

Rate limit information is included in response headers:

```http
X-RateLimit-Limit: 200
X-RateLimit-Remaining: 150
X-RateLimit-Reset: 1642248600
X-RateLimit-Retry-After: 60
```

### Rate Limit Exceeded Response

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 200
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1642248600
X-RateLimit-Retry-After: 60
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": "request-id",
  "error": {
    "code": -32000,
    "message": "Rate limit exceeded",
    "data": {
      "retry_after": 60,
      "limit": 200,
      "window": "1m"
    }
  }
}
```

## WebSocket API (Server-Sent Events)

For real-time communication, MCP Airlock supports Server-Sent Events (SSE) over HTTP.

### Establish SSE Connection

```http
GET /mcp/stream
Accept: text/event-stream
Authorization: Bearer <token>
```

**Response:**
```
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive

event: connected
data: {"status":"connected","session_id":"session-123"}

event: heartbeat
data: {"timestamp":"2024-01-15T10:30:00Z"}

event: message
data: {"jsonrpc":"2.0","id":"notification-1","method":"tools/list_changed","params":{"tools":[]}}
```

### SSE Event Types

- **connected**: Connection established
- **heartbeat**: Periodic heartbeat (every 30 seconds)
- **message**: MCP protocol message
- **error**: Error notification
- **disconnected**: Connection terminated

## SDK and Client Libraries

### Official SDKs

- **Go**: `github.com/your-org/mcp-airlock-go`
- **Python**: `pip install mcp-airlock-python`
- **JavaScript/TypeScript**: `npm install @your-org/mcp-airlock-js`

### Example Usage

#### Go Client

```go
package main

import (
    "context"
    "fmt"
    "github.com/your-org/mcp-airlock-go"
)

func main() {
    client := airlock.NewClient("https://airlock.your-company.com", "your-jwt-token")
    
    tools, err := client.ListTools(context.Background())
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Available tools: %+v\n", tools)
}
```

#### Python Client

```python
from mcp_airlock import AirlockClient

client = AirlockClient("https://airlock.your-company.com", "your-jwt-token")

tools = client.list_tools()
print(f"Available tools: {tools}")

result = client.call_tool("search_docs", {"query": "authentication"})
print(f"Search results: {result}")
```

#### JavaScript Client

```javascript
import { AirlockClient } from '@your-org/mcp-airlock-js';

const client = new AirlockClient('https://airlock.your-company.com', 'your-jwt-token');

async function main() {
  const tools = await client.listTools();
  console.log('Available tools:', tools);
  
  const result = await client.callTool('search_docs', { query: 'authentication' });
  console.log('Search results:', result);
}

main().catch(console.error);
```

## Error Handling Best Practices

### Retry Logic

Implement exponential backoff for transient errors:

```javascript
async function callWithRetry(fn, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (error.code === -32000 && error.message.includes('rate limit')) {
        const delay = Math.pow(2, i) * 1000; // Exponential backoff
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      throw error;
    }
  }
}
```

### Error Classification

Handle different error types appropriately:

```python
def handle_airlock_error(error):
    if error.code == -32600:  # Authentication failed
        # Refresh token and retry
        refresh_token()
        return "retry"
    elif error.code == -32603:  # Policy denied
        # Log and notify user
        log_policy_denial(error.data)
        return "deny"
    elif error.code == -32000:  # Rate limited
        # Wait and retry
        time.sleep(error.data.get('retry_after', 60))
        return "retry"
    else:
        # Unknown error
        log_error(error)
        return "fail"
```

## Security Considerations

### Token Security

- Store tokens securely (environment variables, secure storage)
- Implement automatic token refresh
- Never log or expose tokens in error messages
- Use short-lived tokens when possible

### Request Security

- Validate all inputs before sending requests
- Implement request signing for sensitive operations
- Use HTTPS for all communications
- Implement proper timeout handling

### Data Handling

- Be aware that requests may be logged and audited
- Sensitive data is automatically redacted by Airlock
- Implement client-side data classification
- Follow data retention policies

## Troubleshooting

### Common Issues

#### Authentication Failures

```json
{
  "error": {
    "code": -32600,
    "message": "Authentication failed",
    "data": {
      "reason": "invalid_token",
      "correlation_id": "abc123"
    }
  }
}
```

**Solutions:**
- Check token format and expiration
- Verify OIDC configuration
- Ensure required claims are present

#### Policy Denials

```json
{
  "error": {
    "code": -32603,
    "message": "Policy denied request",
    "data": {
      "reason": "insufficient_permissions",
      "rule_id": "rule-123",
      "correlation_id": "def456"
    }
  }
}
```

**Solutions:**
- Check user group memberships
- Review policy rules
- Contact administrator for access

#### Rate Limiting

```json
{
  "error": {
    "code": -32000,
    "message": "Rate limit exceeded",
    "data": {
      "retry_after": 60
    }
  }
}
```

**Solutions:**
- Implement exponential backoff
- Reduce request frequency
- Consider request batching

### Debug Mode

Enable debug mode for detailed error information:

```http
X-Debug: true
```

This will include additional debugging information in error responses (not recommended for production).

---

For additional support and examples, see the [Developer Onboarding Guide](../onboarding/developer-onboarding.md) and [Troubleshooting Guide](../operations/troubleshooting.md).
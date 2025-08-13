# API Documentation

This section contains comprehensive API documentation and integration examples for MCP Airlock.

## Available Documentation

- [MCP Protocol Integration](mcp-protocol.md) - MCP protocol implementation details
- [Authentication API](authentication.md) - Authentication and token handling
- [Configuration API](configuration.md) - Configuration management endpoints
- [Health and Monitoring](health-monitoring.md) - Health checks and metrics
- [Integration Examples](examples/) - Code examples and integration patterns

## Quick Start

### Basic MCP Client Connection

```typescript
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

// Create transport with authentication
const transport = new SSEClientTransport(
  new URL('https://your-airlock-domain/mcp/v1/sse'),
  {
    headers: {
      'Authorization': `Bearer ${your_jwt_token}`,
      'Content-Type': 'application/json'
    }
  }
);

// Create MCP client
const client = new Client(
  {
    name: "my-mcp-client",
    version: "1.0.0"
  },
  {
    capabilities: {
      tools: {},
      resources: {}
    }
  }
);

// Connect and initialize
await client.connect(transport);
const result = await client.initialize();
console.log('Connected to MCP Airlock:', result);
```

### Authentication Flow

```bash
# 1. Obtain JWT token from your OIDC provider
curl -X POST https://your-oidc-provider/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=your-client-id&client_secret=your-secret&scope=mcp.access"

# 2. Use token with MCP Airlock
curl -H "Authorization: Bearer $JWT_TOKEN" \
     https://your-airlock-domain/mcp/v1/initialize
```

## API Endpoints

### MCP Protocol Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp/v1/initialize` | POST | Initialize MCP session |
| `/mcp/v1/sse` | GET | Server-Sent Events transport |
| `/mcp/v1/tools/list` | POST | List available tools |
| `/mcp/v1/tools/call` | POST | Call a specific tool |
| `/mcp/v1/resources/list` | POST | List available resources |
| `/mcp/v1/resources/read` | POST | Read a specific resource |

### Health and Monitoring

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health/live` | GET | Liveness probe |
| `/health/ready` | GET | Readiness probe |
| `/metrics` | GET | Prometheus metrics |

### Administrative Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/admin/reload` | POST | Reload configuration | Admin token |
| `/admin/policy/validate` | POST | Validate policy | Admin token |
| `/admin/health` | GET | Detailed health status | Admin token |

## Error Handling

All API responses follow the MCP error format:

```json
{
  "error": {
    "code": "InvalidRequest",
    "message": "Authentication failed",
    "data": {
      "reason": "invalid_token",
      "www_authenticate": "Bearer realm=\"mcp-airlock\"",
      "correlation_id": "abc123-def456-ghi789"
    }
  }
}
```

### Common Error Codes

| HTTP Status | MCP Error Code | Description |
|-------------|----------------|-------------|
| 400 | InvalidRequest | Malformed request or invalid parameters |
| 401 | InvalidRequest | Authentication required or failed |
| 403 | Forbidden | Authorization denied by policy |
| 413 | RequestTooLarge | Request exceeds size limits |
| 429 | TooManyRequests | Rate limit exceeded |
| 500 | InternalError | Server error (check correlation_id) |
| 502 | InternalError | Upstream server error |
| 503 | InternalError | Service temporarily unavailable |

## Rate Limiting

Airlock implements multiple levels of rate limiting:

### Per-Token Limits
- Default: 200 requests per minute
- Configurable per tenant/group
- Sliding window implementation

### Per-IP Limits  
- Default: 1000 requests per minute
- Protects against distributed attacks
- Shared across all tokens from same IP

### Response Headers
```http
X-RateLimit-Limit: 200
X-RateLimit-Remaining: 150
X-RateLimit-Reset: 1640995200
X-RateLimit-Retry-After: 30
```

## Authentication

### JWT Token Requirements

```json
{
  "iss": "https://your-oidc-provider",
  "aud": "mcp-airlock",
  "sub": "user@example.com",
  "tid": "tenant-123",
  "groups": ["mcp.users", "engineering"],
  "exp": 1640995200,
  "iat": 1640991600,
  "nbf": 1640991600
}
```

### Required Claims
- `iss` - Token issuer (must match configured OIDC provider)
- `aud` - Audience (must match configured audience)
- `sub` - Subject (user identifier)
- `tid` - Tenant ID (for multi-tenant isolation)
- `groups` - User groups (for authorization)
- `exp` - Expiration time
- `iat` - Issued at time

### Optional Claims
- `nbf` - Not before time
- `jti` - JWT ID (for token tracking)
- `scope` - OAuth2 scopes

## Request/Response Examples

### Initialize Session

**Request:**
```http
POST /mcp/v1/initialize HTTP/1.1
Host: your-airlock-domain
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": {},
      "resources": {}
    },
    "clientInfo": {
      "name": "my-client",
      "version": "1.0.0"
    }
  }
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Correlation-ID: abc123-def456-ghi789

{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": {
        "listChanged": true
      },
      "resources": {
        "subscribe": true,
        "listChanged": true
      }
    },
    "serverInfo": {
      "name": "mcp-airlock",
      "version": "1.0.0"
    }
  }
}
```

### List Tools

**Request:**
```http
POST /mcp/v1/tools/list HTTP/1.1
Host: your-airlock-domain
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list"
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "read_file",
        "description": "Read contents of a file",
        "inputSchema": {
          "type": "object",
          "properties": {
            "path": {
              "type": "string",
              "description": "Path to the file to read"
            }
          },
          "required": ["path"]
        }
      },
      {
        "name": "search_docs",
        "description": "Search documentation",
        "inputSchema": {
          "type": "object",
          "properties": {
            "query": {
              "type": "string",
              "description": "Search query"
            }
          },
          "required": ["query"]
        }
      }
    ]
  }
}
```

### Call Tool

**Request:**
```http
POST /mcp/v1/tools/call HTTP/1.1
Host: your-airlock-domain
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {
      "path": "mcp://repo/README.md"
    }
  }
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "# My Project\n\nThis is a sample README file...\n\nContact: [redacted-email] for more information."
      }
    ],
    "isError": false
  }
}
```

### Error Response Example

**Request:**
```http
POST /mcp/v1/tools/call HTTP/1.1
Host: your-airlock-domain
Authorization: Bearer invalid-token
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {
      "path": "/etc/passwd"
    }
  }
}
```

**Response:**
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
WWW-Authenticate: Bearer realm="mcp-airlock"

{
  "jsonrpc": "2.0",
  "id": 4,
  "error": {
    "code": "InvalidRequest",
    "message": "Authentication failed",
    "data": {
      "reason": "invalid_token",
      "www_authenticate": "Bearer realm=\"mcp-airlock\"",
      "correlation_id": "def456-ghi789-jkl012"
    }
  }
}
```

## Server-Sent Events (SSE)

For real-time communication, Airlock supports SSE transport:

### Connection Setup

```javascript
const eventSource = new EventSource('https://your-airlock-domain/mcp/v1/sse', {
  headers: {
    'Authorization': `Bearer ${jwt_token}`
  }
});

eventSource.onmessage = function(event) {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
};

eventSource.onerror = function(event) {
  console.error('SSE error:', event);
};
```

### Message Format

All SSE messages follow JSON-RPC 2.0 format:

```
data: {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}

data: {"jsonrpc":"2.0","id":1,"result":{"tools":[...]}}

: heartbeat

data: {"jsonrpc":"2.0","id":2,"error":{"code":"Forbidden","message":"Access denied"}}
```

### Heartbeat

Airlock sends heartbeat comments every 20 seconds to prevent connection timeouts:

```
: heartbeat
```

## Integration Patterns

### Retry Logic

```typescript
async function callToolWithRetry(client: Client, toolName: string, args: any, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await client.callTool({ name: toolName, arguments: args });
    } catch (error) {
      if (error.code === 'TooManyRequests' && attempt < maxRetries) {
        const retryAfter = error.data?.retry_after || Math.pow(2, attempt);
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        continue;
      }
      throw error;
    }
  }
}
```

### Connection Management

```typescript
class AirlockClient {
  private client: Client;
  private transport: SSEClientTransport;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;

  async connect(token: string) {
    this.transport = new SSEClientTransport(
      new URL('https://your-airlock-domain/mcp/v1/sse'),
      {
        headers: { 'Authorization': `Bearer ${token}` }
      }
    );

    this.transport.onclose = () => this.handleDisconnect();
    this.transport.onerror = (error) => this.handleError(error);

    await this.client.connect(this.transport);
  }

  private async handleDisconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
      
      setTimeout(() => {
        this.connect(this.getCurrentToken());
      }, delay);
    }
  }
}
```

### Error Handling

```typescript
function handleAirlockError(error: any) {
  switch (error.code) {
    case 'InvalidRequest':
      if (error.data?.reason === 'invalid_token') {
        // Refresh token and retry
        return refreshTokenAndRetry();
      }
      break;
      
    case 'Forbidden':
      // Log policy denial for debugging
      console.error('Access denied:', {
        reason: error.data?.reason,
        rule_id: error.data?.rule_id,
        correlation_id: error.data?.correlation_id
      });
      break;
      
    case 'RequestTooLarge':
      // Split request into smaller chunks
      return splitAndRetry();
      
    case 'TooManyRequests':
      // Implement exponential backoff
      const retryAfter = error.data?.retry_after || 60;
      return new Promise(resolve => 
        setTimeout(resolve, retryAfter * 1000)
      );
  }
  
  throw error;
}
```

## SDK Integration

### Official MCP SDK

```bash
npm install @modelcontextprotocol/sdk
```

```typescript
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

const client = new Client(
  { name: "my-app", version: "1.0.0" },
  { capabilities: { tools: {}, resources: {} } }
);

const transport = new SSEClientTransport(
  new URL('https://your-airlock-domain/mcp/v1/sse'),
  { headers: { 'Authorization': `Bearer ${token}` } }
);

await client.connect(transport);
```

### Custom HTTP Client

```python
import requests
import json

class AirlockClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        })
    
    def call_tool(self, name: str, arguments: dict) -> dict:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }
        
        response = self.session.post(
            f"{self.base_url}/mcp/v1/tools/call",
            json=payload
        )
        
        if response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}: {response.text}")
        
        result = response.json()
        if "error" in result:
            raise Exception(f"MCP Error: {result['error']}")
        
        return result["result"]

# Usage
client = AirlockClient("https://your-airlock-domain", "your-jwt-token")
result = client.call_tool("read_file", {"path": "mcp://repo/README.md"})
```

## Testing and Development

### Local Development Setup

```bash
# Start local Airlock instance
kubectl port-forward -n mcp-airlock svc/mcp-airlock 8080:80

# Test with curl
curl -H "Authorization: Bearer $DEV_TOKEN" \
     http://localhost:8080/health/ready

# Test MCP initialization
curl -H "Authorization: Bearer $DEV_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}' \
     http://localhost:8080/mcp/v1/initialize
```

### Mock Server for Testing

```typescript
// Mock Airlock server for testing
import express from 'express';

const app = express();
app.use(express.json());

app.post('/mcp/v1/initialize', (req, res) => {
  res.json({
    jsonrpc: "2.0",
    id: req.body.id,
    result: {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {}, resources: {} },
      serverInfo: { name: "mock-airlock", version: "1.0.0" }
    }
  });
});

app.post('/mcp/v1/tools/list', (req, res) => {
  res.json({
    jsonrpc: "2.0",
    id: req.body.id,
    result: {
      tools: [
        {
          name: "echo",
          description: "Echo input",
          inputSchema: {
            type: "object",
            properties: { text: { type: "string" } },
            required: ["text"]
          }
        }
      ]
    }
  });
});

app.listen(3000, () => console.log('Mock Airlock running on port 3000'));
```

This API documentation provides comprehensive guidance for integrating with MCP Airlock, including authentication, error handling, and best practices for reliable client implementations.
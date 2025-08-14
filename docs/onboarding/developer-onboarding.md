# Developer Onboarding Guide

This guide helps developers get started with MCP Airlock, from obtaining access credentials to making their first successful MCP tool calls.

## Overview

MCP Airlock is a zero-trust gateway that provides secure access to Model Context Protocol (MCP) servers. As a developer, you'll interact with Airlock to:

- Access documentation and code repositories
- Execute analysis and development tools
- Generate reports and insights
- Manage artifacts and deployments

## Getting Started (5 minutes)

### 1. Obtain Access Credentials

Contact your administrator to get:
- **Airlock Endpoint**: `https://airlock.your-company.com`
- **Identity Provider Access**: Account in your organization's IdP (Okta, Azure AD, etc.)
- **Group Membership**: Added to appropriate groups (e.g., `mcp.users`, `developers`)

### 2. Get Your JWT Token

#### Option A: Using OIDC Device Flow (Recommended)
```bash
# Install oidc-cli tool
go install github.com/int128/kubelogin/cmd/kubelogin@latest

# Get token using device flow
kubelogin get-token \
  --oidc-issuer-url=https://your-idp.com \
  --oidc-client-id=your-client-id \
  --oidc-extra-scope=groups

# Export token for use
export AIRLOCK_TOKEN="your-jwt-token-here"
```

#### Option B: Manual Browser Flow
1. Visit: `https://airlock.your-company.com/auth/login`
2. Complete authentication with your IdP
3. Copy the JWT token from the response
4. Export: `export AIRLOCK_TOKEN="your-jwt-token-here"`

### 3. Test Your Connection

```bash
# Test authentication
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRLOCK_TOKEN" \
  -d '{"jsonrpc":"2.0","id":"test","method":"tools/list"}'

# Expected response: List of available tools
```

## Understanding MCP Airlock

### Architecture Overview

```
Your IDE/Client → HTTPS → MCP Airlock → Internal MCP Servers
                          ↓
                    [Auth, Policy, Audit, DLP]
```

### Security Layers

1. **Authentication**: JWT token validation via OIDC
2. **Authorization**: Policy-based access control
3. **Data Loss Prevention**: Automatic PII redaction
4. **Audit Logging**: Complete activity tracking
5. **Root Virtualization**: Sandboxed file system access

### Virtual Root Mapping

Airlock maps virtual URIs to real resources:
- `mcp://repo/` → Your code repositories
- `mcp://docs/` → Documentation and wikis  
- `mcp://artifacts/` → Build artifacts and reports
- `mcp://workspace/` → Your personal workspace

## Common Development Workflows

### 1. Documentation Search and Access

#### Search Documentation
```bash
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRLOCK_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "search-docs",
    "method": "tools/call",
    "params": {
      "name": "search_docs",
      "arguments": {
        "query": "authentication setup",
        "max_results": 10
      }
    }
  }'
```

#### Read Documentation File
```bash
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRLOCK_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "read-doc",
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {
        "path": "mcp://docs/api/authentication.md"
      }
    }
  }'
```

### 2. Code Repository Access

#### List Repository Contents
```bash
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRLOCK_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "list-repo",
    "method": "tools/call",
    "params": {
      "name": "list_directory",
      "arguments": {
        "path": "mcp://repo/src"
      }
    }
  }'
```

#### Read Source Code
```bash
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRLOCK_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "read-code",
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {
        "path": "mcp://repo/src/main.go"
      }
    }
  }'
```

### 3. Code Analysis and Tools

#### Run Code Analysis
```bash
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRLOCK_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "analyze-code",
    "method": "tools/call",
    "params": {
      "name": "analyze_code",
      "arguments": {
        "file_path": "mcp://repo/src/main.go",
        "analysis_type": "security"
      }
    }
  }'
```

#### Generate Code Metrics
```bash
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRLOCK_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "code-metrics",
    "method": "tools/call",
    "params": {
      "name": "generate_metrics",
      "arguments": {
        "path": "mcp://repo/",
        "metrics": ["complexity", "coverage", "quality"]
      }
    }
  }'
```

### 4. Artifact Management

#### Upload Build Artifacts
```bash
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRLOCK_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "upload-artifact",
    "method": "tools/call",
    "params": {
      "name": "upload_file",
      "arguments": {
        "source_path": "mcp://workspace/build/app.tar.gz",
        "destination_path": "mcp://artifacts/releases/v1.2.3/app.tar.gz"
      }
    }
  }'
```

#### Generate Reports
```bash
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRLOCK_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "generate-report",
    "method": "tools/call",
    "params": {
      "name": "generate_report",
      "arguments": {
        "report_type": "test_coverage",
        "source_path": "mcp://repo/test-results/",
        "output_path": "mcp://artifacts/reports/coverage-report.html"
      }
    }
  }'
```

## IDE Integration

### VS Code Extension

1. **Install MCP Extension**
   ```bash
   # Install from VS Code marketplace
   code --install-extension your-org.mcp-airlock
   ```

2. **Configure Extension**
   ```json
   // settings.json
   {
     "mcp.airlock.endpoint": "https://airlock.your-company.com",
     "mcp.airlock.tokenCommand": "kubelogin get-token --oidc-issuer-url=https://your-idp.com --oidc-client-id=your-client-id",
     "mcp.airlock.autoRefreshToken": true
   }
   ```

3. **Use MCP Features**
   - **Command Palette**: `Ctrl+Shift+P` → "MCP: Search Documentation"
   - **Explorer**: Right-click → "MCP: Analyze File"
   - **Terminal**: Integrated MCP commands

### JetBrains IDEs

1. **Install Plugin**
   - Go to Settings → Plugins → Browse repositories
   - Search for "MCP Airlock" and install

2. **Configure Plugin**
   ```properties
   # mcp-airlock.properties
   endpoint=https://airlock.your-company.com
   token.command=kubelogin get-token --oidc-issuer-url=https://your-idp.com --oidc-client-id=your-client-id
   auto.refresh=true
   ```

### Command Line Tools

#### MCP CLI Tool

1. **Install CLI**
   ```bash
   # Download from releases
   curl -L https://github.com/your-org/mcp-cli/releases/latest/download/mcp-cli-linux-amd64 -o mcp
   chmod +x mcp
   sudo mv mcp /usr/local/bin/
   ```

2. **Configure CLI**
   ```bash
   # Initialize configuration
   mcp config init \
     --endpoint https://airlock.your-company.com \
     --token-command "kubelogin get-token --oidc-issuer-url=https://your-idp.com --oidc-client-id=your-client-id"
   ```

3. **Use CLI Commands**
   ```bash
   # List available tools
   mcp tools list
   
   # Search documentation
   mcp docs search "API authentication"
   
   # Read file
   mcp file read mcp://repo/README.md
   
   # Analyze code
   mcp code analyze mcp://repo/src/main.go --type security
   ```

## Authentication and Token Management

### Token Lifecycle

1. **Token Acquisition**: Get JWT from IdP via OIDC flow
2. **Token Validation**: Airlock validates signature and claims
3. **Token Refresh**: Automatic refresh before expiration
4. **Token Revocation**: Logout or admin revocation

### Token Best Practices

- **Never hardcode tokens** in source code
- **Use environment variables** or secure credential stores
- **Rotate tokens regularly** (automatic with OIDC refresh)
- **Revoke tokens** when no longer needed

### Token Troubleshooting

#### Invalid Token Error
```bash
# Check token expiration
echo $AIRLOCK_TOKEN | cut -d. -f2 | base64 -d | jq .exp

# Compare with current time
date +%s

# Refresh token if expired
kubelogin get-token --oidc-issuer-url=https://your-idp.com --oidc-client-id=your-client-id
```

#### Permission Denied Error
```bash
# Check token claims
echo $AIRLOCK_TOKEN | cut -d. -f2 | base64 -d | jq .

# Verify groups membership
echo $AIRLOCK_TOKEN | cut -d. -f2 | base64 -d | jq .groups

# Contact admin if groups are missing
```

## Understanding Policies and Permissions

### Policy Structure

Policies control what tools you can use and what resources you can access:

```rego
# Example policy snippet
allow if {
    input.groups[_] == "developers"
    input.tool in ["read_file", "search_docs", "analyze_code"]
    startswith(input.resource, "mcp://repo/")
}
```

### Common Permission Groups

- **`mcp.users`**: Basic MCP access
- **`developers`**: Code repository access
- **`mcp.power_users`**: Extended tool access
- **`mcp.writers`**: Write access to artifacts
- **`mcp.admins`**: Administrative functions

### Testing Your Permissions

```bash
# Test tool access
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRLOCK_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "test-permission",
    "method": "tools/call",
    "params": {
      "name": "test_tool",
      "arguments": {}
    }
  }'

# Check response for policy decisions
```

## Error Handling and Troubleshooting

### Common Error Responses

#### Authentication Errors (401)
```json
{
  "jsonrpc": "2.0",
  "id": "test",
  "error": {
    "code": -32600,
    "message": "Authentication failed",
    "data": {
      "reason": "invalid_token",
      "www_authenticate": "Bearer realm=\"mcp-airlock\"",
      "correlation_id": "abc123"
    }
  }
}
```

**Solution**: Refresh your token or check token format

#### Authorization Errors (403)
```json
{
  "jsonrpc": "2.0",
  "id": "test",
  "error": {
    "code": -32603,
    "message": "Policy denied request",
    "data": {
      "reason": "insufficient_permissions",
      "rule_id": "rule-deny-123",
      "correlation_id": "def456"
    }
  }
}
```

**Solution**: Contact admin to review your group memberships

#### Rate Limiting (429)
```json
{
  "jsonrpc": "2.0",
  "id": "test",
  "error": {
    "code": -32000,
    "message": "Rate limit exceeded",
    "data": {
      "retry_after": 60,
      "correlation_id": "ghi789"
    }
  }
}
```

**Solution**: Wait and retry, or optimize request patterns

#### Resource Not Found (404)
```json
{
  "jsonrpc": "2.0",
  "id": "test",
  "error": {
    "code": -32601,
    "message": "Resource not found",
    "data": {
      "resource": "mcp://repo/nonexistent.txt",
      "correlation_id": "jkl012"
    }
  }
}
```

**Solution**: Check resource path and permissions

### Debugging Tips

1. **Use Correlation IDs**: Include correlation ID when reporting issues
2. **Check Logs**: Ask admin to check Airlock logs with correlation ID
3. **Validate Tokens**: Use JWT debugging tools to inspect token claims
4. **Test Incrementally**: Start with simple requests and build complexity

### Getting Help

#### Self-Service Debugging

```bash
# Check service health
curl https://airlock.your-company.com/live

# Validate token format
echo $AIRLOCK_TOKEN | cut -d. -f2 | base64 -d | jq .

# Test basic connectivity
curl -I https://airlock.your-company.com/ready
```

#### Contacting Support

When reporting issues, include:
- **Correlation ID** from error response
- **Request payload** (sanitized)
- **Expected vs actual behavior**
- **Token claims** (sanitized)
- **Timestamp** of the issue

## Advanced Usage

### Batch Operations

```bash
# Process multiple files
for file in $(mcp file list mcp://repo/src/*.go); do
  mcp code analyze "$file" --type security
done
```

### Custom Scripts

```python
#!/usr/bin/env python3
import requests
import json
import os

class MCPClient:
    def __init__(self, endpoint, token):
        self.endpoint = endpoint
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        })
    
    def call_tool(self, tool_name, arguments=None):
        payload = {
            "jsonrpc": "2.0",
            "id": f"python-client-{tool_name}",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments or {}
            }
        }
        
        response = self.session.post(f"{self.endpoint}/mcp", json=payload)
        return response.json()
    
    def search_docs(self, query, max_results=10):
        return self.call_tool("search_docs", {
            "query": query,
            "max_results": max_results
        })
    
    def read_file(self, path):
        return self.call_tool("read_file", {"path": path})

# Usage
client = MCPClient(
    endpoint="https://airlock.your-company.com",
    token=os.environ["AIRLOCK_TOKEN"]
)

# Search for documentation
docs = client.search_docs("authentication")
print(json.dumps(docs, indent=2))

# Read a file
content = client.read_file("mcp://repo/README.md")
print(json.dumps(content, indent=2))
```

### Performance Optimization

#### Request Batching
```bash
# Instead of multiple individual requests
# Batch related operations when possible
curl -X POST https://airlock.your-company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AIRLOCK_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "batch-analysis",
    "method": "tools/call",
    "params": {
      "name": "batch_analyze",
      "arguments": {
        "files": [
          "mcp://repo/src/main.go",
          "mcp://repo/src/handler.go",
          "mcp://repo/src/auth.go"
        ],
        "analysis_type": "security"
      }
    }
  }'
```

#### Caching Results
```bash
# Cache frequently accessed data locally
mkdir -p ~/.mcp-cache

# Check cache before making requests
if [ ! -f ~/.mcp-cache/docs-index.json ]; then
  mcp docs list > ~/.mcp-cache/docs-index.json
fi
```

## Security Best Practices

### Token Security

- **Environment Variables**: Store tokens in environment variables
- **Credential Managers**: Use OS credential managers when available
- **Temporary Tokens**: Use short-lived tokens when possible
- **Token Rotation**: Implement automatic token refresh

### Request Security

- **Input Validation**: Validate all inputs before sending requests
- **Path Sanitization**: Avoid path traversal attempts
- **Rate Limiting**: Respect rate limits and implement backoff
- **Error Handling**: Don't expose sensitive data in error messages

### Data Handling

- **Sensitive Data**: Be aware that requests may be logged and audited
- **PII Protection**: Airlock automatically redacts PII, but be cautious
- **Data Classification**: Understand data sensitivity levels
- **Retention**: Be aware of audit log retention policies

## Development Workflows

### Local Development

1. **Setup Development Environment**
   ```bash
   # Clone your project
   git clone https://github.com/your-org/your-project.git
   cd your-project
   
   # Configure MCP access
   export AIRLOCK_TOKEN=$(kubelogin get-token --oidc-issuer-url=https://your-idp.com --oidc-client-id=your-client-id)
   
   # Test MCP connectivity
   mcp tools list
   ```

2. **Integrate MCP in Build Process**
   ```bash
   # Makefile example
   .PHONY: analyze
   analyze:
   	@echo "Running security analysis..."
   	@mcp code analyze mcp://repo/src/ --type security --format json > security-report.json
   	
   .PHONY: docs
   docs:
   	@echo "Updating documentation..."
   	@mcp docs generate mcp://repo/ --output mcp://artifacts/docs/
   ```

### CI/CD Integration

```yaml
# GitHub Actions example
name: MCP Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Get MCP Token
      run: |
        echo "AIRLOCK_TOKEN=$(kubelogin get-token --oidc-issuer-url=${{ secrets.OIDC_ISSUER }} --oidc-client-id=${{ secrets.OIDC_CLIENT_ID }})" >> $GITHUB_ENV
    
    - name: Run Security Analysis
      run: |
        mcp code analyze mcp://repo/src/ --type security --format sarif > security.sarif
    
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: security.sarif
```

## Next Steps

After completing the developer onboarding:

1. **Explore Available Tools**: Run `mcp tools list` to see all available tools
2. **Join Developer Community**: Connect with other developers using MCP Airlock
3. **Contribute**: Consider contributing tools or improvements
4. **Stay Updated**: Subscribe to updates and new feature announcements

## Resources

- **API Documentation**: [API Reference](../api/README.md)
- **Tool Documentation**: [Available Tools](../tools/README.md)
- **Troubleshooting**: [Troubleshooting Guide](../operations/troubleshooting.md)
- **Security**: [Security Architecture](../security/architecture.md)
- **Examples**: [Code Examples](../../examples/README.md)

## Feedback

We value your feedback! Please:
- Report issues via your organization's support channels
- Suggest improvements through the feedback system
- Share your use cases and success stories
- Contribute to documentation improvements

---

**Need Help?** Contact your administrator or check the [troubleshooting guide](../operations/troubleshooting.md) for common issues and solutions.
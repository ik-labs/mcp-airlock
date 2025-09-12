# 🚀 MCP Airlock Hackathon Demo

**A zero-trust gateway for secure MCP (Model Context Protocol) server access**

This demo showcases all the security features of MCP Airlock in an easy-to-run local environment.

## 🎯 What This Demo Shows

### 🔐 Zero-Trust Security Features
- **JWT Authentication**: Role-based access with admin/developer/viewer roles
- **OPA/Rego Policy Engine**: Dynamic authorization with hot-reload
- **Data Loss Prevention**: Automatic PII redaction (emails, SSNs, API keys, etc.)
- **Virtual Root Security**: Path traversal protection and sandboxing
- **Audit Logging**: Tamper-evident logs with hash chaining
- **Rate Limiting**: Role-based request throttling

### 🛡️ Security Scenarios Demonstrated
1. **Unauthorized Access**: Requests without tokens are blocked
2. **Role-Based Access**: Different users see different data
3. **Sensitive Data Protection**: Admin-only access to secrets
4. **PII Redaction**: Sensitive data automatically masked
5. **Policy Enforcement**: Real-time authorization decisions
6. **Audit Trail**: Complete request/response logging

## 🚀 Quick Start (One Command)

```bash
# Clone and run the complete demo
git clone <your-repo>
cd mcp-airlock
./scripts/run-demo.sh
```

That's it! The script will:
- Build Airlock
- Generate demo JWT tokens
- Start MCP servers
- Launch Airlock with full security features
- Show you example commands to test

## 🧪 Manual Setup (Step by Step)

### Prerequisites
- Go 1.22+
- Python 3.x
- Make (optional)

### 1. Build and Setup
```bash
# Install dependencies and build
make deps
make build

# Generate demo tokens
python3 scripts/generate-demo-tokens.py
```

### 2. Start Services
```bash
# Terminal 1: Start MCP servers
python3 examples/mcp-servers/docs-server.py &
python3 examples/mcp-servers/analytics-server.py &

# Terminal 2: Start Airlock with demo config
./airlock -config config-demo.yaml
```

### 3. Test Security Features
```bash
# Load demo tokens
source <(python3 -c "
import json
with open('demo-tokens.json') as f:
    tokens = json.load(f)
for role, token in tokens.items():
    print(f'export {role.upper()}_TOKEN=\"{token}\"')
")

# Test 1: No auth (should fail)
curl http://localhost:8080/mcp/tools

# Test 2: Admin access (full access)
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
     http://localhost:8080/mcp/tools

# Test 3: Developer trying to read secrets (should be blocked)
curl -H "Authorization: Bearer $DEVELOPER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"read_file","arguments":{"file_path":"sensitive/secrets.txt"}}' \
     http://localhost:8080/mcp/tools/call

# Test 4: Viewer searching docs (should work)
curl -H "Authorization: Bearer $VIEWER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"search_docs","arguments":{"query":"API"}}' \
     http://localhost:8080/mcp/tools/call
```

## 🎭 Demo User Roles

### 👑 Admin User (`admin-user`)
- **Access**: Full access to all tools and data
- **Rate Limit**: 1000 requests/minute
- **Can Access**: All files including secrets
- **Use Case**: System administration and configuration

### 👨‍💻 Developer User (`dev-user`)
- **Access**: Read docs, query analytics, limited file access
- **Rate Limit**: 100 requests/minute
- **Cannot Access**: Sensitive files (secrets, configs)
- **Use Case**: Application development and debugging

### 👀 Viewer User (`readonly-user`)
- **Access**: Search documentation only
- **Rate Limit**: 50 requests/minute
- **Cannot Access**: Analytics, file reading, sensitive data
- **Use Case**: Documentation browsing and learning

## 🔍 Security Features in Action

### 1. Data Loss Prevention (DLP)
Try reading the sensitive file as admin - watch PII get redacted:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"read_file","arguments":{"file_path":"sensitive/secrets.txt"}}' \
     http://localhost:8080/mcp/tools/call
```

**Result**: Emails, SSNs, API keys, and passwords are automatically redacted!

### 2. Policy Enforcement
The OPA/Rego policy (`configs/policy.rego`) enforces:
- Role-based tool access
- File path restrictions
- Rate limiting by user type
- Audit requirements for sensitive operations

### 3. Virtual Root Security
- `mcp://docs/` → `./examples/sample-docs/public` (safe)
- `mcp://sensitive/` → `./examples/sample-docs/sensitive` (admin-only)
- `mcp://temp/` → `/tmp/airlock-demo` (read-write)

### 4. Audit Trail
Check the comprehensive audit log:
```bash
sqlite3 /tmp/airlock-demo-audit.db "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 5;"
```

## 📊 Monitoring and Observability

### Health Endpoints
- **Liveness**: `GET /live` - Service is running
- **Readiness**: `GET /ready` - Ready to serve traffic  
- **Info**: `GET /info` - Version and build information

### Metrics
- **Prometheus**: `GET /metrics` - Request counts, latencies, errors
- **Custom Metrics**: Authentication success/failure, policy decisions, DLP actions

### Audit Logging
- **Database**: SQLite with hash-chained entries (tamper-evident)
- **Fields**: User, action, request/response, timestamp, hash
- **Retention**: Configurable (7 days in demo)

## 🎯 Hackathon Highlights

### Why MCP Airlock Matters
1. **Security Gap**: MCP servers often lack built-in security
2. **Zero-Trust**: Never trust, always verify every request
3. **Policy-Driven**: Flexible authorization with OPA/Rego
4. **Data Protection**: Prevent sensitive data leakage
5. **Audit Compliance**: Complete audit trail for compliance

### Technical Innovation
- **MCP Protocol Compliance**: Built on official Go SDK
- **High Performance**: Sub-60ms p95 latency
- **Hot-Reload Policies**: Update security rules without restart
- **Extensible**: Plugin architecture for custom security rules

### Real-World Use Cases
- **Enterprise AI**: Secure AI assistant access to internal tools
- **Multi-Tenant SaaS**: Isolate customer data and access
- **Compliance**: Meet SOC2, HIPAA, PCI requirements
- **Development**: Secure development environment access

## 🛠️ Configuration Files

- **`config-demo.yaml`**: Full-featured demo configuration
- **`config-minimal.yaml`**: Basic setup for development
- **`config-standalone.yaml`**: Zero-dependency testing
- **`configs/policy.rego`**: OPA authorization policies

## 🔧 Troubleshooting

### Common Issues

**Port already in use:**
```bash
lsof -ti:8080 | xargs kill -9
```

**MCP servers not starting:**
```bash
# Check Python dependencies
pip3 install -r requirements.txt  # if exists

# Check socket permissions
ls -la /tmp/*.sock
```

**Policy errors:**
```bash
# Test policy syntax
opa fmt configs/policy.rego
opa test configs/policy.rego
```

### Debug Commands
```bash
# Check Airlock logs
./airlock -config config-demo.yaml -v

# Test MCP server directly
python3 -c "
import socket
s = socket.socket(socket.AF_UNIX)
s.connect('/tmp/docs.sock')
print('MCP server is running')
s.close()
"

# Validate JWT token
python3 -c "
import jwt
token = 'your-token-here'
print(jwt.decode(token, 'demo-secret-key-for-hackathon-only', algorithms=['HS256']))
"
```

## 🎉 What Makes This Demo Special

1. **Complete Security Stack**: Shows every security feature working together
2. **Easy Setup**: One script gets everything running
3. **Realistic Scenarios**: Real-world security challenges and solutions
4. **Interactive Testing**: Multiple user roles to demonstrate access control
5. **Production-Ready**: All features you'd need in a real deployment

## 🚀 Next Steps

After running the demo:

1. **Explore the Code**: Check out the policy engine, DLP patterns, and audit system
2. **Customize Policies**: Modify `configs/policy.rego` to see real-time policy updates
3. **Add MCP Servers**: Connect your own MCP servers to see Airlock in action
4. **Scale Testing**: Use the load testing tools in `examples/`
5. **Deploy**: Use the Kubernetes configs in `deployments/`

---

**Built for the Code with Kiro Hackathon** 🏆

*Showcasing how AI-assisted development with Kiro can create production-ready security infrastructure*
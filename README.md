# MCP Airlock

A zero-trust gateway that provides secure, policy-enforced access to remote MCP (Model Context Protocol) servers.

## Overview

MCP Airlock acts as a reverse proxy that enables hosts to communicate with MCP servers inside VPCs without compromising security through direct network access or data leakage. The system implements capability negotiation, policy enforcement, root virtualization, data redaction, and OAuth2 authentication at the edge.

## Features

- **Zero Trust Security**: All requests are authenticated, authorized, and audited
- **MCP Protocol Compliance**: Built on the official modelcontextprotocol/go-sdk
- **Policy Enforcement**: OPA/Rego-based authorization with hot-reload
- **Root Virtualization**: Virtual file system mapping with path sandboxing
- **Data Loss Prevention**: Configurable redaction patterns for sensitive data
- **Audit Logging**: Comprehensive audit trail with hash chaining
- **High Performance**: Sub-60ms p95 latency with minimal resource usage

## Quick Start

### 🚀 Hackathon Demo (One Command Setup)

**Want to see all security features in action?**

```bash
git clone <repository-url>
cd mcp-airlock
./scripts/run-demo.sh
```

**What the demo script does:**
1. **Builds Airlock** from source
2. **Generates JWT tokens** for 3 user roles (admin/developer/viewer)
3. **Starts 2 MCP servers** with sample data:
   - **Documentation Server**: Provides document search and file reading
   - **Analytics Server**: Provides metrics querying and report generation
4. **Launches Airlock** with full security configuration
5. **Shows interactive examples** to test different security scenarios

**Security features demonstrated:**
- Zero-trust authentication with JWT tokens
- OPA/Rego policy enforcement with role-based access control
- Data loss prevention with automatic PII redaction
- Virtual root security and path traversal protection
- Comprehensive audit logging with hash chaining
- Role-based rate limiting (admin: 1000/min, dev: 100/min, viewer: 50/min)

**Demo includes 3 user roles:**
- **Admin**: Full access to all tools and sensitive data
- **Developer**: Limited access, blocked from reading secrets
- **Viewer**: Read-only access to documentation only

See [DEMO.md](DEMO.md) for detailed demo instructions and security test scenarios.

### 📋 Manual Setup

#### Prerequisites

- Go 1.22 or later
- Python 3.x (for MCP servers)
- PyJWT library (automatically installed by demo script)
- Make (optional, for using Makefile)

#### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd mcp-airlock
```

2. Install dependencies:
```bash
make deps
# or
go mod download
```

3. Build the application:
```bash
make build
# or
go build -o airlock ./cmd/airlock
```

#### Configuration Options

**For Hackathon Demo (Full Security Features):**
```bash
./airlock -config config-demo.yaml
```

**For Development (Minimal Setup):**
```bash
./airlock -config config-minimal.yaml
```

**For Testing (Zero Dependencies):**
```bash
./airlock -config config-standalone.yaml
```

#### Running

**Option 1: Full Demo (Recommended for Hackathon)**
```bash
# Automated demo with MCP servers and sample data
./scripts/run-demo.sh
```

**Option 2: Manual Setup**
```bash
# Start MCP servers first
python3 examples/mcp-servers/docs-server.py &
python3 examples/mcp-servers/analytics-server.py &

# Then start Airlock
./airlock -config config-demo.yaml
```

**Option 3: Minimal Development**
```bash
# Just Airlock without MCP servers
./airlock -config config-standalone.yaml
```

#### Testing the Setup

```bash
# Health endpoints (no auth required)
curl http://localhost:8080/live
curl http://localhost:8080/ready
curl http://localhost:8080/info

# Generate and use demo tokens (if using demo config)
python3 scripts/generate-demo-tokens.py

# Test with authentication
curl -H "Authorization: Bearer <token>" http://localhost:8080/mcp/tools
```

## Development

### Project Structure

```
├── cmd/airlock/              # Main application entry point
├── pkg/
│   ├── config/               # Configuration management
│   ├── health/               # Health check functionality
│   └── mcp/                  # MCP SDK adapter interfaces
├── internal/                 # Internal packages
├── examples/
│   ├── mcp-servers/          # Sample MCP servers for demo
│   │   ├── docs-server.py    # Documentation server
│   │   └── analytics-server.py # Analytics server
│   └── sample-docs/          # Sample documents with PII for testing
├── scripts/
│   ├── run-demo.sh           # One-command demo launcher
│   └── generate-demo-tokens.py # JWT token generator
├── configs/
│   ├── policy.rego           # OPA authorization policies
│   └── examples/             # Configuration examples
├── config.yaml               # Production configuration example
├── config-demo.yaml          # Hackathon demo configuration
├── config-minimal.yaml       # Development configuration
├── config-standalone.yaml    # Zero-dependency configuration
├── DEMO.md                   # Comprehensive demo guide
├── Makefile                  # Build automation
└── README.md
```

### Building

```bash
# Development build
make build

# Production build (optimized)
make build-prod

# Run tests
make test

# Run tests with coverage
make test-coverage

# Format code
make fmt

# Run all checks
make check
```

### Testing

```bash
# Run all tests
make test

# Run tests with race detection
go test -race ./...

# Generate coverage report
make test-coverage
```

## Configuration

The application uses YAML configuration with the following main sections:

- `server`: HTTP server settings and TLS configuration
- `auth`: OIDC/JWT authentication settings
- `policy`: OPA/Rego policy engine configuration
- `roots`: Virtual root mappings for file system access
- `dlp`: Data loss prevention and redaction patterns
- `upstreams`: MCP server connections (stdio, unix, http)
- `audit`: Audit logging and retention settings
- `observability`: Metrics, tracing, and logging configuration

### Configuration Files Available

- **`config-demo.yaml`**: Full-featured hackathon demo with all security features
- **`config-minimal.yaml`**: Development setup with basic MCP server connections
- **`config-standalone.yaml`**: Zero-dependency testing configuration
- **`config.yaml`**: Production-ready configuration template

See individual config files for detailed examples and documentation.

## Health Checks

The application provides standard Kubernetes health check endpoints:

- `/live`: Liveness probe - returns 200 if the application is running
- `/ready`: Readiness probe - returns 200 if ready to serve traffic, 503 otherwise
- `/info`: Version and build information

## Security

MCP Airlock implements defense-in-depth security:

1. **Authentication**: OIDC/JWT token validation with JWKS caching
2. **Authorization**: OPA/Rego policy engine with tenant isolation
3. **Path Security**: Virtual root mapping with traversal protection
4. **Data Protection**: Configurable PII redaction patterns
5. **Audit Trail**: Tamper-evident logging with hash chaining
6. **Rate Limiting**: Per-token and per-IP rate limiting

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

The MIT License is an OSI-approved open source license that allows for commercial and non-commercial use, modification, and distribution.

## Contributing

[Contributing guidelines to be added]
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

### Prerequisites

- Go 1.22 or later
- Make (optional, for using Makefile)

### Installation

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

### Configuration

1. Copy the example configuration:
```bash
cp config.yaml config-local.yaml
```

2. Edit `config-local.yaml` to match your environment:
   - Update OIDC issuer and audience
   - Configure upstream MCP servers
   - Set up virtual root mappings
   - Configure audit storage location

### Running

1. Start the server:
```bash
make run
# or
./airlock -config config-local.yaml
```

2. Check health endpoints:
```bash
# Liveness probe
curl http://localhost:8080/live

# Readiness probe
curl http://localhost:8080/ready

# Version info
curl http://localhost:8080/info
```

## Development

### Project Structure

```
├── cmd/airlock/          # Main application entry point
├── pkg/
│   ├── config/           # Configuration management
│   ├── health/           # Health check functionality
│   └── mcp/              # MCP SDK adapter interfaces
├── internal/             # Internal packages
├── config.yaml           # Example configuration
├── Makefile              # Build automation
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

See `config.yaml` for a complete example with documentation.

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

[License information to be added]

## Contributing

[Contributing guidelines to be added]
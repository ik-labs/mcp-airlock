# MCP Airlock Examples

This directory contains example MCP servers and integration test harnesses for demonstrating MCP Airlock functionality.

## Overview

The examples include:

1. **Sample MCP Servers** - Demonstration servers for testing and development
2. **Docker Images** - Containerized versions of the sample servers
3. **Integration Tests** - Comprehensive test suite for end-to-end validation
4. **Load Testing** - Performance validation tools

## Sample MCP Servers

### Documentation Server (`docs-server.py`)

A sample MCP server that provides document search and retrieval capabilities:

**Features:**
- Document search with relevance scoring
- File reading with security validation
- Directory listing
- Path traversal protection
- Sample documentation generation

**Tools:**
- `search_docs` - Search for documents containing specific terms
- `read_file` - Read the contents of a specific file
- `list_directory` - List files and directories in a path

**Resources:**
- `mcp://docs/` - Root resource for documentation access

**Usage:**
```bash
# Run standalone
python examples/mcp-servers/docs-server.py

# Run with custom configuration
DOCS_ROOT=/path/to/docs MCP_SOCKET_PATH=/tmp/docs.sock python examples/mcp-servers/docs-server.py
```

### Analytics Server (`analytics-server.py`)

A sample MCP server that provides analytics and metrics capabilities:

**Features:**
- Metrics storage and querying
- Report generation
- Data export in multiple formats
- Dashboard data aggregation
- Background sample data generation

**Tools:**
- `query_metrics` - Query metrics data with filters and aggregations
- `generate_report` - Generate analytics reports (summary, performance, usage)
- `export_data` - Export analytics data in JSON or CSV format
- `get_dashboard_data` - Get data for analytics dashboards

**Resources:**
- `mcp://analytics/` - Root resource for analytics data
- `mcp://analytics/dashboard` - Dashboard data
- `mcp://analytics/reports/{name}` - Specific reports

**Usage:**
```bash
# Run standalone
python examples/mcp-servers/analytics-server.py

# Run with custom configuration
ANALYTICS_DB_PATH=/path/to/analytics.db MCP_SOCKET_PATH=/tmp/analytics.sock python examples/mcp-servers/analytics-server.py
```

## Docker Images

### Building Images

```bash
# Build documentation server image
docker build -f examples/mcp-servers/Dockerfile.docs -t mcp-docs-server:latest examples/mcp-servers/

# Build analytics server image
docker build -f examples/mcp-servers/Dockerfile.analytics -t mcp-analytics-server:latest examples/mcp-servers/
```

### Running Containers

```bash
# Run docs server
docker run -d \
  --name docs-server \
  -v /path/to/docs:/mnt/docs:ro \
  -v /tmp/mcp:/run/mcp \
  mcp-docs-server:latest

# Run analytics server
docker run -d \
  --name analytics-server \
  -v /tmp/analytics:/var/lib/analytics \
  -v /tmp/mcp:/run/mcp \
  mcp-analytics-server:latest
```

## Integration Testing

### Test Harness

The integration test harness (`tests/integration/e2e/integration_test.go`) provides comprehensive end-to-end testing:

**Test Categories:**
- Health checks and basic connectivity
- Authentication and authorization
- MCP server connectivity and tool execution
- Security policy enforcement
- Rate limiting validation
- Audit logging verification
- Load testing and performance validation
- Kubernetes deployment validation

### Running Tests

#### Automated Test Runner

Use the provided script for complete test automation:

```bash
# Run all integration tests
./scripts/run-integration-tests.sh

# Run with custom configuration
NAMESPACE=my-test RUN_LOAD_TESTS=true ./scripts/run-integration-tests.sh

# Clean up test resources
./scripts/run-integration-tests.sh cleanup

# Collect debug information
./scripts/run-integration-tests.sh debug
```

#### Manual Test Execution

```bash
# Set up test environment
export KUBERNETES_SERVICE_HOST="kubernetes.default.svc"
export AIRLOCK_URL="http://localhost:8080"
export TEST_TOKEN="your-test-token"
export TEST_NAMESPACE="airlock-test"

# Run Go integration tests
go test -v -timeout=10m ./tests/integration/e2e/...

# Run specific test categories
go test -v -run TestEndToEndIntegration ./tests/integration/e2e/...
go test -v -run TestLoadTesting ./tests/integration/e2e/...
go test -v -run TestKubernetesDeployment ./tests/integration/e2e/...
```

### Test Configuration

The test harness supports various configuration options:

**Environment Variables:**
- `AIRLOCK_URL` - URL of the Airlock instance to test
- `TEST_TOKEN` - Authentication token for API calls
- `TEST_NAMESPACE` - Kubernetes namespace for tests
- `KUBERNETES_SERVICE_HOST` - Indicates Kubernetes environment

**Test Parameters:**
- Timeout settings for different test phases
- Concurrency levels for load testing
- Request counts and patterns
- Expected response times and success rates

## Load Testing

### Performance Validation

The load testing component validates Airlock performance under realistic conditions:

**Test Scenarios:**
- Concurrent user simulation
- High-frequency API calls
- Mixed workload patterns
- Resource utilization monitoring

**Metrics Collected:**
- Request success rates
- Response time distributions
- Throughput measurements
- Error rates and types

**Example Load Test:**
```bash
# Run load test with custom parameters
export RUN_LOAD_TESTS=true
export LOAD_TEST_CONCURRENCY=20
export LOAD_TEST_REQUESTS=100
./scripts/run-integration-tests.sh
```

## Deployment Patterns

### Sidecar Pattern

Deploy MCP servers as sidecars alongside Airlock:

```yaml
# Example sidecar configuration
sidecars:
  - name: docs-sidecar
    image: mcp-docs-server:latest
    env:
      - name: MCP_SOCKET_PATH
        value: "/run/mcp/docs.sock"
    volumeMounts:
      - name: mcp-sockets
        mountPath: /run/mcp
      - name: docs-content
        mountPath: /mnt/docs
```

### Standalone Services

Deploy MCP servers as separate services:

```yaml
# Example service deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: docs-server
spec:
  template:
    spec:
      containers:
      - name: docs-server
        image: mcp-docs-server:latest
        ports:
        - containerPort: 8080
```

### Unix Socket Communication

Configure Unix socket communication between Airlock and MCP servers:

```yaml
# Shared volume for Unix sockets
volumes:
  - name: mcp-sockets
    emptyDir: {}

# Volume mounts in both containers
volumeMounts:
  - name: mcp-sockets
    mountPath: /run/mcp
```

## Security Considerations

### Container Security

All example containers follow security best practices:

- Run as non-root user (UID 1001)
- Read-only root filesystem
- Dropped capabilities
- Security context constraints
- Health checks for monitoring

### Network Security

- Unix socket communication for local services
- TLS encryption for remote services
- Network policies for traffic control
- Service mesh integration support

### Data Protection

- Path traversal protection
- Input validation and sanitization
- Audit logging for all operations
- Data loss prevention (DLP) integration

## Troubleshooting

### Common Issues

1. **Socket Permission Errors**
   ```bash
   # Check socket permissions
   ls -la /run/mcp/
   
   # Fix permissions if needed
   chmod 666 /run/mcp/*.sock
   ```

2. **Container Startup Failures**
   ```bash
   # Check container logs
   docker logs docs-server
   
   # Verify volume mounts
   docker inspect docs-server
   ```

3. **Test Failures**
   ```bash
   # Collect debug information
   ./scripts/run-integration-tests.sh debug
   
   # Check Kubernetes events
   kubectl get events -n airlock-test
   ```

### Debug Commands

```bash
# Test MCP server connectivity
python -c "
import socket
s = socket.socket(socket.AF_UNIX)
s.connect('/run/mcp/docs.sock')
s.send(b'{\"method\":\"search_docs\",\"params\":{\"query\":\"test\"}}')
print(s.recv(1024))
s.close()
"

# Check Airlock health
curl -f http://localhost:8080/live
curl -f http://localhost:8080/ready
curl -f http://localhost:8080/info

# Test authenticated request
curl -H "Authorization: Bearer $TEST_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"method":"tools/call","params":{"name":"search_docs","arguments":{"query":"test"}}}' \
     http://localhost:8080/mcp
```

## Contributing

To contribute additional examples or improvements:

1. **Add New MCP Servers**
   - Create server implementation in `examples/mcp-servers/`
   - Add corresponding Dockerfile
   - Update integration tests
   - Document tools and resources

2. **Enhance Test Coverage**
   - Add new test scenarios to `tests/integration/e2e/`
   - Improve load testing patterns
   - Add security validation tests
   - Document test procedures

3. **Improve Documentation**
   - Add usage examples
   - Document configuration options
   - Provide troubleshooting guides
   - Include performance benchmarks

## References

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [Airlock Documentation](../docs/README.md)
- [Deployment Guide](../deployments/README.md)
- [Security Guide](../docs/security/README.md)
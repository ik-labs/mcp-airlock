# Design Document

## Overview

MCP Airlock is a zero-trust gateway that provides secure, policy-enforced access to remote MCP servers. The system acts as a reverse proxy that terminates HTTP/SSE connections from external clients and proxies them to internal MCP servers over stdio/Unix sockets, implementing comprehensive security controls at the edge.

### Key Design Principles

- **Zero Trust**: All requests are authenticated, authorized, and audited
- **Fail Closed**: Security failures result in request denial, not bypass
- **Defense in Depth**: Multiple security layers (auth, policy, redaction, audit)
- **Performance First**: Sub-60ms p95 latency with minimal resource usage
- **Operational Excellence**: Observable, configurable, and maintainable
- **SDK-First**: Built on official modelcontextprotocol/go-sdk for protocol compliance

### Technology Stack

- **Language**: Go 1.22+
- **MCP Protocol**: modelcontextprotocol/go-sdk v0.2.0+ (server, client, transport)
- **Authentication**: golang-jwt/jwt/v5, coreos/go-oidc for OIDC discovery
- **Policy Engine**: github.com/open-policy-agent/opa/rego
- **Configuration**: YAML via koanf
- **Data Redaction**: Go stdlib regexp with compiled patterns
- **Audit Storage**: SQLite with WAL mode (MVP), PostgreSQL support later
- **Observability**: OpenTelemetry (OTLP) + zap structured logging
- **Packaging**: Docker multi-stage builds, Helm charts for Kubernetes
- **CI/CD**: GitHub Actions with Trivy security scanning + Cosign signing

## Architecture

### High-Level Architecture

```
External Client (IDE/Host)
    │
    │ HTTPS + SSE (MCP over HTTP)
    ▼
┌─────────────────────────────────────┐
│           Airlock Gateway           │
│  ┌─────────────────────────────────┐│
│  │    MCP Go-SDK HTTP/SSE Server   ││
│  └─────────────────────────────────┘│
│  ┌─────────────────────────────────┐│
│  │      Authentication Layer       ││
│  │   • OIDC/JWT Validation         ││
│  │   • JWKS Cache (TTL: 5m)        ││
│  │   • Tenant Extraction           ││
│  └─────────────────────────────────┘│
│  ┌─────────────────────────────────┐│
│  │       Filter Chain              ││
│  │   • Rate Limiting               ││
│  │   • Policy Engine (OPA)         ││
│  │   • Root Virtualization         ││
│  │   • DLP Redaction               ││
│  │   • Audit Logging               ││
│  └─────────────────────────────────┘│
│  ┌─────────────────────────────────┐│
│  │      MCP Connector Layer        ││
│  │   • Go-SDK Client Bridge        ││
│  │   • stdio/Unix Socket Adapters  ││
│  │   • Connection Pooling          ││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
    │
    │ stdio/Unix Socket
    ▼
Internal MCP Server(s)
```

### Component Architecture

The system is organized into distinct layers with clear separation of concerns:

1. **MCP Protocol Layer**: Official go-sdk Server and Client handling
2. **Security Layer**: Authentication, authorization, and policy enforcement
3. **Processing Layer**: Request/response filtering, redaction, and transformation
4. **Connector Layer**: Bridge to internal MCP servers using go-sdk clients
5. **Infrastructure Layer**: Audit, metrics, configuration, and health checks

### MCP Go-SDK Integration Strategy

The Airlock gateway is built as a security wrapper around the official MCP Go SDK:

- **Server Side**: Use go-sdk Server with custom handlers that implement security middleware
- **Client Side**: Use go-sdk Client instances to connect to upstream MCP servers
- **Transport**: Leverage go-sdk's HTTP/SSE and stdio/Unix socket transports
- **Message Handling**: All MCP message parsing, validation, and serialization handled by SDK
- **Protocol Compliance**: Automatic compliance with MCP specification through SDK updates

```go
// Core integration pattern
type AirlockGateway struct {
    // Official MCP server handling external clients
    mcpServer *server.Server
    
    // Pool of MCP clients for upstream servers
    upstreamClients map[string]*client.Client
    
    // Security middleware chain
    authMiddleware   AuthenticationMiddleware
    policyMiddleware PolicyMiddleware
    auditMiddleware  AuditMiddleware
}
```

## Components and Interfaces

### 1. MCP Server Layer (`pkg/server/`)

**Responsibilities:**
- Wrap go-sdk Server with security middleware
- Handle MCP protocol compliance using official SDK
- Manage client sessions and connection lifecycle
- Implement security filter chain for all MCP operations

**Key Interfaces:**
```go
import (
    "github.com/modelcontextprotocol/go-sdk/pkg/server"
    "github.com/modelcontextprotocol/go-sdk/pkg/transport"
)

type AirlockServer struct {
    mcpServer    *server.Server
    transport    transport.Transport
    authLayer    AuthenticationLayer
    policyEngine PolicyEngine
    auditor      AuditLogger
}

type SecurityMiddleware interface {
    ProcessRequest(ctx context.Context, req *server.Request) (*server.Request, error)
    ProcessResponse(ctx context.Context, resp *server.Response) (*server.Response, error)
}

type SessionManager interface {
    CreateSession(ctx context.Context, token string) (*Session, error)
    GetSession(sessionID string) (*Session, error)
    InvalidateSession(sessionID string) error
}
```

**Implementation Details:**
- Use go-sdk Server as the foundation with custom handlers
- Wrap SDK transport with security middleware
- Leverage SDK's HTTP/SSE implementation
- Add security context to all MCP operations

### 2. Authentication Layer (`pkg/auth/`)

**Responsibilities:**
- Validate JWT tokens using OIDC discovery
- Cache JWKS with TTL ≤ 5 minutes and handle rotation
- Extract tenant and group information from claims
- Implement rate limiting and brute-force protection

**Key Interfaces:**
```go
type Authenticator interface {
    ValidateToken(ctx context.Context, token string) (*Claims, error)
    RefreshJWKS(ctx context.Context) error
}

type Claims struct {
    Subject   string   `json:"sub"`
    Tenant    string   `json:"tid"`
    Groups    []string `json:"groups"`
    ExpiresAt int64    `json:"exp"`
}

type RateLimiter interface {
    Allow(ctx context.Context, key string) (bool, time.Duration, error)
    RecordFailure(ctx context.Context, key string) error
}
```

**Implementation Details:**
- Use `coreos/go-oidc` for OIDC discovery and validation
- `golang-jwt/jwt/v5` for JWT parsing and validation
- In-memory JWKS cache with automatic refresh
- Token-based and IP-based rate limiting with Redis backend option

### 3. Policy Engine (`pkg/policy/`)

**Responsibilities:**
- Load and compile OPA/Rego policies
- Make authorization decisions based on request context
- Cache policy decisions with configurable TTL
- Support hot-reload of policies via SIGHUP

**Key Interfaces:**
```go
type PolicyEngine interface {
    Evaluate(ctx context.Context, input *PolicyInput) (*PolicyDecision, error)
    LoadPolicy(ctx context.Context, policy string) error
    ReloadPolicy(ctx context.Context) error
}

type PolicyInput struct {
    Subject     string            `json:"sub"`
    Tenant      string            `json:"tenant"`
    Groups      []string          `json:"groups"`
    Tool        string            `json:"tool"`
    Resource    string            `json:"resource"`
    Method      string            `json:"method"`
    Headers     map[string]string `json:"headers"`
}

type PolicyDecision struct {
    Allow       bool     `json:"allow"`
    Reason      string   `json:"reason"`
    RuleID      string   `json:"rule_id"`
    Metadata    map[string]interface{} `json:"metadata"`
}
```

**Implementation Details:**
- Use `github.com/open-policy-agent/opa/rego` for policy evaluation
- Precompile policies for performance
- Decision caching with tenant isolation
- Policy validation before hot-reload

### 4. Root Virtualization (`pkg/roots/`)

**Responsibilities:**
- Map virtual MCP URIs to real file system or S3 paths
- Enforce read-only restrictions at syscall level
- Prevent path traversal attacks
- Support multiple backend types (filesystem, S3)

**Key Interfaces:**
```go
type RootMapper interface {
    MapURI(ctx context.Context, virtualURI string, tenant string) (*MappedResource, error)
    ValidateAccess(ctx context.Context, resource *MappedResource, operation string) error
}

type MappedResource struct {
    VirtualURI  string            `json:"virtual_uri"`
    RealPath    string            `json:"real_path"`
    Type        string            `json:"type"` // "fs", "s3"
    ReadOnly    bool              `json:"read_only"`
    Metadata    map[string]string `json:"metadata"`
}

type Backend interface {
    Read(ctx context.Context, path string) ([]byte, error)
    Write(ctx context.Context, path string, data []byte) error
    List(ctx context.Context, path string) ([]string, error)
    Stat(ctx context.Context, path string) (*FileInfo, error)
}
```

**Implementation Details:**
- Path normalization and validation using `filepath.Clean`
- Chroot-style isolation for filesystem access
- S3 backend with prefix-based isolation
- Syscall-level write protection using `seccomp` filters

### 5. DLP Redaction (`pkg/redact/`)

**Responsibilities:**
- Apply configurable redaction patterns to requests and responses
- Count redaction events for audit purposes
- Support regex and structured data redaction
- Maintain performance with compiled patterns

**Key Interfaces:**
```go
type Redactor interface {
    RedactRequest(ctx context.Context, data []byte) (*RedactionResult, error)
    RedactResponse(ctx context.Context, data []byte) (*RedactionResult, error)
    LoadPatterns(patterns []Pattern) error
}

type Pattern struct {
    Name    string `yaml:"name"`
    Regex   string `yaml:"regex"`
    Replace string `yaml:"replace"`
    Fields  []string `yaml:"fields,omitempty"` // for structured redaction
}

type RedactionResult struct {
    Data           []byte            `json:"data"`
    RedactionCount int               `json:"redaction_count"`
    PatternsHit    map[string]int    `json:"patterns_hit"`
}
```

**Implementation Details:**
- Use `regexp` package with compiled patterns
- Structured JSON redaction for specific fields
- Configurable replacement strings
- Performance monitoring for redaction overhead

### 6. Audit System (`pkg/audit/`)

**Responsibilities:**
- Log all security-relevant events with hash chaining
- Support multiple storage backends (SQLite, PostgreSQL, S3)
- Provide data retention and export capabilities
- Enable compliance reporting and forensic analysis

**Key Interfaces:**
```go
type AuditLogger interface {
    LogEvent(ctx context.Context, event *AuditEvent) error
    Query(ctx context.Context, filter *QueryFilter) ([]*AuditEvent, error)
    Export(ctx context.Context, format string, writer io.Writer) error
}

type AuditEvent struct {
    ID            string                 `json:"id"`
    Timestamp     time.Time              `json:"timestamp"`
    Tenant        string                 `json:"tenant"`
    Subject       string                 `json:"subject"`
    Action        string                 `json:"action"`
    Resource      string                 `json:"resource"`
    Decision      string                 `json:"decision"`
    Reason        string                 `json:"reason"`
    Metadata      map[string]interface{} `json:"metadata"`
    Hash          string                 `json:"hash"`
    PreviousHash  string                 `json:"previous_hash"`
}
```

**Implementation Details:**
- Blake3 hash chaining for tamper detection
- SQLite with WAL mode for high-performance writes
- Configurable retention policies with automatic cleanup
- JSONL export format for external analysis

### 7. MCP Client Connector (`pkg/connector/`)

**Responsibilities:**
- Use go-sdk Client to connect to upstream MCP servers
- Bridge Airlock server requests to upstream servers
- Handle upstream failures and implement circuit breakers
- Maintain MCP protocol compliance through SDK

**Key Interfaces:**
```go
import (
    "github.com/modelcontextprotocol/go-sdk/pkg/client"
    "github.com/modelcontextprotocol/go-sdk/pkg/transport"
)

type UpstreamConnector interface {
    Connect(ctx context.Context, upstream *Upstream) (*client.Client, error)
    ProxyRequest(ctx context.Context, client *client.Client, req *server.Request) (*server.Response, error)
    Close(ctx context.Context, client *client.Client) error
}

type Upstream struct {
    Name      string            `yaml:"name"`
    Type      string            `yaml:"type"` // "stdio", "unix"
    Command   []string          `yaml:"command,omitempty"`
    Socket    string            `yaml:"socket,omitempty"`
    Env       map[string]string `yaml:"env,omitempty"`
    Timeout   time.Duration     `yaml:"timeout"`
    Transport transport.Transport `yaml:"-"`
}

type ClientPool interface {
    Get(ctx context.Context, upstream string) (*client.Client, error)
    Put(ctx context.Context, upstream string, client *client.Client) error
    Close(ctx context.Context, upstream string) error
}
```

**Implementation Details:**
- Use go-sdk Client for all upstream communication
- Leverage SDK's stdio and Unix socket transports
- Connection pooling with go-sdk clients
- Circuit breaker pattern for upstream failures
- Proper MCP message routing through SDK

## Data Models

### Configuration Schema

```yaml
server:
  addr: ":8080"
  public_base_url: "https://airlock.example.com"
  tls:
    cert_file: "/etc/certs/tls.crt"
    key_file: "/etc/certs/tls.key"
  timeouts:
    read: "30s"
    write: "30s"
    idle: "120s"

auth:
  oidc_issuer: "https://auth.example.com/.well-known/openid-configuration"
  audience: "mcp-airlock"
  jwks_cache_ttl: "5m"
  clock_skew: "2m"
  required_groups: ["mcp.users"]

policy:
  rego_file: "configs/policy.rego"
  cache_ttl: "1m"
  reload_signal: "SIGHUP"

roots:
  - name: "repo-readonly"
    type: "fs"
    virtual: "mcp://repo/"
    real: "/var/airlock/mounts/repo"
    read_only: true
  - name: "artifacts"
    type: "s3"
    virtual: "mcp://artifacts/"
    real: "s3://airlock-artifacts/"
    read_only: false

dlp:
  patterns:
    - name: "email"
      regex: '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
      replace: "[redacted-email]"
    - name: "bearer_token"
      regex: '(?i)bearer\s+[a-z0-9._-]+'
      replace: "[redacted-token]"

rate_limiting:
  per_token: "200/min"
  per_ip: "1000/min"
  burst: 50

upstreams:
  - name: "docs-server"
    type: "unix"
    socket: "/run/mcp/docs.sock"
    timeout: "30s"
    allow_tools: ["search_docs", "read_file"]
  - name: "code-server"
    type: "stdio"
    command: ["python", "-m", "mcp_server.code"]
    env:
      PYTHONPATH: "/opt/mcp-servers"
    timeout: "30s"

audit:
  backend: "sqlite"
  database: "/var/lib/airlock/audit.db"
  retention: "30d"
  export_format: "jsonl"

observability:
  metrics:
    enabled: true
    path: "/metrics"
  tracing:
    enabled: true
    endpoint: "http://jaeger:14268/api/traces"
  logging:
    level: "info"
    format: "json"
```

### Policy Schema (OPA/Rego)

```rego
package airlock.authz

import rego.v1

# Default deny
default allow := false

# Allow if user has required group and tool is permitted
allow if {
    input.groups[_] == "mcp.users"
    allowed_tool[input.tool]
    allowed_resource[input.resource]
}

# Define allowed tools per tenant/group
allowed_tool contains tool if {
    tool := input.tool
    tool in ["search_docs", "read_file", "list_directory"]
}

allowed_tool contains tool if {
    tool := input.tool
    startswith(tool, "read_")
    input.groups[_] == "mcp.power_users"
}

# Define allowed resources with path restrictions
allowed_resource contains resource if {
    resource := input.resource
    startswith(resource, "mcp://repo/")
    not contains(resource, "../")
}

allowed_resource contains resource if {
    resource := input.resource
    startswith(resource, "mcp://artifacts/")
    input.groups[_] == "mcp.writers"
}

# Deny reasons for debugging
deny_reason contains msg if {
    not input.groups[_] == "mcp.users"
    msg := "user not in required group"
}

deny_reason contains msg if {
    not allowed_tool[input.tool]
    msg := sprintf("tool '%s' not allowed", [input.tool])
}

deny_reason contains msg if {
    not allowed_resource[input.resource]
    msg := sprintf("resource '%s' not allowed", [input.resource])
}
```

## Error Handling

### Error Classification

1. **Authentication Errors** (HTTP 401)
   - Invalid JWT token
   - Expired token
   - Missing required claims
   - JWKS validation failure

2. **Authorization Errors** (HTTP 403)
   - Policy denial
   - Insufficient permissions
   - Resource access violation
   - Rate limit exceeded

3. **Protocol Errors** (HTTP 400)
   - Invalid MCP message format
   - Message size exceeded
   - Malformed JSON-RPC

4. **System Errors** (HTTP 500)
   - Upstream server unavailable
   - Policy engine failure
   - Audit system failure
   - Internal processing error

### Error Response Format

All errors use go-sdk error types to ensure MCP specification compliance:

```go
import "github.com/modelcontextprotocol/go-sdk/pkg/protocol"

// Policy denial error
func NewPolicyDenialError(reason, ruleID, tenant string) *protocol.Error {
    return &protocol.Error{
        Code:    protocol.ErrorCodeInternalError,
        Message: "Policy denied request",
        Data: map[string]interface{}{
            "reason":         reason,
            "rule_id":        ruleID,
            "tenant":         tenant,
            "correlation_id": generateCorrelationID(),
        },
    }
}

// Authentication error
func NewAuthenticationError(reason string) *protocol.Error {
    return &protocol.Error{
        Code:    protocol.ErrorCodeInvalidRequest,
        Message: "Authentication failed",
        Data: map[string]interface{}{
            "reason": reason,
            "www_authenticate": "Bearer realm=\"mcp-airlock\"",
        },
    }
}
```

### Circuit Breaker Implementation

```go
type CircuitBreaker struct {
    maxFailures   int
    resetTimeout  time.Duration
    state         State
    failures      int
    lastFailTime  time.Time
    mutex         sync.RWMutex
}

func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
    if !cb.canExecute() {
        return ErrCircuitOpen
    }
    
    err := fn()
    cb.recordResult(err)
    return err
}
```

## Testing Strategy

### Unit Testing

- **Coverage Target**: 90% line coverage minimum
- **Test Categories**:
  - Authentication and JWT validation
  - Policy engine decision logic
  - Root mapping and path validation
  - DLP redaction patterns
  - Audit event generation

### Integration Testing

- **Component Integration**: Test interactions between major components
- **Database Integration**: Test audit storage and retrieval
- **External Service Integration**: Test OIDC provider integration
- **Policy Integration**: Test OPA policy loading and evaluation

### End-to-End Testing

- **Golden Path Tests**: Complete request flow from client to upstream
- **Security Tests**: Authentication bypass attempts, policy violations
- **Performance Tests**: Load testing with vegeta/hey (target: 1k msgs/min)
- **Failure Mode Tests**: Upstream failures, policy engine failures, audit failures

### Security Testing

- **Penetration Testing**: Path traversal, injection attacks, privilege escalation
- **Fuzzing**: Input validation with go-fuzz
- **Static Analysis**: gosec, semgrep for security vulnerabilities
- **Dependency Scanning**: govulncheck for known vulnerabilities

### Test Data and Fixtures

```go
// Golden test cases for policy decisions
var policyTestCases = []struct {
    name     string
    input    PolicyInput
    expected PolicyDecision
}{
    {
        name: "allow_read_file_for_user",
        input: PolicyInput{
            Subject:  "user@example.com",
            Tenant:   "tenant-1",
            Groups:   []string{"mcp.users"},
            Tool:     "read_file",
            Resource: "mcp://repo/README.md",
        },
        expected: PolicyDecision{
            Allow:  true,
            Reason: "tool allowed for user group",
            RuleID: "airlock.authz.allowed_tool",
        },
    },
    // ... more test cases
}
```

### Performance Benchmarks

```go
func BenchmarkPolicyEvaluation(b *testing.B) {
    engine := setupPolicyEngine()
    input := &PolicyInput{
        Subject:  "test@example.com",
        Groups:   []string{"mcp.users"},
        Tool:     "read_file",
        Resource: "mcp://repo/test.txt",
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := engine.Evaluate(context.Background(), input)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

### Repository Structure

```
airlock/
├── cmd/airlock/              # Main application entry point
├── pkg/
│   ├── server/              # MCP server wrapper with security middleware
│   ├── client/              # MCP client pool and upstream management
│   ├── auth/                # Authentication and JWT validation
│   ├── policy/              # OPA policy engine integration
│   ├── roots/               # Virtual root mapping and access control
│   ├── redact/              # DLP redaction and pattern matching
│   ├── audit/               # Audit logging and hash chaining
│   ├── transport/           # Custom transport adapters for go-sdk
│   └── middleware/          # Security middleware implementations
├── internal/
│   ├── config/              # Configuration loading and validation
│   ├── health/              # Health check implementations
│   └── testutil/            # Test utilities and fixtures
├── examples/
│   ├── private-server/      # Sample MCP server for testing
│   └── client/              # Sample client for integration testing
├── deploy/
│   ├── helm/                # Kubernetes Helm charts
│   └── docker/              # Docker build configurations
├── configs/
│   ├── airlock.example.yaml # Example configuration
│   ├── policy.rego          # Example OPA policy
│   └── roots.yaml           # Example root mappings
└── docs/
    ├── api.md               # API documentation
    ├── deployment.md        # Deployment guide
    └── security.md          # Security architecture
```

### Go Module Dependencies

```go
module github.com/your-org/mcp-airlock

go 1.22

require (
    github.com/modelcontextprotocol/go-sdk v0.2.0
    github.com/open-policy-agent/opa v0.58.0
    github.com/coreos/go-oidc/v3 v3.7.0
    github.com/golang-jwt/jwt/v5 v5.2.0
    github.com/knadh/koanf/v2 v2.0.1
    go.opentelemetry.io/otel v1.21.0
    go.uber.org/zap v1.26.0
    // ... other dependencies
)
```

This design provides a comprehensive, production-ready architecture that addresses all the requirements while maintaining high performance, security, and operational excellence. The modular design allows for independent testing and deployment of components while ensuring clear separation of concerns. By building on the official MCP Go SDK, we ensure protocol compliance and benefit from ongoing SDK improvements.
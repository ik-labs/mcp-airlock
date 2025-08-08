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

- **Language**: Go 1.22+ (stable version for production reliability)
- **MCP Protocol**: modelcontextprotocol/go-sdk v0.2.0+ via adapter interface (pkg/mcp/ports.go)
- **Authentication**: golang-jwt/jwt/v5, coreos/go-oidc for OIDC discovery
- **Policy Engine**: github.com/open-policy-agent/opa/rego with Last-Known-Good fallback
- **Configuration**: YAML via koanf with hot-reload support
- **Data Redaction**: Go stdlib regexp with compiled patterns (regex-first, structured later)
- **Audit Storage**: SQLite with WAL mode per-pod (MVP), PostgreSQL support later
- **Rate Limiting**: In-memory (MVP), Redis/Memcached (v1.1)
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

### Go-Specific Implementation Patterns

**Concurrency Architecture:**
```go
// One goroutine per client connection with bounded channels
type ClientConnection struct {
    id       string
    outbound chan []byte // bounded to 1,000 events
    ctx      context.Context
    cancel   context.CancelFunc
}

// Context propagation for cancellation
func (s *AirlockServer) HandleRequest(ctx context.Context, req *Request) (*Response, error) {
    // ctx flows: HTTP handler → auth → policy → upstream → response
    ctx = withCorrelationID(ctx, generateID())
    
    // Early timeout and cancellation
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()
    
    return s.processWithMiddleware(ctx, req)
}

// Bounded goroutines with errgroup
func (s *AirlockServer) Start(ctx context.Context) error {
    g, ctx := errgroup.WithContext(ctx)
    
    // Concurrent startup: JWKS refresh + policy load + upstream warmup
    g.Go(func() error { return s.refreshJWKS(ctx) })
    g.Go(func() error { return s.loadPolicy(ctx) })
    g.Go(func() error { return s.warmupUpstreams(ctx) })
    
    return g.Wait() // fail fast if any component fails
}
```

**Performance-Optimized HTTP/SSE:**
```go
// Tuned HTTP server
func NewServer() *http.Server {
    return &http.Server{
        ReadHeaderTimeout: 5 * time.Second,
        IdleTimeout:      120 * time.Second, // ALB-friendly
        MaxHeaderBytes:   32 << 10,          // 32KB headers max
    }
}

// SSE with heartbeat and early size rejection
func (c *ClientConnection) sseWriter(w http.ResponseWriter) {
    flusher := w.(http.Flusher)
    heartbeat := time.NewTicker(20 * time.Second)
    defer heartbeat.Stop()
    
    for {
        select {
        case msg := <-c.outbound:
            // Fail fast on oversized messages
            if len(msg) > 256*1024 {
                c.sendError("request_too_large")
                continue
            }
            
            fmt.Fprintf(w, "data: %s\n\n", msg)
            flusher.Flush()
            
        case <-heartbeat.C:
            fmt.Fprintf(w, ": heartbeat\n\n")
            flusher.Flush()
            
        case <-c.ctx.Done():
            return
        }
    }
}

// Early size rejection with LimitedReader
func (s *AirlockServer) parseRequest(r *http.Request) (*Request, error) {
    limited := &io.LimitedReader{R: r.Body, N: 256 * 1024}
    
    var req Request
    if err := json.NewDecoder(limited).Decode(&req); err != nil {
        if limited.N == 0 {
            return nil, ErrRequestTooLarge
        }
        return nil, err
    }
    return &req, nil
}
```

**Rate Limiting with Built-in Tools:**
```go
import "golang.org/x/time/rate"

// Per-token rate limiter with singleflight for cache misses
type RateLimiter struct {
    limiters sync.Map // map[string]*rate.Limiter
    sf       singleflight.Group
}

func (rl *RateLimiter) Allow(token string) bool {
    limiter, _ := rl.sf.Do(token, func() (interface{}, error) {
        if l, ok := rl.limiters.Load(token); ok {
            return l, nil
        }
        
        // 200 req/min = ~3.33 req/sec with burst of 10
        limiter := rate.NewLimiter(rate.Limit(3.33), 10)
        rl.limiters.Store(token, limiter)
        return limiter, nil
    })
    
    return limiter.(*rate.Limiter).Allow()
}
```

**Memory-Efficient Resource Handling:**
```go
// Zero-copy streaming with sync.Pool
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 32*1024) // 32KB buffers
    },
}

// Stream large resources without buffering
func (r *RootMapper) streamResource(ctx context.Context, uri string) (io.ReadCloser, error) {
    switch {
    case strings.HasPrefix(uri, "s3://"):
        // AWS SDK returns io.ReadCloser - stream directly
        return r.s3Client.GetObject(ctx, &s3.GetObjectInput{
            Bucket: aws.String(bucket),
            Key:    aws.String(key),
        })
        
    case strings.HasPrefix(uri, "file://"):
        // File streaming with proper cleanup
        return os.Open(r.mapToRealPath(uri))
    }
}

// Reuse JSON encoders in hot paths
var encoderPool = sync.Pool{
    New: func() interface{} {
        return json.NewEncoder(nil)
    },
}
```

**Robust Authentication with Background Refresh:**
```go
// JWKS refresh with context-aware background goroutine
func (a *Authenticator) startJWKSRefresh(ctx context.Context) {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            if err := a.refreshJWKS(ctx); err != nil {
                log.Error("JWKS refresh failed", "error", err)
                // Continue with cached keys
            }
            
        case <-ctx.Done():
            return
        }
    }
}

// Clock skew handling in pure Go
func (a *Authenticator) validateTiming(claims *jwt.Claims) error {
    now := time.Now()
    skew := 2 * time.Minute
    
    if claims.ExpiresAt != nil && now.After(claims.ExpiresAt.Add(skew)) {
        return ErrTokenExpired
    }
    
    if claims.NotBefore != nil && now.Before(claims.NotBefore.Add(-skew)) {
        return ErrTokenNotYetValid
    }
    
    return nil
}
```

**Policy Engine with LKG and Caching:**
```go
// Sharded decision cache with per-tenant isolation
type PolicyCache struct {
    shards []*sync.Map // 16 shards to reduce contention
    ttl    time.Duration
}

func (pc *PolicyCache) Get(tenant, key string) (*PolicyDecision, bool) {
    shard := pc.shards[hash(tenant+key)%16]
    
    if entry, ok := shard.Load(key); ok {
        cached := entry.(*CacheEntry)
        if time.Since(cached.timestamp) < pc.ttl {
            return cached.decision, true
        }
        shard.Delete(key) // expired
    }
    return nil, false
}

// Last-Known-Good policy with atomic swapping
type PolicyEngine struct {
    current atomic.Value // *rego.PreparedEvalQuery
    lkg     atomic.Value // *rego.PreparedEvalQuery
}

func (pe *PolicyEngine) ReloadPolicy(policy string) error {
    compiled, err := rego.New(rego.Query("data.airlock.authz.allow")).PrepareForEval(context.Background())
    if err != nil {
        log.Error("Policy compilation failed, keeping LKG", "error", err)
        return err
    }
    
    // Atomic swap - no locks needed
    pe.current.Store(&compiled)
    if pe.lkg.Load() == nil {
        pe.lkg.Store(&compiled) // First successful compile becomes LKG
    }
    
    return nil
}
```

**Path Sandboxing with Modern Syscalls:**
```go
// Safe path resolution with filepath.Clean and validation
func (rm *RootMapper) validatePath(virtualPath, realRoot string) (string, error) {
    // Clean and validate virtual path
    cleaned := filepath.Clean(virtualPath)
    
    // Reject dangerous patterns
    if strings.Contains(cleaned, "..") || filepath.IsAbs(cleaned) {
        return "", ErrPathTraversal
    }
    
    // Build real path
    realPath := filepath.Join(realRoot, cleaned)
    
    // Ensure it's still within root (handles symlinks)
    if !strings.HasPrefix(realPath, realRoot) {
        return "", ErrPathEscape
    }
    
    // Optional: use openat2 with RESOLVE_BENEATH on Linux 5.6+
    if runtime.GOOS == "linux" {
        return rm.openat2Resolve(realRoot, cleaned)
    }
    
    return realPath, nil
}
```

**Built-in Observability:**
```go
// Structured logging with correlation IDs
func (s *AirlockServer) logRequest(ctx context.Context, decision string, latency time.Duration) {
    slog.InfoContext(ctx, "request_processed",
        "tenant", getTenant(ctx),
        "tool", getTool(ctx),
        "decision", decision,
        "latency_ms", latency.Milliseconds(),
        "correlation_id", getCorrelationID(ctx),
    )
}

// Built-in profiling for production debugging
func (s *AirlockServer) enableProfiling() {
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil)) // pprof endpoints
    }()
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

# Define allowed tools per tenant/group (explicit lists preferred)
allowed_tool contains tool if {
    tool := input.tool
    tool in ["search_docs", "read_file", "list_directory"]
    input.groups[_] == "mcp.users"
}

allowed_tool contains tool if {
    tool := input.tool
    tool in ["read_file", "read_directory", "read_config", "search_docs"]
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

All errors use go-sdk error types with deterministic HTTP-to-MCP mapping:

| HTTP Status | Scenario | MCP Error Code | Data Fields |
|-------------|----------|----------------|-------------|
| 401 | Missing/invalid token | InvalidRequest | `www_authenticate`, `correlation_id` |
| 403 | Policy denial | Forbidden | `reason`, `rule_id`, `correlation_id`, `tenant` |
| 413 | Message too large | RequestTooLarge | `max_size_kb`, `actual_size_kb` |
| 502 | Upstream failure | InternalError | `upstream_status`, `correlation_id` |
| 500 | Internal error | InternalError | `correlation_id` (no sensitive details) |

```go
import "github.com/modelcontextprotocol/go-sdk/pkg/protocol"

// Error mapping functions
func NewAuthenticationError(reason string) *protocol.Error {
    return &protocol.Error{
        Code:    protocol.ErrorCodeInvalidRequest,
        Message: "Authentication failed",
        Data: map[string]interface{}{
            "reason":           reason,
            "www_authenticate": "Bearer realm=\"mcp-airlock\"",
            "correlation_id":   generateCorrelationID(),
        },
    }
}

func NewPolicyDenialError(reason, ruleID, tenant string) *protocol.Error {
    return &protocol.Error{
        Code:    protocol.ErrorCodeForbidden,
        Message: "Policy denied request",
        Data: map[string]interface{}{
            "reason":         reason,
            "rule_id":        ruleID,
            "tenant":         tenant,
            "correlation_id": generateCorrelationID(),
        },
    }
}

func NewMessageTooLargeError(maxSize, actualSize int) *protocol.Error {
    return &protocol.Error{
        Code:    protocol.ErrorCodeRequestTooLarge,
        Message: "Request too large",
        Data: map[string]interface{}{
            "max_size_kb":    maxSize,
            "actual_size_kb": actualSize,
            "correlation_id": generateCorrelationID(),
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
│   ├── mcp/                 # MCP SDK adapter interface (ports.go)
│   ├── auth/                # Authentication and JWT validation
│   ├── policy/              # OPA policy engine with LKG fallback
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

go 1.24

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

## Deployment Architecture

### Single-VPC Production Deployment (MVP)

The primary deployment target is a single Kubernetes cluster within an AWS VPC, providing "zero-trust MCP as a service" for organizations:

```
Internet/VPN Users
    │
    │ HTTPS/SSE
    ▼
┌─────────────────────────────────────┐
│              AWS VPC                │
│                                     │
│  [ALB Ingress] → [Airlock Pods]     │
│       │              │              │
│       │              ▼              │
│   TLS Term.    [MCP Server Pods]    │
│                [Unix Sockets]       │
│                                     │
│  [EFS/EBS] ← Virtual Roots          │
│  [S3 Bucket] ← Artifact Storage     │
│  [RDS/SQLite] ← Audit Storage       │
│                                     │
│  Egress: OIDC + S3 only             │
└─────────────────────────────────────┘
```

### Deployment Components

**Ingress Layer:**
- AWS Application Load Balancer (ALB) with TLS termination
- Kubernetes Ingress Controller routing to Airlock service
- Security groups allowing HTTPS (443) from authorized networks

**Airlock Layer:**
- 2-3 stateless pod replicas with Horizontal Pod Autoscaler
- CPU/QPS-based scaling with pod disruption budgets
- Health checks: `/live` and `/ready` endpoints

**Upstream MCP Servers:**
- Option A: Sidecar containers with Unix socket communication
- Option B: Separate pods with HTTP service communication
- Managed via Kubernetes Deployments with service discovery

**Storage Layer:**
- **Audit**: SQLite per-pod with local PVC (single writer, no sharing across replicas)
- **Virtual Roots**: EFS/EBS for filesystem access (read-only via mount-level enforcement)
- **Artifacts**: S3 buckets (read-only except single allow-listed prefix)

**Security:**
- Pod Security Admission (PSA) levels + NetworkPolicy (not deprecated PodSecurityPolicies)
- Egress filtering: only OIDC issuer and S3 endpoints
- SSE heartbeat every 15-30s; ALB idle timeout ≥ 120s
- Resource URI whitelist: only configured virtual schemes (mcp://repo/, mcp://artifacts/)
- Secrets management via Kubernetes Secrets or AWS Secrets Manager

### Helm Configuration Example

```yaml
# values.yaml for single-VPC deployment
ingress:
  enabled: true
  className: "alb"
  annotations:
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
  hosts:
    - host: airlock.myorg.com
      paths:
        - path: /
          pathType: Prefix

auth:
  oidc:
    issuer: "https://myorg.okta.com/oauth2/default"
    audience: "mcp-airlock"
    requiredGroups: ["mcp.users"]

policy:
  configMap: "airlock-policy"
  hotReload: true

roots:
  - name: "repo"
    type: "fs"
    virtual: "mcp://repo/"
    real: "/mnt/repo"
    readOnly: true
    storage:
      type: "efs"
      volumeId: "fs-12345678"
  - name: "artifacts"
    type: "s3"
    virtual: "mcp://artifacts/"
    real: "s3://airlock-artifacts/prod/"

upstreams:
  - name: "docs"
    type: "unix"
    socket: "/run/mcp/docs.sock"
    sidecar:
      image: "myorg/mcp-docs:latest"
      command: ["python", "-m", "mcp_server.docs"]
  - name: "analytics"
    type: "http"
    url: "http://mcp-analytics.svc.cluster.local:8080"

scaling:
  replicas: 3
  hpa:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80

resources:
  requests:
    cpu: "100m"
    memory: "128Mi"
  limits:
    cpu: "500m"
    memory: "512Mi"

audit:
  storage:
    type: "sqlite"  # or "postgresql"
    pvc:
      size: "10Gi"
      storageClass: "gp3"
  retention: "30d"
  export:
    s3Bucket: "airlock-audit-exports"

observability:
  metrics:
    enabled: true
    serviceMonitor: true
  tracing:
    enabled: true
    endpoint: "http://jaeger-collector:14268/api/traces"
  logging:
    level: "info"
    format: "json"
```

### End-to-End User Flow

**1. Administrator Setup:**
```bash
# Deploy Airlock
helm install airlock ./deploy/helm -f values-prod.yaml

# Configure OIDC integration
kubectl apply -f oidc-config.yaml

# Set up virtual roots and policies
kubectl apply -f policy-configmap.yaml
kubectl apply -f roots-config.yaml
```

**2. Developer Onboarding:**
```bash
# Authenticate with OIDC provider
airlock auth login --issuer https://myorg.okta.com

# Configure IDE/client
export MCP_ENDPOINT="https://airlock.myorg.com"
export MCP_TOKEN="$(airlock auth token)"

# Test connection
mcp-client connect $MCP_ENDPOINT --token $MCP_TOKEN
```

**3. Runtime Flow:**
- Developer IDE connects to Airlock endpoint with Bearer token
- Airlock validates JWT, applies policies, maps virtual roots
- Requests proxied to appropriate upstream MCP servers
- Responses filtered through DLP redaction before return
- All interactions logged to audit trail with correlation IDs

### Multi-Tenancy Patterns

**Single Organization (MVP):**
- One Airlock deployment with OPA policies keyed by groups/roles
- Shared infrastructure with policy-based isolation

**Multi-Tenant B2B (Future):**
- Separate Airlock deployment per tenant namespace
- Isolated audit databases and virtual root mappings
- No shared caches or policy decisions across tenants

### Operational Considerations

**Monitoring:**
- Prometheus metrics for performance and security events
- Jaeger tracing for request flow analysis
- CloudWatch/Loki for structured log aggregation

**Security:**
- Regular security scanning with Trivy
- Image signing with Cosign
- Network policies and pod security standards
- Secrets rotation and key management

**Disaster Recovery:**
- Audit log backup to S3 with cross-region replication
- Configuration backup and GitOps deployment
- RTO/RPO targets for service restoration

### Go-Specific Testing and Build Patterns

**Testing with Go's Built-in Tools:**
```go
// Property-based testing for path validation
func TestPathValidation(t *testing.T) {
    f := func(path string) bool {
        cleaned, err := validatePath(path, "/safe/root")
        if err != nil {
            return true // rejection is always safe
        }
        return strings.HasPrefix(cleaned, "/safe/root")
    }
    
    if err := quick.Check(f, nil); err != nil {
        t.Error(err)
    }
}

// Fuzzing for JSON-RPC parsing (Go 1.18+)
func FuzzJSONRPCParsing(f *testing.F) {
    f.Add(`{"jsonrpc":"2.0","method":"test","id":1}`)
    
    f.Fuzz(func(t *testing.T, data string) {
        var req Request
        json.Unmarshal([]byte(data), &req) // Should never panic
    })
}

// httptest for SSE flows without live infrastructure
func TestSSEConnection(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(sseHandler))
    defer server.Close()
    
    // Test SSE connection and heartbeat
    resp, err := http.Get(server.URL + "/sse")
    require.NoError(t, err)
    
    scanner := bufio.NewScanner(resp.Body)
    // Verify heartbeat and message format
}

// Deterministic time for cache TTL testing
type MockClock struct{ now time.Time }
func (m *MockClock) Now() time.Time { return m.now }
func (m *MockClock) Advance(d time.Duration) { m.now = m.now.Add(d) }

// Benchmarks for critical paths
func BenchmarkPolicyEvaluation(b *testing.B) {
    engine := setupPolicyEngine()
    input := &PolicyInput{Tool: "read_file", Resource: "mcp://repo/test.txt"}
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        engine.Evaluate(context.Background(), input)
    }
}
```

**Production Build Optimizations:**
```dockerfile
# Multi-stage build with Go optimizations
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Optimized build flags
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -trimpath \
    -o airlock ./cmd/airlock

# Minimal runtime with non-root user
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /app/airlock /airlock

USER nobody
EXPOSE 8080
ENTRYPOINT ["/airlock"]
```

**CI/CD with Go Tools:**
```yaml
# .github/workflows/ci.yml
- name: Test with race detection
  run: go test -race -coverprofile=coverage.out ./...

- name: Fuzz testing
  run: go test -fuzz=. -fuzztime=30s ./...

- name: Static analysis
  run: |
    go vet ./...
    staticcheck ./...
    gosec ./...

- name: Benchmark regression
  run: go test -bench=. -benchmem ./... > bench.txt

- name: Build optimized binary
  run: |
    go build -ldflags="-s -w" -trimpath ./cmd/airlock
    syft airlock -o spdx-json > sbom.json
```

**Memory and Performance Monitoring:**
```go
// Built-in profiling endpoints
import _ "net/http/pprof"

func main() {
    // Enable pprof in production (behind auth)
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()
    
    // Runtime metrics
    go func() {
        for {
            var m runtime.MemStats
            runtime.ReadMemStats(&m)
            
            log.Printf("Alloc=%d KB, Sys=%d KB, NumGC=%d", 
                m.Alloc/1024, m.Sys/1024, m.NumGC)
            
            time.Sleep(30 * time.Second)
        }
    }()
}

// GC tuning for consistent latency
func init() {
    // Tune GC for lower latency (measure first!)
    debug.SetGCPercent(100) // Default, adjust based on profiling
}
```

**Why Go Excels for Airlock:**

1. **Concurrency Model**: Goroutines map perfectly to our "one connection = one goroutine" model with bounded channels preventing memory exhaustion
2. **HTTP/SSE Built-ins**: `net/http` with `http.Flusher` gives us production-ready SSE with minimal code
3. **Context Propagation**: `context.Context` provides clean cancellation from client disconnect through the entire request pipeline
4. **Memory Efficiency**: `sync.Pool` for buffer reuse, zero-copy streaming with `io.Reader`, and predictable GC behavior
5. **Built-in Security**: Race detector catches concurrency bugs, fuzzing finds parsing edge cases, and `go vet` prevents common mistakes
6. **Operational Excellence**: `pprof` for live debugging, `expvar` for metrics, and deterministic builds with module checksums
7. **Performance**: Sub-60ms p95 latency achievable with careful allocation patterns and Go's efficient runtime

This design provides a comprehensive, production-ready architecture that addresses all the requirements while maintaining high performance, security, and operational excellence. The modular design allows for independent testing and deployment of components while ensuring clear separation of concerns. By building on the official MCP Go SDK and leveraging Go's concurrency primitives, we ensure protocol compliance and optimal performance characteristics.
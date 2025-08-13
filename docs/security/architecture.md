# Security Architecture

This document describes the security architecture and design principles of MCP Airlock.

## Overview

MCP Airlock implements a zero-trust security model that assumes no implicit trust and verifies every request. The system provides secure access to internal MCP servers through multiple layers of security controls.

## Security Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Internet/External Clients                │
└─────────────────────────┬───────────────────────────────────────┘
                          │ HTTPS/TLS 1.3
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Load Balancer (ALB/Ingress)                  │
│  • TLS Termination                                              │
│  • DDoS Protection                                              │
│  • Rate Limiting                                                │
└─────────────────────────┬───────────────────────────────────────┘
                          │ HTTP (internal)
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      MCP Airlock Gateway                        │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                Authentication Layer                      │   │
│  │  • OIDC/JWT Validation                                  │   │
│  │  • JWKS Caching (TTL: 5m)                              │   │
│  │  • Clock Skew Handling (±2m)                           │   │
│  │  • Tenant Extraction                                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          │                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                Authorization Layer                       │   │
│  │  • OPA/Rego Policy Engine                              │   │
│  │  • Fine-grained Access Control                         │   │
│  │  • Resource Path Validation                            │   │
│  │  • Tool Allowlists                                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          │                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                Data Protection Layer                     │   │
│  │  • DLP Redaction Engine                                │   │
│  │  • PII Pattern Matching                                │   │
│  │  • Structured Data Filtering                           │   │
│  │  • Content Sanitization                                │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          │                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                Root Virtualization                       │   │
│  │  • Virtual URI Mapping                                 │   │
│  │  • Path Traversal Prevention                           │   │
│  │  • Read-only Enforcement                               │   │
│  │  • Sandboxing                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                          │                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                 Audit & Monitoring                       │   │
│  │  • Request/Response Logging                            │   │
│  │  • Security Event Tracking                             │   │
│  │  • Hash Chain Integrity                                │   │
│  │  • Compliance Reporting                                │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────────┘
                          │ stdio/Unix Socket
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Internal MCP Servers                         │
│  • Document Servers                                            │
│  • Code Analysis Servers                                       │
│  • Custom Business Logic                                       │
└─────────────────────────────────────────────────────────────────┘
```

## Security Layers

### 1. Network Security

**TLS Termination:**
- TLS 1.3 enforcement at load balancer
- Certificate validation and management
- Perfect Forward Secrecy (PFS)
- HSTS headers for browser security

**Network Isolation:**
- Kubernetes Network Policies
- Pod-to-pod communication restrictions
- Ingress/egress traffic controls
- Service mesh integration (optional)

**DDoS Protection:**
- Rate limiting at multiple layers
- Connection throttling
- Request size limits
- Burst protection

### 2. Authentication Layer

**OIDC/JWT Validation:**
```go
type AuthenticationLayer struct {
    oidcProvider   *oidc.Provider
    jwksCache      *jwks.Cache
    tokenValidator *jwt.Validator
    clockSkew      time.Duration
}

func (a *AuthenticationLayer) ValidateToken(ctx context.Context, token string) (*Claims, error) {
    // 1. Parse JWT without verification
    unverified, err := jwt.ParseUnverified(token, &Claims{})
    if err != nil {
        return nil, ErrInvalidToken
    }
    
    // 2. Get signing key from JWKS cache
    key, err := a.jwksCache.GetKey(unverified.Header["kid"].(string))
    if err != nil {
        return nil, ErrKeyNotFound
    }
    
    // 3. Verify signature and claims
    verified, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return key, nil
    })
    if err != nil {
        return nil, ErrTokenInvalid
    }
    
    // 4. Validate timing with clock skew
    claims := verified.Claims.(*Claims)
    if err := a.validateTiming(claims); err != nil {
        return nil, err
    }
    
    return claims, nil
}
```

**Security Features:**
- JWKS caching with automatic refresh
- Clock skew tolerance (±2 minutes)
- Token expiration validation
- Issuer and audience validation
- Rate limiting per token/IP

### 3. Authorization Layer

**Policy Engine Architecture:**
```go
type PolicyEngine struct {
    rego        *rego.Rego
    cache       *PolicyCache
    lkgPolicy   atomic.Value // Last-Known-Good policy
    metrics     *PolicyMetrics
}

type PolicyInput struct {
    Subject     string            `json:"sub"`
    Tenant      string            `json:"tenant"`
    Groups      []string          `json:"groups"`
    Tool        string            `json:"tool"`
    Resource    string            `json:"resource"`
    Method      string            `json:"method"`
    Headers     map[string]string `json:"headers"`
    Metadata    map[string]interface{} `json:"metadata"`
}

type PolicyDecision struct {
    Allow       bool                   `json:"allow"`
    Reason      string                 `json:"reason"`
    RuleID      string                 `json:"rule_id"`
    Metadata    map[string]interface{} `json:"metadata"`
    CacheKey    string                 `json:"-"`
    TTL         time.Duration          `json:"-"`
}
```

**Policy Features:**
- Fine-grained access control
- Tool and resource allowlists
- Tenant isolation
- Group-based permissions
- Decision caching with TTL
- Hot-reload with LKG fallback

### 4. Data Protection Layer

**DLP Redaction Engine:**
```go
type RedactionEngine struct {
    patterns    []*CompiledPattern
    bufferPool  sync.Pool
    metrics     *RedactionMetrics
}

type CompiledPattern struct {
    Name        string
    Regex       *regexp.Regexp
    Replacement string
    Fields      []string // for structured redaction
}

func (r *RedactionEngine) RedactContent(ctx context.Context, content []byte) (*RedactionResult, error) {
    buffer := r.bufferPool.Get().([]byte)
    defer r.bufferPool.Put(buffer)
    
    result := &RedactionResult{
        Data:           make([]byte, len(content)),
        RedactionCount: 0,
        PatternsHit:    make(map[string]int),
    }
    
    copy(result.Data, content)
    
    for _, pattern := range r.patterns {
        matches := pattern.Regex.FindAllIndex(result.Data, -1)
        if len(matches) > 0 {
            result.RedactionCount += len(matches)
            result.PatternsHit[pattern.Name] += len(matches)
            
            // Replace matches with redaction string
            result.Data = pattern.Regex.ReplaceAll(result.Data, []byte(pattern.Replacement))
        }
    }
    
    return result, nil
}
```

**Protection Features:**
- PII pattern detection and redaction
- Structured data filtering
- Content sanitization
- Redaction metrics and monitoring
- Configurable patterns and replacements

### 5. Root Virtualization Layer

**Path Security:**
```go
type RootMapper struct {
    roots       map[string]*VirtualRoot
    pathCache   *lru.Cache
    validator   *PathValidator
}

type VirtualRoot struct {
    Name        string
    Type        string // "fs", "s3"
    VirtualPath string
    RealPath    string
    ReadOnly    bool
    Backend     Backend
}

func (rm *RootMapper) MapPath(ctx context.Context, virtualURI string, tenant string) (*MappedPath, error) {
    // 1. Parse and validate virtual URI
    parsed, err := url.Parse(virtualURI)
    if err != nil {
        return nil, ErrInvalidURI
    }
    
    // 2. Find matching virtual root
    root, ok := rm.roots[parsed.Scheme+"://"+parsed.Host]
    if !ok {
        return nil, ErrRootNotFound
    }
    
    // 3. Validate path traversal
    cleanPath := filepath.Clean(parsed.Path)
    if strings.Contains(cleanPath, "..") || filepath.IsAbs(cleanPath) {
        return nil, ErrPathTraversal
    }
    
    // 4. Build real path with tenant isolation
    realPath := filepath.Join(root.RealPath, tenant, cleanPath)
    
    // 5. Ensure path is within bounds
    if !strings.HasPrefix(realPath, root.RealPath) {
        return nil, ErrPathEscape
    }
    
    return &MappedPath{
        VirtualURI: virtualURI,
        RealPath:   realPath,
        Root:       root,
    }, nil
}
```

**Virtualization Features:**
- Virtual URI to real path mapping
- Path traversal prevention
- Read-only enforcement
- Tenant isolation
- Multiple backend support (filesystem, S3)

### 6. Audit and Monitoring Layer

**Audit System:**
```go
type AuditLogger struct {
    backend     AuditBackend
    hasher      *HashChain
    buffer      chan *AuditEvent
    metrics     *AuditMetrics
}

type AuditEvent struct {
    ID            string                 `json:"id"`
    Timestamp     time.Time              `json:"timestamp"`
    CorrelationID string                 `json:"correlation_id"`
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

func (al *AuditLogger) LogEvent(ctx context.Context, event *AuditEvent) error {
    // 1. Generate correlation ID if not present
    if event.CorrelationID == "" {
        event.CorrelationID = generateCorrelationID()
    }
    
    // 2. Calculate hash chain
    event.Hash, event.PreviousHash = al.hasher.NextHash(event)
    
    // 3. Buffer event for async processing
    select {
    case al.buffer <- event:
        return nil
    default:
        // Buffer full - apply backpressure
        return ErrAuditBufferFull
    }
}
```

**Audit Features:**
- Comprehensive event logging
- Hash chain integrity protection
- Tamper detection
- Correlation ID tracking
- Async processing with backpressure
- Multiple storage backends

## Security Controls Implementation

### Authentication Controls

| Control | Implementation | Verification |
|---------|----------------|--------------|
| Strong Authentication | OIDC/JWT with RS256+ | Token signature validation |
| Token Validation | JWKS with caching | Automated JWKS refresh |
| Clock Skew Handling | ±2 minute tolerance | Time synchronization checks |
| Rate Limiting | Per-token and per-IP | Metrics monitoring |
| Brute Force Protection | Exponential backoff | Failed attempt tracking |

### Authorization Controls

| Control | Implementation | Verification |
|---------|----------------|--------------|
| Fine-grained Access | OPA/Rego policies | Policy testing framework |
| Least Privilege | Explicit allowlists | Regular access reviews |
| Tenant Isolation | Namespace separation | Cross-tenant access tests |
| Resource Validation | Path sanitization | Path traversal tests |
| Policy Hot-reload | SIGHUP handling | Zero-downtime updates |

### Data Protection Controls

| Control | Implementation | Verification |
|---------|----------------|--------------|
| Data Redaction | Regex pattern matching | Pattern effectiveness tests |
| Encryption at Rest | Database/storage encryption | Encryption verification |
| Encryption in Transit | TLS 1.3 enforcement | TLS configuration tests |
| Content Filtering | Structured data parsing | Content sanitization tests |
| Audit Protection | Hash chain integrity | Tamper detection tests |

### Infrastructure Controls

| Control | Implementation | Verification |
|---------|----------------|--------------|
| Container Security | Non-root execution | Security scanning |
| Network Isolation | Kubernetes NetworkPolicies | Network connectivity tests |
| Resource Limits | CPU/memory constraints | Resource usage monitoring |
| Secret Management | Kubernetes secrets | Secret rotation procedures |
| Image Security | Distroless base images | Vulnerability scanning |

## Threat Mitigation Matrix

| Threat Category | Mitigations | Monitoring |
|-----------------|-------------|------------|
| Authentication Bypass | JWT validation, JWKS caching, rate limiting | Auth failure metrics, anomaly detection |
| Authorization Bypass | OPA policies, path validation, tenant isolation | Policy decision logs, access patterns |
| Data Exfiltration | DLP redaction, audit logging, network controls | Data access patterns, large transfers |
| Injection Attacks | Input validation, path sanitization, parameterized queries | Error patterns, suspicious inputs |
| DoS/DDoS | Rate limiting, resource limits, circuit breakers | Request rates, resource usage |
| Privilege Escalation | Least privilege, container security, network policies | Permission changes, unusual access |
| Man-in-the-Middle | TLS enforcement, certificate validation, HSTS | TLS errors, certificate changes |
| Insider Threats | Audit logging, access controls, monitoring | Unusual access patterns, data access |

## Security Metrics and KPIs

### Authentication Metrics
- Authentication success/failure rates
- Token validation latency
- JWKS refresh frequency
- Rate limiting triggers

### Authorization Metrics
- Policy decision rates (allow/deny)
- Policy evaluation latency
- Policy reload frequency
- Access pattern analysis

### Data Protection Metrics
- Redaction event counts
- Pattern match rates
- Content filtering effectiveness
- Encryption coverage

### Audit Metrics
- Event logging rates
- Hash chain integrity
- Storage utilization
- Export success rates

## Compliance Considerations

### SOC 2 Type II
- Access controls and monitoring
- Data protection and encryption
- Audit logging and retention
- Incident response procedures

### GDPR
- Data subject rights (erasure via tombstones)
- Data minimization (redaction)
- Consent management (policy controls)
- Breach notification (monitoring/alerting)

### HIPAA
- Access controls and audit trails
- Data encryption and protection
- Administrative safeguards
- Technical safeguards

### PCI DSS
- Network security controls
- Access control measures
- Data protection requirements
- Monitoring and testing

## Security Testing

### Static Analysis
- Code security scanning (gosec, semgrep)
- Dependency vulnerability scanning
- Configuration security validation
- Policy syntax validation

### Dynamic Testing
- Penetration testing
- Fuzzing (input validation)
- Load testing (DoS resistance)
- Integration testing

### Security Regression Testing
- Authentication bypass attempts
- Authorization bypass attempts
- Path traversal attacks
- Injection attack vectors
- Data exfiltration scenarios

## Incident Response Integration

### Detection
- Security metrics monitoring
- Anomaly detection algorithms
- Log analysis and correlation
- External threat intelligence

### Response
- Automated incident creation
- Security team notification
- Evidence preservation
- System isolation capabilities

### Recovery
- Service restoration procedures
- Security patch deployment
- Configuration updates
- Monitoring enhancement

This security architecture provides comprehensive protection through multiple layers of security controls, ensuring that MCP Airlock can safely expose internal MCP servers to external clients while maintaining zero-trust principles.
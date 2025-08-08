# Requirements Document

## Introduction

MCP Airlock is a zero-trust gateway that provides secure, policy-enforced access to remote MCP (Model Context Protocol) servers. It acts as a reverse proxy that enables hosts to communicate with MCP servers inside VPCs without compromising security through direct network access or data leakage. The system implements capability negotiation, policy enforcement, root virtualization, data redaction, and OAuth2 authentication at the edge.

## Requirements

### Requirement 1

**User Story:** As a system administrator, I want to securely expose internal MCP servers to external clients, so that I can maintain zero-trust security while enabling remote access.

#### Acceptance Criteria

1. WHEN an external client connects THEN the system SHALL terminate HTTP/SSE transport at the gateway
2. WHEN a client attempts to access an internal server THEN the system SHALL proxy the connection without exposing internal network topology
3. WHEN multiple tenants access the system THEN the system SHALL isolate their access based on configured policies
4. IF a connection attempt lacks proper authentication THEN the system SHALL reject with HTTP 401 + WWW-Authenticate: Bearer and return MCP-spec JSON-RPC error body

### Requirement 2

**User Story:** As a security engineer, I want comprehensive authentication and authorization controls, so that only authorized users can access specific MCP tools and resources.

#### Acceptance Criteria

1. WHEN a client connects THEN the system SHALL validate JWT via OIDC discovery with JWKS cache TTL ≤ 5m and clock skew ±2m
2. WHEN token validation succeeds THEN the system SHALL extract tenant and group information for policy decisions
3. WHEN a tool call is made THEN the system SHALL enforce allow/deny policies based on user context
4. IF authentication fails THEN the system SHALL return WWW-Authenticate headers with OAuth2 metadata
5. WHEN policies are updated THEN the system SHALL hot-reload with no 5xx during reload; deny only if no Last-Known-Good (LKG) exists, otherwise keep LKG and alert

### Requirement 3

**User Story:** As a compliance officer, I want all MCP interactions to be audited and sensitive data to be redacted, so that we maintain regulatory compliance and data protection.

#### Acceptance Criteria

1. WHEN any MCP interaction occurs THEN the system SHALL log the event with request ID and timestamp
2. WHEN sensitive data patterns are detected THEN the system SHALL redact before logging and before proxying, keeping only redaction counts in logs
3. WHEN audit logs are written THEN the system SHALL use blake3 hash-chaining for tamper detection with rotation and JSONL export
4. WHEN DLP rules are configured THEN the system SHALL apply them to both requests and responses
5. IF audit storage fails THEN the system SHALL alert administrators while maintaining service availability

### Requirement 4

**User Story:** As a developer, I want virtual root mapping for MCP resources, so that internal file paths and storage locations remain hidden from external clients.

#### Acceptance Criteria

1. WHEN a client requests a resource using virtual URI THEN the system SHALL map it to the real internal location
2. WHEN read-only roots are configured THEN the system SHALL enforce via mount-level readOnly and path sandboxing (filepath.Clean, deny symlinks, no .. escapes); seccomp optional
3. WHEN path traversal attempts are made THEN the system SHALL block them and log security violations
4. IF a virtual root maps to S3 THEN the system SHALL handle S3-specific operations transparently
5. WHEN multiple root types are configured THEN the system SHALL route requests to appropriate handlers

### Requirement 5

**User Story:** As a platform engineer, I want the gateway to be deployable in Kubernetes with proper observability, so that it integrates with our existing infrastructure.

#### Acceptance Criteria

1. WHEN deploying to Kubernetes THEN the system SHALL provide Helm charts with configurable values
2. WHEN the service starts THEN the system SHALL expose health check endpoints for readiness and liveness probes
3. WHEN processing requests THEN the system SHALL emit OTEL traces with span attributes: tenant, tool, decision (allow/deny), root, latency
4. WHEN errors occur THEN the system SHALL log structured messages with appropriate severity levels
5. IF the service becomes unhealthy THEN Kubernetes SHALL restart it automatically

### Requirement 6

**User Story:** As an operations engineer, I want high performance and reliability, so that the gateway doesn't become a bottleneck for MCP communications.

#### Acceptance Criteria

1. WHEN processing requests THEN the system SHALL maintain p95 < 60ms at 1 vCPU/512MB with payload ≤ 256 KiB
2. WHEN under load THEN the system SHALL handle at least 1000 messages per minute on 1 vCPU
3. WHEN upstream servers are slow THEN the system SHALL implement timeouts: connect 2s, upstream call 30s, cancellable via client abort
4. WHEN SSE connections fan out THEN the system SHALL use bounded queue per connection max 1,000 events; on overflow drop oldest + signal with MCP stream error
5. IF policy decisions are cached THEN the system SHALL respect TTL settings for security

### Requirement 7

**User Story:** As a developer integrating with the system, I want clear configuration and policy management, so that I can easily set up and maintain the gateway.

#### Acceptance Criteria

1. WHEN configuring the system THEN the system SHALL validate config schema at boot and fail to start on invalid config
2. WHEN writing policies THEN the system SHALL use OPA/Rego for consistent policy language
3. WHEN policies change THEN the system SHALL validate them before applying
4. WHEN configuration errors occur THEN the system SHALL provide clear error messages with line numbers
5. IF example configurations are provided THEN they SHALL demonstrate common use cases

### Requirement 8

**User Story:** As a security auditor, I want comprehensive logging and monitoring capabilities, so that I can track all security-relevant events and policy decisions.

#### Acceptance Criteria

1. WHEN policy decisions are made THEN the system SHALL log decisions with rule ID and input digest (no raw data)
2. WHEN redaction occurs THEN the system SHALL count and log redaction events without exposing original data
3. WHEN authentication events happen THEN the system SHALL log success/failure with relevant metadata
4. WHEN audit logs are exported THEN the system SHALL support multiple output formats
5. IF suspicious activity is detected THEN the system SHALL generate appropriate alerts

### Requirement 9

**User Story:** As an integrator, I want predictable MCP protocol behavior, so that I can reliably build clients that work with the gateway.

#### Acceptance Criteria

1. WHEN communicating with clients THEN the system SHALL use the official modelcontextprotocol/go-sdk for MCP protocol handling over HTTP + SSE transport
2. WHEN errors occur THEN the system SHALL use go-sdk error types and mapping to ensure MCP spec compliance
3. WHEN message size limits are exceeded THEN the system SHALL fail fast on oversized JSON-RPC (256 KiB default) and stream resource bodies for large content

### Requirement 10

**User Story:** As a platform owner, I want strong tenant isolation, so that tenants cannot access each other's resources or data.

#### Acceptance Criteria

1. WHEN processing requests THEN the system SHALL derive tenant from JWT claim (e.g., tid or org_id) and namespace all policy/audit roots
2. WHEN making policy decisions THEN the system SHALL prevent cross-tenant access with no shared caches for policy decisions across tenants
3. WHEN tenants exceed limits THEN the system SHALL enforce per-tenant quotas (QPS, concurrent streams) with configurable defaults and deny if unset

### Requirement 11

**User Story:** As a security engineer, I want DoS protection and abuse safeguards, so that the gateway remains available under attack.

#### Acceptance Criteria

1. WHEN rate limits are exceeded THEN the system SHALL enforce per-token rate limit (default 200 req/min) with in-memory limiter (MVP); Redis/Memcached for distributed enforcement (v1.1)
2. WHEN SSE reconnects occur THEN the system SHALL provide exponential backoff guidance with 20-40% jitter
3. WHEN authentication brute-force is detected THEN the system SHALL implement temporary 401 throttle after 5 failed auths/min/IP

### Requirement 12

**User Story:** As an operator, I want safe configuration and secret handling, so that sensitive data is protected and systems can be updated safely.

#### Acceptance Criteria

1. WHEN handling secrets THEN the system SHALL read via env/secret mounts and never write to audit or metrics
2. WHEN JWKS keys rotate THEN the system SHALL honor rotation within ≤ 10 minutes with tested key rollover
3. WHEN configuration changes THEN the system SHALL support hot-reload via SIGHUP or admin endpoint with transactional apply

### Requirement 13

**User Story:** As an SRE, I want predictable failure modes and graceful degradation, so that partial outages don't cause complete service failure.

#### Acceptance Criteria

1. WHEN audit store is down THEN the system SHALL continue serving but emit critical alert and buffer up to 10k events with backpressure after
2. WHEN OPA is unreachable or has compile errors THEN the system SHALL deny only if no Last-Known-Good policy exists; otherwise continue with LKG and emit critical alert
3. WHEN health checks are performed THEN the system SHALL provide /live and /ready endpoints (ready only when JWKS fetched + policy compiled)

### Requirement 14

**User Story:** As QA, I want verifiable system behavior, so that I can ensure the gateway works correctly under all conditions.

#### Acceptance Criteria

1. WHEN testing the system THEN the system SHALL provide golden tests for allow/deny, roots, redaction with canary tokens
2. WHEN running CI THEN the system SHALL include a mock MCP server and end-to-end test harness
3. WHEN performance testing THEN the system SHALL sustain ≥ 1,000 msgs/min with < 200 MiB RSS

### Requirement 15

**User Story:** As a compliance officer, I want data retention controls and privacy protection, so that we meet regulatory requirements.

#### Acceptance Criteria

1. WHEN storing audit data THEN the system SHALL support configurable retention (default 30 days) with S3 export and optional KMS
2. WHEN redacting PII THEN the system SHALL use unit-tested patterns with documented false-positive budget
3. WHEN data subject erasure is required THEN the system SHALL support subject erasure via tombstone events (not row deletes) to maintain hash-chain integrity

### Requirement 16

**User Story:** As a developer, I want to use the official MCP Go SDK, so that the gateway maintains protocol compliance and benefits from official updates.

#### Acceptance Criteria

1. WHEN implementing MCP protocol handling THEN the system SHALL use modelcontextprotocol/go-sdk v0.2.0+ as the foundation
2. WHEN creating server and client connections THEN the system SHALL use go-sdk Server and Client interfaces
3. WHEN handling MCP transports THEN the system SHALL leverage go-sdk HTTP/SSE transport implementations
4. WHEN processing MCP messages THEN the system SHALL use go-sdk message types and serialization
5. IF the go-sdk is updated THEN the system SHALL be designed to easily adopt new versions with minimal changes

### Requirement 17

**User Story:** As a platform operator, I want clear deployment patterns for single-VPC production environments, so that I can deploy Airlock as "zero-trust MCP as a service" for my organization.

#### Acceptance Criteria

1. WHEN deploying to AWS THEN the system SHALL support single-VPC Kubernetes deployment with ALB ingress and HPA scaling
2. WHEN configuring upstreams THEN the system SHALL support both Unix socket sidecars and HTTP service connections within the cluster
3. WHEN storing audit data THEN the system SHALL support SQLite with per-pod PVC (single writer) for MVP and PostgreSQL/RDS for production scale
4. WHEN managing virtual roots THEN the system SHALL support EFS/EBS for filesystem roots and S3 for object storage roots
5. IF scaling is needed THEN the system SHALL support horizontal pod autoscaling based on CPU/QPS with pod disruption budgets

### Requirement 18

**User Story:** As a business administrator, I want a complete onboarding flow from account setup to first MCP connection, so that developers can quickly start using secured MCP services.

#### Acceptance Criteria

1. WHEN setting up Airlock THEN the system SHALL provide Helm values templates for common AWS deployment scenarios
2. WHEN configuring OIDC THEN the system SHALL support standard IdP integration (Okta, Auth0, Azure AD) with group mapping
3. WHEN onboarding developers THEN the system SHALL provide clear connection snippets with endpoint URL and authentication flow
4. WHEN developers connect THEN the system SHALL return clear MCP-compliant errors with policy reasons and correlation IDs for troubleshooting
5. IF policy violations occur THEN the system SHALL provide actionable error messages that help developers understand access requirements

### Requirement 19

**User Story:** As a security engineer, I want strict resource URI validation, so that the gateway only accesses configured virtual schemes and prevents unauthorized resource access.

#### Acceptance Criteria

1. WHEN processing resource requests THEN the system SHALL only allow configured virtual schemes (mcp://repo/, mcp://artifacts/)
2. WHEN invalid schemes are requested THEN the system SHALL reject file://, http://, or other non-whitelisted schemes
3. WHEN virtual root mapping occurs THEN the system SHALL validate URI format and prevent scheme injection attacks
4. WHEN S3 roots are configured THEN the system SHALL start read-only except for single allow-listed artifacts prefix
5. IF unauthorized schemes are detected THEN the system SHALL log security violations and return clear error messages

### Requirement 20

**User Story:** As a developer, I want deterministic error responses, so that I can programmatically handle different failure scenarios.

#### Acceptance Criteria

1. WHEN authentication fails THEN the system SHALL return HTTP 401 with MCP error containing www_authenticate header
2. WHEN policy denies access THEN the system SHALL return HTTP 403 with MCP error containing reason, rule_id, and correlation_id
3. WHEN message size exceeds limits THEN the system SHALL return HTTP 413 with MCP error "request_too_large"
4. WHEN upstream servers fail THEN the system SHALL return HTTP 502 with MCP error containing upstream status
5. IF internal errors occur THEN the system SHALL return HTTP 500 with MCP error containing correlation_id but no sensitive details
# Implementation Plan

- [x] 1. Project scaffolding and core infrastructure setup
  - Initialize Go 1.22+ module with modelcontextprotocol/go-sdk v0.2.0+ dependency
  - Create repository structure with pkg/mcp/ports.go adapter interface for SDK isolation
  - Set up basic configuration loading with koanf and YAML validation
  - Implement structured logging with zap and basic health check endpoints
  - _Requirements: R7.1, R5.2, R16.1, R16.5_

- [-] 2. MCP Go-SDK integration foundation
- [x] 2.1 Create basic MCP server wrapper with Go concurrency patterns
  - Implement AirlockServer with one goroutine per client connection and bounded channels
  - Create HTTP/SSE transport with proper timeouts, heartbeat, and http.Flusher
  - Add context propagation for cancellation and correlation ID generation
  - Write unit tests with httptest and race detection enabled
  - _Requirements: R16.1, R16.2, R16.3, R9.1_

- [x] 2.2 Implement MCP client connector for upstream servers
  - Create UpstreamConnector using go-sdk Client for stdio/Unix socket connections
  - Implement client pool management with connection lifecycle handling
  - Add basic request proxying from server to upstream clients
  - Write unit tests for client connection and message forwarding
  - _Requirements: R16.2, R16.4, R1.2_

- [x] 2.3 Create end-to-end MCP message flow
  - Integrate server and client components for complete message routing
  - Implement basic error handling using go-sdk error types
  - Add request/response correlation and basic metrics collection
  - Write integration tests with mock upstream MCP server
  - _Requirements: R16.4, R9.2, R14.2_

- [x] 3. Authentication and JWT validation system
- [x] 3.1 Implement OIDC/JWT authentication with background refresh
  - Create Authenticator with context-aware background JWKS refresh goroutine
  - Implement JWT validation with pure Go clock skew handling (±2m)
  - Add tenant and group extraction with singleflight for cache miss protection
  - Write unit tests with deterministic time mocking and race detection
  - _Requirements: R2.1, R2.2, R12.2, R10.1_

- [x] 3.2 Add authentication middleware to MCP server
  - Integrate authentication layer with MCP server request processing
  - Implement session management and authentication context propagation
  - Add proper HTTP 401 responses with WWW-Authenticate headers
  - Write integration tests for authenticated and unauthenticated requests
  - _Requirements: R1.4, R2.1, R2.2_

- [x] 3.3 Implement rate limiting with golang.org/x/time/rate
  - Create RateLimiter using rate.Limiter with singleflight for thundering herd protection
  - Add per-token limits (200 req/min = ~3.33 req/sec) with sync.Map storage
  - Implement brute-force protection with temporary throttling and exponential backoff
  - Write unit tests for rate limiting scenarios with deterministic time control
  - _Requirements: R11.1, R11.2, R11.3_

- [x] 4. Policy engine integration with OPA/Rego
- [x] 4.1 Create OPA policy engine wrapper with Last-Known-Good fallback
  - Implement PolicyEngine interface with OPA/Rego integration and LKG policy storage
  - Add policy compilation, caching, and hot-reload via SIGHUP with fallback behavior
  - Create PolicyInput/PolicyDecision types with per-tenant cache isolation
  - Write unit tests for policy loading, compilation, LKG fallback, and basic decisions
  - _Requirements: R2.3, R2.5, R7.2, R12.3, R13.2_

- [x] 4.2 Integrate policy engine with request processing
  - Add policy middleware to MCP server request chain
  - Implement fail-closed behavior when policy engine is unavailable
  - Add policy decision logging with rule ID and input digest
  - Write integration tests for allow/deny scenarios and policy failures
  - _Requirements: R2.3, R2.4, R8.1, R13.2_

- [x] 4.3 Create comprehensive policy test suite with Go testing tools
  - Implement golden tests with property-based testing using testing/quick
  - Add fuzzing tests for policy input validation with Go 1.18+ fuzzing
  - Create tenant isolation tests with sharded cache validation
  - Write performance benchmarks targeting sub-millisecond policy evaluation
  - _Requirements: R14.1, R10.2, R6.5_

- [-] 5. Root virtualization and access control
- [x] 5.1 Implement virtual root mapping with Go path security
  - Create RootMapper using filepath.Clean and symlink validation
  - Add zero-copy streaming for S3 and filesystem resources with io.Reader
  - Implement path sandboxing with optional openat2 syscall on Linux
  - Write property-based tests for path traversal prevention with testing/quick
  - _Requirements: R4.1, R4.3, R4.4, R4.5_

- [x] 5.2 Add read-only enforcement via mount-level and path sandboxing
  - Implement mount-level readOnly enforcement and path sandboxing (filepath.Clean, deny symlinks)
  - Add S3 read-only mode except for single allow-listed artifacts prefix
  - Create resource URI whitelist validation (only mcp://repo/, mcp://artifacts/ schemes)
  - Write integration tests for read-only enforcement and URI validation
  - _Requirements: R4.2, R4.5, R19.1, R19.2, R19.4_

- [x] 5.3 Integrate root virtualization with MCP message processing
  - Add root mapping to MCP request/response processing pipeline
  - Implement resource URI rewriting for upstream server communication
  - Add root-based authorization checks in policy engine
  - Write end-to-end tests for virtual root access patterns
  - _Requirements: R4.1, R4.4, R4.5_

- [x] 6. DLP redaction and data protection
- [x] 6.1 Create memory-efficient redaction engine
  - Implement Redactor with sync.Pool for buffer reuse and compiled regex patterns
  - Add streaming redaction to avoid buffering large payloads
  - Create configurable redaction patterns with fuzzing tests for edge cases
  - Write benchmarks for redaction performance with memory allocation tracking
  - _Requirements: R3.2, R3.4, R15.2_

- [x] 6.2 Integrate redaction with request/response processing
  - Add redaction middleware to MCP server processing chain
  - Implement redaction before logging and before proxying to upstream
  - Add redaction count tracking for audit purposes
  - Write integration tests for request/response redaction scenarios
  - _Requirements: R3.2, R3.4_

- [x] 6.3 Add redaction monitoring and validation
  - Implement redaction effectiveness monitoring and false-positive tracking
  - Add unit tests for redaction patterns with documented false-positive budget
  - Create performance benchmarks for redaction overhead
  - Write security tests to validate PII protection effectiveness
  - _Requirements: R15.2, R14.3_

- [-] 7. Audit logging and compliance system
- [x] 7.1 Implement audit logging with hash chaining
  - Create AuditLogger interface with Blake3 hash chaining for tamper detection
  - Add SQLite backend with WAL mode for high-performance writes
  - Implement audit event structure with correlation IDs and metadata
  - Write unit tests for audit event creation, storage, and hash validation
  - _Requirements: R3.1, R3.3, R8.1, R8.2_

- [x] 7.2 Integrate audit logging with all security events
  - Add audit logging to authentication, authorization, and policy decisions
  - Implement audit event generation for redaction counts and security violations
  - Add structured logging with no raw sensitive data exposure
  - Write integration tests for complete audit trail coverage
  - _Requirements: R3.1, R8.1, R8.2, R8.3_

- [x] 7.3 Add audit retention and tombstone-based erasure
  - Implement configurable retention policies with automatic cleanup (default 30 days)
  - Add JSONL export format with optional S3 export and KMS encryption
  - Create subject erasure via tombstone events (preserves hash-chain integrity)
  - Write tests for retention policies, export functionality, and tombstone erasure
  - _Requirements: R15.1, R15.3, R8.4_

- [ ] 8. Error handling and resilience patterns
- [x] 8.1 Implement deterministic error handling with HTTP-to-MCP mapping
  - Create error mapping table (401→InvalidRequest, 403→Forbidden, 413→RequestTooLarge, etc.)
  - Add basic retry/backoff for upstream failures (circuit breaker in v1.1)
  - Implement graceful degradation when audit store fails (buffer events)
  - Write unit tests for error scenarios and deterministic error responses
  - _Requirements: R9.2, R13.1, R20.1, R20.2, R20.3, R20.4, R20.5_

- [x] 8.2 Add timeout, backpressure, and SSE heartbeat handling
  - Implement configurable timeouts (connect 2s, upstream call 30s) with ALB idle ≥ 120s
  - Add SSE heartbeat every 15-30s to prevent ALB connection drops
  - Add bounded queues for SSE connections with fail-fast on oversized JSON-RPC
  - Write integration tests for timeout scenarios, heartbeat, and message size limits
  - _Requirements: R6.3, R6.4, R9.3_

- [x] 8.3 Implement health checks and monitoring
  - Create /live and /ready endpoints with proper dependency checking
  - Add health checks for JWKS fetch, policy compilation, and upstream connectivity
  - Implement critical alerting for audit store failures with event buffering
  - Write tests for health check scenarios and alerting behavior
  - _Requirements: R5.2, R13.1, R13.3_

- [ ] 9. Configuration management and hot-reload
- [ ] 9.1 Create comprehensive configuration system
  - Implement YAML configuration with schema validation at boot
  - Add environment variable and secret mount support for sensitive data
  - Create configuration validation with clear error messages and line numbers
  - Write unit tests for configuration loading, validation, and error handling
  - _Requirements: R7.1, R7.4, R12.1_

- [ ] 9.2 Add hot-reload capabilities for policies and configuration
  - Implement SIGHUP handler for policy and configuration reload
  - Add transactional configuration updates with rollback on failure
  - Create admin endpoint for configuration reload with proper authorization
  - Write integration tests for hot-reload scenarios and failure handling
  - _Requirements: R2.5, R12.3, R7.3_

- [ ] 9.3 Add secrets management and key rotation support
  - Implement secure secret handling via environment variables and secret mounts
  - Add JWKS key rotation handling with tested rollover procedures
  - Create configuration templates and examples for common deployment scenarios
  - Write tests for secret handling and key rotation scenarios
  - _Requirements: R12.1, R12.2, R7.5_

- [ ] 10. Observability and monitoring integration
- [ ] 10.1 Implement OpenTelemetry tracing and metrics
  - Add OTEL tracing with span attributes (tenant, tool, decision, root, latency)
  - Implement structured metrics for performance, security events, and errors
  - Create trace correlation across authentication, policy, and upstream calls
  - Write tests for trace generation and metric collection
  - _Requirements: R5.3, R5.4_

- [ ] 10.2 Add performance monitoring and alerting
  - Implement performance benchmarks targeting p95 < 60ms at 1 vCPU/512MB
  - Add memory usage monitoring with alerts for resource exhaustion
  - Create dashboard templates for operational monitoring
  - Write performance tests to validate latency and throughput requirements
  - _Requirements: R6.1, R6.2, R14.3_

- [ ] 10.3 Create operational documentation and runbooks
  - Write deployment guides for Kubernetes with Helm charts
  - Create troubleshooting runbooks for common operational scenarios
  - Add security architecture documentation and threat model
  - Create API documentation and integration examples
  - _Requirements: R5.1, R7.5_

- [ ] 11. Kubernetes deployment and packaging
- [ ] 11.1 Create Docker images and Helm charts with modern security
  - Implement multi-stage Docker builds with non-root user and read-only filesystem
  - Create Helm charts with Pod Security Admission (PSA) levels and NetworkPolicy
  - Add per-pod SQLite PVC configuration (no sharing across replicas)
  - Write deployment tests for Kubernetes environments with security validation
  - _Requirements: R5.1, R5.5, R17.3_

- [ ] 11.2 Add CI/CD pipeline with security scanning
  - Implement GitHub Actions workflow with automated testing
  - Add Trivy security scanning and Cosign image signing
  - Create automated deployment to staging environments
  - Write integration tests for CI/CD pipeline and deployment validation
  - _Requirements: R5.1, R5.5_

- [ ] 11.3 Create production-ready Helm values and deployment examples
  - Create Helm values templates for single-VPC AWS deployment with ALB ingress
  - Add sidecar and HTTP service upstream configuration examples
  - Implement EFS/EBS and S3 virtual root integration examples
  - Write deployment validation tests for Kubernetes environments
  - _Requirements: R17.1, R17.2, R17.3, R17.4_

- [ ] 11.4 Build sample MCP servers and integration test harness
  - Create sample MCP servers (docs, analytics) for demonstration
  - Implement Unix socket sidecar deployment patterns
  - Add end-to-end integration test harness with real MCP clients
  - Write load tests to validate performance requirements in realistic environments
  - _Requirements: R14.2, R14.3, R17.2_

- [ ] 12. Security hardening and compliance validation
- [ ] 12.1 Implement security hardening measures
  - Add TLS 1.3 enforcement with proper certificate validation
  - Implement non-root container execution with read-only filesystem
  - Add seccomp profiles and capability dropping for container security
  - Write security tests for hardening measures and attack surface reduction
  - _Requirements: R1.1, R4.2_

- [ ] 12.2 Create comprehensive security test suite
  - Implement penetration testing scenarios for common attack vectors
  - Add fuzzing tests for input validation and protocol handling
  - Create security regression tests for policy bypass attempts
  - Write tests for path traversal, injection attacks, and privilege escalation
  - _Requirements: R4.3, R14.1_

- [ ] 12.3 Add compliance validation and audit capabilities
  - Implement compliance reporting for audit trail completeness
  - Add data retention validation and automated cleanup verification
  - Create compliance dashboard for regulatory reporting
  - Write tests for compliance requirements and audit trail integrity
  - _Requirements: R15.1, R15.3, R8.5_

- [ ] 13. Performance optimization and load testing
- [ ] 13.1 Optimize critical path performance
  - Profile and optimize authentication, policy evaluation, and redaction performance
  - Implement connection pooling and resource reuse optimizations
  - Add caching strategies for frequently accessed data (policy decisions, JWKS)
  - Write performance benchmarks for all critical code paths
  - _Requirements: R6.1, R6.2, R6.5_

- [ ] 13.2 Implement comprehensive load testing
  - Create load testing scenarios with realistic MCP traffic patterns
  - Add stress testing for resource exhaustion and failure scenarios
  - Implement sustained load testing to validate throughput requirements (≥1k msgs/min)
  - Write performance regression tests for CI/CD pipeline
  - _Requirements: R14.3, R6.2_

- [ ] 13.3 Add performance monitoring and optimization tooling
  - Implement runtime performance profiling and monitoring
  - Add automated performance regression detection
  - Create performance optimization recommendations and tuning guides
  - Write tools for performance analysis and bottleneck identification
  - _Requirements: R6.1, R6.2_

- [ ] 14. Final integration and production readiness
- [ ] 14.1 Complete end-to-end integration testing
  - Run comprehensive integration tests with real MCP clients and servers
  - Validate all security controls work together correctly
  - Test failure scenarios and recovery procedures
  - Write acceptance tests for all major user scenarios
  - _Requirements: R14.1, R14.2_

- [ ] 14.2 Production deployment validation
  - Deploy to staging environment with production-like configuration
  - Run security penetration testing against deployed system
  - Validate monitoring, alerting, and operational procedures
  - Write production deployment checklist and validation procedures
  - _Requirements: R5.1, R5.5_

- [ ] 14.3 Create onboarding documentation and developer experience
  - Write complete administrator setup guide with Helm deployment steps
  - Create developer onboarding documentation with connection snippets and authentication flow
  - Add troubleshooting guide with common policy errors and correlation ID lookup
  - Create demo scenarios showing end-to-end user flow from setup to first MCP connection
  - _Requirements: R18.1, R18.2, R18.3, R18.4, R18.5_

- [ ] 14.4 Complete operational documentation and handover materials
  - Finalize API documentation and integration guides
  - Create operational runbooks for scaling, monitoring, and incident response
  - Write security architecture documentation and threat model
  - Create training materials and production deployment checklists
  - _Requirements: R7.5, R17.5_
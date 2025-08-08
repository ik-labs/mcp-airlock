# Implementation Plan

- [ ] 1. Project scaffolding and core infrastructure setup
  - Initialize Go 1.24.0+ module with modelcontextprotocol/go-sdk v0.2.0+ dependency
  - Create repository structure with pkg/, cmd/, internal/, examples/, deploy/ directories
  - Set up basic configuration loading with koanf and YAML validation
  - Implement structured logging with zap and basic health check endpoints
  - _Requirements: R7.1, R5.2, R16.1_

- [ ] 2. MCP Go-SDK integration foundation
- [ ] 2.1 Create basic MCP server wrapper with go-sdk
  - Implement AirlockServer struct wrapping go-sdk Server
  - Create HTTP/SSE transport setup using go-sdk transport layer
  - Add basic request/response logging and correlation ID generation
  - Write unit tests for server initialization and basic message handling
  - _Requirements: R16.1, R16.2, R16.3, R9.1_

- [ ] 2.2 Implement MCP client connector for upstream servers
  - Create UpstreamConnector using go-sdk Client for stdio/Unix socket connections
  - Implement client pool management with connection lifecycle handling
  - Add basic request proxying from server to upstream clients
  - Write unit tests for client connection and message forwarding
  - _Requirements: R16.2, R16.4, R1.2_

- [ ] 2.3 Create end-to-end MCP message flow
  - Integrate server and client components for complete message routing
  - Implement basic error handling using go-sdk error types
  - Add request/response correlation and basic metrics collection
  - Write integration tests with mock upstream MCP server
  - _Requirements: R16.4, R9.2, R14.2_

- [ ] 3. Authentication and JWT validation system
- [ ] 3.1 Implement OIDC/JWT authentication layer
  - Create Authenticator interface with OIDC discovery and JWT validation
  - Implement JWKS caching with TTL ≤ 5m and automatic refresh
  - Add tenant and group extraction from JWT claims
  - Write unit tests for token validation, JWKS caching, and claim extraction
  - _Requirements: R2.1, R2.2, R12.2, R10.1_

- [ ] 3.2 Add authentication middleware to MCP server
  - Integrate authentication layer with MCP server request processing
  - Implement session management and authentication context propagation
  - Add proper HTTP 401 responses with WWW-Authenticate headers
  - Write integration tests for authenticated and unauthenticated requests
  - _Requirements: R1.4, R2.1, R2.2_

- [ ] 3.3 Implement rate limiting and abuse protection
  - Create RateLimiter with per-token and per-IP limits (default 200 req/min)
  - Add brute-force protection with temporary throttling after 5 failed auths/min/IP
  - Implement exponential backoff guidance for SSE reconnections with jitter
  - Write unit tests for rate limiting scenarios and abuse detection
  - _Requirements: R11.1, R11.2, R11.3_

- [ ] 4. Policy engine integration with OPA/Rego
- [ ] 4.1 Create OPA policy engine wrapper
  - Implement PolicyEngine interface with OPA/Rego integration
  - Add policy compilation, caching, and hot-reload via SIGHUP
  - Create PolicyInput/PolicyDecision types with tenant isolation
  - Write unit tests for policy loading, compilation, and basic decisions
  - _Requirements: R2.3, R2.5, R7.2, R12.3_

- [ ] 4.2 Integrate policy engine with request processing
  - Add policy middleware to MCP server request chain
  - Implement fail-closed behavior when policy engine is unavailable
  - Add policy decision logging with rule ID and input digest
  - Write integration tests for allow/deny scenarios and policy failures
  - _Requirements: R2.3, R2.4, R8.1, R13.2_

- [ ] 4.3 Create comprehensive policy test suite
  - Implement golden tests for allow/deny decisions with canary tokens
  - Add policy validation and error handling tests
  - Create tenant isolation tests to prevent cross-tenant access
  - Write performance benchmarks for policy evaluation latency
  - _Requirements: R14.1, R10.2, R6.5_

- [ ] 5. Root virtualization and access control
- [ ] 5.1 Implement virtual root mapping system
  - Create RootMapper interface for virtual URI to real path translation
  - Add support for filesystem and S3 backend types
  - Implement path normalization and traversal attack prevention
  - Write unit tests for URI mapping, path validation, and security checks
  - _Requirements: R4.1, R4.3, R4.4, R4.5_

- [ ] 5.2 Add read-only enforcement and access control
  - Implement syscall-level write protection for filesystem roots
  - Add S3 write operation blocking unless explicitly allow-listed
  - Create access validation for different operation types (read/write/list)
  - Write integration tests for read-only enforcement and write blocking
  - _Requirements: R4.2, R4.5_

- [ ] 5.3 Integrate root virtualization with MCP message processing
  - Add root mapping to MCP request/response processing pipeline
  - Implement resource URI rewriting for upstream server communication
  - Add root-based authorization checks in policy engine
  - Write end-to-end tests for virtual root access patterns
  - _Requirements: R4.1, R4.4, R4.5_

- [ ] 6. DLP redaction and data protection
- [ ] 6.1 Create configurable redaction engine
  - Implement Redactor interface with regex pattern compilation
  - Add support for structured JSON field redaction
  - Create configurable redaction patterns (email, tokens, PII)
  - Write unit tests for pattern matching, replacement, and performance
  - _Requirements: R3.2, R3.4, R15.2_

- [ ] 6.2 Integrate redaction with request/response processing
  - Add redaction middleware to MCP server processing chain
  - Implement redaction before logging and before proxying to upstream
  - Add redaction count tracking for audit purposes
  - Write integration tests for request/response redaction scenarios
  - _Requirements: R3.2, R3.4_

- [ ] 6.3 Add redaction monitoring and validation
  - Implement redaction effectiveness monitoring and false-positive tracking
  - Add unit tests for redaction patterns with documented false-positive budget
  - Create performance benchmarks for redaction overhead
  - Write security tests to validate PII protection effectiveness
  - _Requirements: R15.2, R14.3_

- [ ] 7. Audit logging and compliance system
- [ ] 7.1 Implement audit logging with hash chaining
  - Create AuditLogger interface with Blake3 hash chaining for tamper detection
  - Add SQLite backend with WAL mode for high-performance writes
  - Implement audit event structure with correlation IDs and metadata
  - Write unit tests for audit event creation, storage, and hash validation
  - _Requirements: R3.1, R3.3, R8.1, R8.2_

- [ ] 7.2 Integrate audit logging with all security events
  - Add audit logging to authentication, authorization, and policy decisions
  - Implement audit event generation for redaction counts and security violations
  - Add structured logging with no raw sensitive data exposure
  - Write integration tests for complete audit trail coverage
  - _Requirements: R3.1, R8.1, R8.2, R8.3_

- [ ] 7.3 Add audit retention and export capabilities
  - Implement configurable retention policies with automatic cleanup (default 30 days)
  - Add JSONL export format with optional S3 export and KMS encryption
  - Create data subject erasure capability by tokenized subject ID
  - Write tests for retention policies, export functionality, and compliance features
  - _Requirements: R15.1, R15.3, R8.4_

- [ ] 8. Error handling and resilience patterns
- [ ] 8.1 Implement comprehensive error handling with go-sdk types
  - Create error mapping functions using go-sdk error types for MCP compliance
  - Add circuit breaker pattern for upstream server failures
  - Implement graceful degradation when audit store or policy engine fails
  - Write unit tests for error scenarios and circuit breaker behavior
  - _Requirements: R9.2, R13.1, R13.2_

- [ ] 8.2 Add timeout and backpressure handling
  - Implement configurable timeouts (connect 2s, upstream call 30s)
  - Add bounded queues for SSE connections (max 1,000 events per connection)
  - Create backpressure handling with client abort cancellation
  - Write integration tests for timeout scenarios and queue overflow handling
  - _Requirements: R6.3, R6.4, R9.3_

- [ ] 8.3 Implement health checks and monitoring
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
- [ ] 11.1 Create Docker images and Helm charts
  - Implement multi-stage Docker builds with security scanning
  - Create Helm charts with configurable values and security defaults
  - Add Kubernetes manifests for RBAC, NetworkPolicies, and PodSecurityPolicies
  - Write deployment tests for Kubernetes environments
  - _Requirements: R5.1, R5.5_

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
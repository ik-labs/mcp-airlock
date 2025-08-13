# Threat Model

This document provides a comprehensive threat model for MCP Airlock, identifying potential security threats, attack vectors, and corresponding mitigations.

## Threat Modeling Methodology

We use the STRIDE methodology to systematically identify threats:
- **S**poofing - Impersonating users or systems
- **T**ampering - Modifying data or code
- **R**epudiation - Denying actions performed
- **I**nformation Disclosure - Exposing sensitive information
- **D**enial of Service - Preventing legitimate access
- **E**levation of Privilege - Gaining unauthorized access

## System Assets

### Primary Assets
1. **MCP Server Access** - Access to internal MCP servers and their capabilities
2. **Sensitive Data** - Code, documents, and other content accessed through MCP
3. **Authentication Tokens** - JWT tokens and session credentials
4. **Configuration Data** - Policies, secrets, and system configuration
5. **Audit Logs** - Security and compliance audit trails

### Supporting Assets
1. **Kubernetes Infrastructure** - Pods, services, and cluster resources
2. **Database Systems** - PostgreSQL/SQLite for audit storage
3. **Network Infrastructure** - Load balancers, ingress controllers
4. **External Dependencies** - OIDC providers, S3 storage

## Threat Analysis

### T1: Authentication Threats

#### T1.1: Token Spoofing (Spoofing)
**Description:** Attacker creates or modifies JWT tokens to impersonate legitimate users.

**Attack Vectors:**
- Weak signing algorithms (HS256 with shared secrets)
- Key confusion attacks (RS256 to HS256)
- Token replay attacks
- Stolen signing keys

**Impact:** High - Complete authentication bypass, unauthorized access to all resources

**Mitigations:**
- Enforce RS256+ asymmetric signing algorithms
- Validate token issuer and audience claims
- Implement token expiration and refresh
- Secure JWKS endpoint and key rotation
- Rate limiting on authentication attempts

**Detection:**
```yaml
# Prometheus alert for suspicious authentication patterns
- alert: SuspiciousAuthenticationPattern
  expr: rate(airlock_auth_failures_total[5m]) > 0.1
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "High authentication failure rate detected"
```

#### T1.2: JWKS Poisoning (Tampering)
**Description:** Attacker compromises JWKS endpoint to inject malicious signing keys.

**Attack Vectors:**
- DNS hijacking of OIDC provider
- BGP hijacking to redirect JWKS requests
- Compromised OIDC provider infrastructure
- Man-in-the-middle attacks on JWKS fetch

**Impact:** High - Complete authentication bypass with valid-looking tokens

**Mitigations:**
- TLS certificate pinning for JWKS endpoints
- JWKS caching with reasonable TTL (5 minutes)
- Multiple OIDC provider support for redundancy
- JWKS signature validation if supported by provider
- Network security controls and monitoring

**Detection:**
```go
// Monitor JWKS changes
func (a *Authenticator) monitorJWKSChanges(newKeys []jose.JSONWebKey) {
    for _, key := range newKeys {
        if !a.isKnownKey(key.KeyID) {
            a.alertUnknownKey(key.KeyID)
        }
    }
}
```

#### T1.3: Clock Skew Attacks (Spoofing)
**Description:** Attacker exploits clock synchronization issues to use expired tokens.

**Attack Vectors:**
- System clock manipulation
- Network time protocol (NTP) attacks
- Timezone confusion attacks
- Leap second exploitation

**Impact:** Medium - Limited window for using expired tokens

**Mitigations:**
- Reasonable clock skew tolerance (±2 minutes)
- NTP synchronization monitoring
- Token lifetime limits (short-lived tokens preferred)
- Regular time synchronization checks

### T2: Authorization Threats

#### T2.1: Policy Bypass (Elevation of Privilege)
**Description:** Attacker circumvents authorization policies to access restricted resources.

**Attack Vectors:**
- Policy logic errors or edge cases
- Race conditions in policy evaluation
- Input validation bypass
- Policy cache poisoning
- OPA query injection

**Impact:** High - Unauthorized access to sensitive resources and tools

**Mitigations:**
- Comprehensive policy testing with edge cases
- Policy syntax validation and compilation checks
- Input sanitization for policy evaluation
- Policy decision caching with proper isolation
- Regular policy reviews and audits

**Testing:**
```go
// Policy bypass test cases
func TestPolicyBypass(t *testing.T) {
    testCases := []struct {
        name     string
        input    PolicyInput
        expected bool
    }{
        {
            name: "path_traversal_attempt",
            input: PolicyInput{
                Resource: "mcp://repo/../../../etc/passwd",
                Tool:     "read_file",
                Groups:   []string{"mcp.users"},
            },
            expected: false, // Should be denied
        },
        {
            name: "unicode_normalization_bypass",
            input: PolicyInput{
                Resource: "mcp://repo/sensitive\u202e.txt",
                Tool:     "read_file",
                Groups:   []string{"mcp.users"},
            },
            expected: false, // Should be denied
        },
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            decision, err := policyEngine.Evaluate(context.Background(), &tc.input)
            require.NoError(t, err)
            assert.Equal(t, tc.expected, decision.Allow)
        })
    }
}
```

#### T2.2: Tenant Isolation Bypass (Information Disclosure)
**Description:** Attacker accesses resources belonging to other tenants.

**Attack Vectors:**
- Tenant ID manipulation in requests
- Policy logic errors in tenant isolation
- Shared cache pollution
- Race conditions in tenant context

**Impact:** High - Cross-tenant data access, privacy violations

**Mitigations:**
- Strong tenant ID validation from JWT claims
- Tenant-scoped resource paths and policies
- Isolated caches per tenant
- Comprehensive tenant isolation testing

**Validation:**
```go
func (rm *RootMapper) validateTenantAccess(virtualURI, tenant string) error {
    // Extract tenant from URI path
    uriTenant := extractTenantFromURI(virtualURI)
    
    // Ensure tenant matches JWT claim
    if uriTenant != tenant {
        return ErrTenantMismatch
    }
    
    // Validate tenant format (prevent injection)
    if !isValidTenantID(tenant) {
        return ErrInvalidTenant
    }
    
    return nil
}
```

### T3: Data Protection Threats

#### T3.1: Data Exfiltration (Information Disclosure)
**Description:** Attacker extracts sensitive data through legitimate or illegitimate channels.

**Attack Vectors:**
- Large bulk data requests
- Automated scraping through MCP tools
- Bypassing DLP redaction patterns
- Exploiting tool capabilities for data extraction
- Side-channel attacks through error messages

**Impact:** High - Loss of sensitive intellectual property, compliance violations

**Mitigations:**
- Rate limiting on data access requests
- DLP redaction with comprehensive patterns
- Request size limits and monitoring
- Tool capability restrictions
- Audit logging of all data access

**Monitoring:**
```yaml
# Alert on large data transfers
- alert: LargeDataTransfer
  expr: increase(airlock_bytes_transferred_total[5m]) > 100000000  # 100MB
  for: 1m
  labels:
    severity: warning
  annotations:
    summary: "Large data transfer detected"
    description: "{{ $value }} bytes transferred in 5 minutes"
```

#### T3.2: DLP Bypass (Information Disclosure)
**Description:** Attacker circumvents data loss prevention controls to access sensitive data.

**Attack Vectors:**
- Pattern evasion techniques (encoding, obfuscation)
- Structured data extraction bypassing regex patterns
- Binary data exfiltration
- Steganography in allowed content types
- Time-based data extraction

**Impact:** Medium - Exposure of sensitive data patterns

**Mitigations:**
- Comprehensive redaction patterns with regular updates
- Structured data parsing and filtering
- Binary content inspection
- Pattern effectiveness monitoring and testing
- Multiple redaction layers (request and response)

**Pattern Testing:**
```go
func TestRedactionPatterns(t *testing.T) {
    testData := []struct {
        name     string
        input    string
        expected string
    }{
        {
            name:     "email_basic",
            input:    "Contact john.doe@example.com for details",
            expected: "Contact [redacted-email] for details",
        },
        {
            name:     "email_obfuscated",
            input:    "Email: john[dot]doe[at]example[dot]com",
            expected: "Email: [redacted-email]",
        },
        {
            name:     "aws_key_embedded",
            input:    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            expected: "AWS_ACCESS_KEY_ID=[redacted-aws-key]",
        },
    }
    
    for _, td := range testData {
        t.Run(td.name, func(t *testing.T) {
            result, err := redactor.RedactContent(context.Background(), []byte(td.input))
            require.NoError(t, err)
            assert.Equal(t, td.expected, string(result.Data))
        })
    }
}
```

### T4: Infrastructure Threats

#### T4.1: Container Escape (Elevation of Privilege)
**Description:** Attacker escapes container boundaries to access host system.

**Attack Vectors:**
- Kernel vulnerabilities
- Container runtime vulnerabilities
- Privileged container exploitation
- Volume mount abuse
- Capability abuse

**Impact:** Critical - Full host system compromise

**Mitigations:**
- Non-root container execution
- Read-only root filesystem
- Minimal capabilities (drop ALL)
- Security contexts and Pod Security Standards
- Regular security scanning and updates

**Security Configuration:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65534
  runAsGroup: 65534
  fsGroup: 65534
  seccompProfile:
    type: RuntimeDefault
  capabilities:
    drop:
    - ALL
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
```

#### T4.2: Network Lateral Movement (Elevation of Privilege)
**Description:** Attacker moves laterally through network to access other systems.

**Attack Vectors:**
- Kubernetes service discovery abuse
- Network policy bypass
- DNS poisoning within cluster
- Service mesh exploitation
- Inter-pod communication abuse

**Impact:** High - Access to other cluster resources and services

**Mitigations:**
- Kubernetes Network Policies with default deny
- Service mesh with mTLS (if applicable)
- DNS security controls
- Network segmentation
- Regular network security audits

**Network Policy Example:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: airlock-network-policy
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: airlock
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to: []  # Specific egress rules only
    ports:
    - protocol: TCP
      port: 443  # HTTPS for OIDC
    - protocol: TCP
      port: 5432  # PostgreSQL
```

### T5: Denial of Service Threats

#### T5.1: Resource Exhaustion (Denial of Service)
**Description:** Attacker consumes system resources to prevent legitimate access.

**Attack Vectors:**
- CPU exhaustion through complex policy evaluation
- Memory exhaustion through large requests
- Disk space exhaustion through audit logs
- Connection exhaustion through connection flooding
- Goroutine exhaustion through concurrent requests

**Impact:** High - Service unavailability

**Mitigations:**
- Resource limits and requests in Kubernetes
- Request size limits and timeouts
- Connection limits and rate limiting
- Audit log rotation and retention policies
- Circuit breakers and graceful degradation

**Resource Limits:**
```yaml
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 1000m
    memory: 1Gi
```

#### T5.2: Algorithmic Complexity Attacks (Denial of Service)
**Description:** Attacker exploits algorithmic complexity to cause performance degradation.

**Attack Vectors:**
- Regex ReDoS (Regular Expression Denial of Service)
- JSON parsing complexity attacks
- Policy evaluation complexity attacks
- Hash collision attacks
- Compression bomb attacks

**Impact:** Medium - Performance degradation, potential service disruption

**Mitigations:**
- Regex pattern validation and testing
- JSON parsing limits and timeouts
- Policy complexity analysis
- Secure hash functions
- Content decompression limits

**ReDoS Prevention:**
```go
// Validate regex patterns for ReDoS vulnerabilities
func validateRegexPattern(pattern string) error {
    // Compile with timeout to detect ReDoS
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()
    
    done := make(chan error, 1)
    go func() {
        _, err := regexp.Compile(pattern)
        done <- err
    }()
    
    select {
    case err := <-done:
        return err
    case <-ctx.Done():
        return ErrRegexTimeout
    }
}
```

### T6: Supply Chain Threats

#### T6.1: Dependency Vulnerabilities (Various)
**Description:** Vulnerabilities in third-party dependencies compromise system security.

**Attack Vectors:**
- Known CVEs in dependencies
- Malicious packages in dependency chain
- Typosquatting attacks
- Dependency confusion attacks
- Compromised package repositories

**Impact:** Variable - Depends on vulnerability type and location

**Mitigations:**
- Regular dependency scanning (govulncheck, Trivy)
- Dependency pinning and verification
- Minimal dependency usage
- Security-focused dependency selection
- Automated security updates

**Scanning Integration:**
```yaml
# GitHub Actions security scanning
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: 'fs'
    scan-ref: '.'
    format: 'sarif'
    output: 'trivy-results.sarif'

- name: Upload Trivy scan results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: 'trivy-results.sarif'
```

## Risk Assessment Matrix

| Threat ID | Likelihood | Impact | Risk Level | Priority |
|-----------|------------|--------|------------|----------|
| T1.1 | Medium | High | High | P1 |
| T1.2 | Low | High | Medium | P2 |
| T1.3 | Low | Medium | Low | P3 |
| T2.1 | Medium | High | High | P1 |
| T2.2 | Low | High | Medium | P2 |
| T3.1 | High | High | Critical | P0 |
| T3.2 | Medium | Medium | Medium | P2 |
| T4.1 | Low | Critical | High | P1 |
| T4.2 | Medium | High | High | P1 |
| T5.1 | High | High | Critical | P0 |
| T5.2 | Medium | Medium | Medium | P2 |
| T6.1 | High | Variable | High | P1 |

## Threat Monitoring and Detection

### Security Metrics Dashboard

```yaml
# Key security metrics to monitor
security_metrics:
  authentication:
    - airlock_auth_attempts_total
    - airlock_auth_failures_total
    - airlock_auth_success_rate
    - airlock_token_validation_duration
  
  authorization:
    - airlock_policy_decisions_total{decision="deny"}
    - airlock_policy_evaluation_duration
    - airlock_policy_cache_hit_rate
  
  data_protection:
    - airlock_redaction_events_total
    - airlock_bytes_transferred_total
    - airlock_large_request_count
  
  infrastructure:
    - airlock_container_restarts_total
    - airlock_memory_usage_percent
    - airlock_cpu_usage_percent
    - airlock_network_connections_active
```

### Automated Threat Detection

```go
// Anomaly detection for authentication patterns
type AuthAnomalyDetector struct {
    baseline    *AuthBaseline
    threshold   float64
    alerter     Alerter
}

func (d *AuthAnomalyDetector) DetectAnomalies(ctx context.Context, metrics *AuthMetrics) {
    // Detect unusual failure rates
    if metrics.FailureRate > d.baseline.FailureRate*d.threshold {
        d.alerter.Alert(ctx, &Alert{
            Type:        "auth_anomaly",
            Severity:    "high",
            Description: fmt.Sprintf("Authentication failure rate %.2f%% exceeds baseline %.2f%%", 
                        metrics.FailureRate*100, d.baseline.FailureRate*100),
            Metrics:     metrics,
        })
    }
    
    // Detect unusual geographic patterns
    if d.detectGeographicAnomalies(metrics.GeographicDistribution) {
        d.alerter.Alert(ctx, &Alert{
            Type:        "geographic_anomaly",
            Severity:    "medium",
            Description: "Unusual geographic authentication pattern detected",
        })
    }
}
```

## Incident Response Procedures

### Security Incident Classification

**P0 - Critical Security Incident**
- Active security breach
- Data exfiltration in progress
- Complete authentication bypass
- Container escape or privilege escalation

**Response Time:** Immediate (< 15 minutes)

**P1 - High Security Incident**
- Suspected security breach
- Unusual access patterns
- Policy bypass attempts
- Infrastructure compromise indicators

**Response Time:** < 1 hour

**P2 - Medium Security Incident**
- Authentication anomalies
- DLP pattern bypasses
- Performance-based attacks
- Configuration security issues

**Response Time:** < 4 hours

### Automated Response Actions

```go
// Automated incident response
type IncidentResponder struct {
    alertManager AlertManager
    k8sClient    kubernetes.Interface
    auditLogger  AuditLogger
}

func (ir *IncidentResponder) HandleSecurityIncident(ctx context.Context, incident *SecurityIncident) error {
    switch incident.Severity {
    case "critical":
        // Immediate isolation
        if err := ir.isolateAffectedPods(ctx, incident.AffectedPods); err != nil {
            return err
        }
        
        // Scale up healthy replicas
        if err := ir.scaleHealthyReplicas(ctx); err != nil {
            return err
        }
        
        // Preserve evidence
        if err := ir.preserveEvidence(ctx, incident); err != nil {
            return err
        }
        
    case "high":
        // Enhanced monitoring
        if err := ir.enableEnhancedMonitoring(ctx); err != nil {
            return err
        }
        
        // Rate limiting
        if err := ir.enableStrictRateLimiting(ctx); err != nil {
            return err
        }
    }
    
    // Always log incident
    return ir.auditLogger.LogSecurityIncident(ctx, incident)
}
```

## Security Testing Strategy

### Threat-Based Testing

Each identified threat should have corresponding test cases:

```go
// T1.1: Token Spoofing Tests
func TestTokenSpoofingPrevention(t *testing.T) {
    tests := []struct {
        name        string
        token       string
        expectError bool
    }{
        {
            name:        "unsigned_token",
            token:       createUnsignedToken(),
            expectError: true,
        },
        {
            name:        "wrong_algorithm",
            token:       createHS256Token(),
            expectError: true,
        },
        {
            name:        "expired_token",
            token:       createExpiredToken(),
            expectError: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            _, err := authenticator.ValidateToken(context.Background(), tt.token)
            if tt.expectError {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

### Penetration Testing Scenarios

1. **Authentication Bypass Testing**
   - Token manipulation attempts
   - JWKS poisoning simulation
   - Clock skew exploitation

2. **Authorization Bypass Testing**
   - Policy logic exploitation
   - Path traversal attempts
   - Tenant isolation bypass

3. **Data Exfiltration Testing**
   - DLP pattern evasion
   - Large data transfer attempts
   - Side-channel information leakage

4. **Infrastructure Testing**
   - Container escape attempts
   - Network lateral movement
   - Resource exhaustion attacks

## Continuous Threat Modeling

### Regular Review Process

1. **Monthly Threat Review**
   - New threat intelligence integration
   - Attack pattern analysis
   - Mitigation effectiveness review

2. **Quarterly Deep Dive**
   - Comprehensive threat model update
   - Risk assessment recalculation
   - Security control validation

3. **Annual Security Assessment**
   - External penetration testing
   - Security architecture review
   - Compliance gap analysis

### Threat Intelligence Integration

```go
// Threat intelligence feed integration
type ThreatIntelligence struct {
    feeds       []ThreatFeed
    indicators  *IOCDatabase
    alerter     Alerter
}

func (ti *ThreatIntelligence) ProcessThreatFeed(ctx context.Context, feed ThreatFeed) error {
    indicators, err := feed.GetLatestIndicators(ctx)
    if err != nil {
        return err
    }
    
    for _, indicator := range indicators {
        if ti.isRelevantToAirlock(indicator) {
            if err := ti.indicators.Store(ctx, indicator); err != nil {
                return err
            }
            
            // Check if indicator matches current traffic
            if matches := ti.checkCurrentTraffic(indicator); len(matches) > 0 {
                ti.alerter.Alert(ctx, &ThreatAlert{
                    Indicator: indicator,
                    Matches:   matches,
                })
            }
        }
    }
    
    return nil
}
```

This comprehensive threat model provides a systematic approach to identifying, assessing, and mitigating security threats to MCP Airlock. Regular updates and continuous monitoring ensure that the threat model remains current and effective against evolving attack vectors.
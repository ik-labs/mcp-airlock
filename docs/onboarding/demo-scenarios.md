# Demo Scenarios

This document provides complete end-to-end demo scenarios that showcase MCP Airlock's capabilities, from initial setup to advanced usage patterns.

## Scenario 1: Developer Documentation Access

**Duration**: 10 minutes  
**Audience**: Developers, Technical Writers  
**Prerequisites**: Basic MCP Airlock deployment

### Overview
Demonstrate how developers can securely access and search through company documentation using MCP Airlock's authentication, authorization, and audit capabilities.

### Setup

1. **Prepare Demo Environment**
   ```bash
   # Set up demo namespace
   kubectl create namespace airlock-demo
   
   # Deploy sample documentation server
   kubectl apply -f - << EOF
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: docs-server
     namespace: airlock-demo
   spec:
     replicas: 1
     selector:
       matchLabels:
         app: docs-server
     template:
       metadata:
         labels:
           app: docs-server
       spec:
         containers:
         - name: docs-server
           image: nginx:alpine
           ports:
           - containerPort: 80
           volumeMounts:
           - name: docs-content
             mountPath: /usr/share/nginx/html
         volumes:
         - name: docs-content
           configMap:
             name: demo-docs
   ---
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: demo-docs
     namespace: airlock-demo
   data:
     index.html: |
       <h1>Company Documentation</h1>
       <ul>
         <li><a href="api.html">API Documentation</a></li>
         <li><a href="security.html">Security Guidelines</a></li>
         <li><a href="deployment.html">Deployment Guide</a></li>
       </ul>
     api.html: |
       <h1>API Documentation</h1>
       <h2>Authentication</h2>
       <p>All API requests must include a valid JWT token in the Authorization header.</p>
       <h2>Endpoints</h2>
       <ul>
         <li>GET /api/users - List users</li>
         <li>POST /api/users - Create user</li>
         <li>GET /api/health - Health check</li>
       </ul>
     security.html: |
       <h1>Security Guidelines</h1>
       <h2>Authentication</h2>
       <p>Use strong passwords and enable MFA.</p>
       <h2>Data Protection</h2>
       <p>All sensitive data must be encrypted at rest and in transit.</p>
     deployment.html: |
       <h1>Deployment Guide</h1>
       <h2>Prerequisites</h2>
       <p>Kubernetes 1.24+ with Helm 3.8+</p>
       <h2>Installation</h2>
       <pre>helm install myapp ./chart</pre>
   EOF
   ```

2. **Configure MCP Airlock for Documentation Access**
   ```yaml
   # demo-values.yaml
   upstreams:
     - name: "docs-server"
       type: "http"
       url: "http://docs-server.airlock-demo.svc.cluster.local"
       timeout: "30s"
   
   roots:
     - name: "documentation"
       type: "fs"
       virtual: "mcp://docs/"
       real: "/mnt/docs"
       readOnly: true
   
   policy:
     rules: |
       package airlock.authz
       import rego.v1
       
       default allow := false
       
       allow if {
           input.groups[_] == "developers"
           input.tool in ["search_docs", "read_file", "list_directory"]
           startswith(input.resource, "mcp://docs/")
       }
   ```

### Demo Script

#### Step 1: Authentication Flow (2 minutes)

**Narrator**: "Let's start by showing how a developer authenticates with MCP Airlock."

```bash
# Show unauthenticated request fails
echo "=== Attempting unauthenticated request ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "demo-1",
    "method": "tools/list"
  }'

# Expected: 401 Unauthorized with WWW-Authenticate header
```

**Narrator**: "As expected, the request is rejected. Now let's authenticate using our company's identity provider."

```bash
# Get authentication token (simulated)
echo "=== Getting authentication token ==="
export DEMO_TOKEN=$(kubelogin get-token \
  --oidc-issuer-url=https://demo-idp.company.com \
  --oidc-client-id=airlock-demo)

echo "Token obtained: ${DEMO_TOKEN:0:20}..."
```

#### Step 2: Tool Discovery (1 minute)

**Narrator**: "Now let's discover what tools are available to our authenticated developer."

```bash
echo "=== Discovering available tools ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DEMO_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "demo-2",
    "method": "tools/list"
  }' | jq .

# Expected: List of tools including search_docs, read_file, list_directory
```

**Narrator**: "Great! We can see the documentation tools are available. Notice how the policy engine has already determined what tools this developer can access based on their group membership."

#### Step 3: Documentation Search (2 minutes)

**Narrator**: "Let's search for information about API authentication."

```bash
echo "=== Searching documentation ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DEMO_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "demo-3",
    "method": "tools/call",
    "params": {
      "name": "search_docs",
      "arguments": {
        "query": "authentication",
        "max_results": 5
      }
    }
  }' | jq .

# Expected: Search results showing relevant documentation
```

**Narrator**: "The search found relevant documentation about authentication. Let's read the API documentation file."

#### Step 4: File Access (2 minutes)

```bash
echo "=== Reading API documentation ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DEMO_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "demo-4",
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {
        "path": "mcp://docs/api.html"
      }
    }
  }' | jq .

# Expected: File content with API documentation
```

**Narrator**: "Perfect! The developer can access the API documentation. Notice how the virtual path `mcp://docs/` is mapped to the actual documentation location, providing abstraction and security."

#### Step 5: Security Demonstration (2 minutes)

**Narrator**: "Now let's demonstrate the security controls. What happens if we try to access a restricted path?"

```bash
echo "=== Attempting path traversal attack ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $DEMO_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "demo-5",
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {
        "path": "mcp://docs/../../../etc/passwd"
      }
    }
  }' | jq .

# Expected: Security violation error
```

**Narrator**: "Excellent! The path traversal attempt was blocked by Airlock's security controls. The system detected the malicious path and prevented access."

#### Step 6: Audit Trail (1 minute)

**Narrator**: "Finally, let's check the audit trail to see how all these activities were logged."

```bash
echo "=== Checking audit trail ==="
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock --tail=10 | grep -E "(demo-[1-5]|correlation)"

# Expected: Audit entries for all requests with correlation IDs
```

**Narrator**: "As you can see, every interaction was logged with correlation IDs, making it easy to track user activities for compliance and security purposes."

### Key Takeaways

- **Zero Trust**: Every request is authenticated and authorized
- **Policy Enforcement**: Fine-grained access control based on user groups
- **Security Controls**: Path traversal and other attacks are automatically blocked
- **Audit Trail**: Complete logging for compliance and security monitoring
- **Developer Experience**: Simple, familiar API access patterns

---

## Scenario 2: CI/CD Pipeline Integration

**Duration**: 15 minutes  
**Audience**: DevOps Engineers, Platform Teams  
**Prerequisites**: Kubernetes cluster with CI/CD system

### Overview
Demonstrate how CI/CD pipelines can securely integrate with MCP Airlock to perform automated code analysis, generate reports, and manage artifacts.

### Setup

1. **Deploy Sample MCP Servers**
   ```bash
   # Code analysis server
   kubectl apply -f examples/mcp-servers/Dockerfile.analytics
   
   # Artifact management server
   kubectl apply -f - << EOF
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: artifact-server
     namespace: airlock-demo
   spec:
     replicas: 1
     selector:
       matchLabels:
         app: artifact-server
     template:
       metadata:
         labels:
           app: artifact-server
       spec:
         containers:
         - name: artifact-server
           image: minio/minio:latest
           command: ["minio", "server", "/data"]
           ports:
           - containerPort: 9000
           env:
           - name: MINIO_ROOT_USER
             value: "admin"
           - name: MINIO_ROOT_PASSWORD
             value: "password123"
   EOF
   ```

2. **Configure CI/CD Service Account**
   ```yaml
   # ci-service-account.yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: ci-pipeline
     namespace: airlock-demo
   ---
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   metadata:
     name: ci-pipeline
     namespace: airlock-demo
   rules:
   - apiGroups: [""]
     resources: ["secrets", "configmaps"]
     verbs: ["get", "list"]
   ---
   apiVersion: rbac.authorization.k8s.io/v1
   kind: RoleBinding
   metadata:
     name: ci-pipeline
     namespace: airlock-demo
   subjects:
   - kind: ServiceAccount
     name: ci-pipeline
     namespace: airlock-demo
   roleRef:
     kind: Role
     name: ci-pipeline
     apiGroup: rbac.authorization.k8s.io
   ```

### Demo Script

#### Step 1: CI Pipeline Authentication (3 minutes)

**Narrator**: "Let's simulate a CI/CD pipeline that needs to perform automated security analysis and artifact management."

```bash
# Simulate CI pipeline getting service account token
echo "=== CI Pipeline Authentication ==="
CI_TOKEN=$(kubectl create token ci-pipeline -n airlock-demo --duration=1h)
echo "CI service account token obtained"

# Test authentication
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CI_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "ci-1",
    "method": "tools/list"
  }' | jq '.result.tools[] | select(.name | contains("analyze"))'
```

**Narrator**: "The CI pipeline has successfully authenticated and can see the analysis tools available to it."

#### Step 2: Automated Code Analysis (4 minutes)

**Narrator**: "Now let's run automated security analysis on our codebase."

```bash
echo "=== Running Security Analysis ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CI_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "ci-2",
    "method": "tools/call",
    "params": {
      "name": "analyze_code",
      "arguments": {
        "repository": "mcp://repo/",
        "branch": "main",
        "commit": "abc123def456",
        "analysis_types": ["security", "quality", "performance"]
      }
    }
  }' | jq .

# Expected: Analysis results with security findings
```

**Narrator**: "The analysis found several security issues. Let's generate a detailed report."

```bash
echo "=== Generating Security Report ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CI_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "ci-3",
    "method": "tools/call",
    "params": {
      "name": "generate_report",
      "arguments": {
        "report_type": "security_analysis",
        "format": "sarif",
        "input_data": "analysis_results_ci-2",
        "output_path": "mcp://artifacts/reports/security-report.sarif"
      }
    }
  }' | jq .
```

#### Step 3: Artifact Management (3 minutes)

**Narrator**: "Now let's publish the build artifacts and reports to our artifact repository."

```bash
echo "=== Publishing Build Artifacts ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CI_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "ci-4",
    "method": "tools/call",
    "params": {
      "name": "publish_artifacts",
      "arguments": {
        "source_path": "mcp://workspace/build/",
        "destination_path": "mcp://artifacts/releases/v1.2.3/",
        "metadata": {
          "version": "1.2.3",
          "commit": "abc123def456",
          "branch": "main",
          "build_time": "2024-01-15T10:30:00Z"
        }
      }
    }
  }' | jq .
```

**Narrator**: "The artifacts have been published. Let's verify they're accessible."

```bash
echo "=== Verifying Artifact Publication ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CI_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "ci-5",
    "method": "tools/call",
    "params": {
      "name": "list_artifacts",
      "arguments": {
        "path": "mcp://artifacts/releases/v1.2.3/"
      }
    }
  }' | jq .
```

#### Step 4: Policy Enforcement Demo (3 minutes)

**Narrator**: "Let's demonstrate how policies protect against unauthorized actions, even from CI systems."

```bash
echo "=== Attempting Unauthorized Action ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $CI_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "ci-6",
    "method": "tools/call",
    "params": {
      "name": "delete_production_data",
      "arguments": {
        "path": "mcp://production/database/"
      }
    }
  }' | jq .

# Expected: Policy denial
```

**Narrator**: "Perfect! Even though this is a CI system, the policy engine correctly denied access to production data deletion."

#### Step 5: Audit and Compliance (2 minutes)

**Narrator**: "Finally, let's check the audit trail for our CI pipeline activities."

```bash
echo "=== CI Pipeline Audit Trail ==="
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT timestamp, subject, action, decision, reason FROM audit_events WHERE correlation_id LIKE 'ci-%' ORDER BY timestamp DESC LIMIT 10;"
```

**Narrator**: "All CI activities are fully audited, providing complete traceability for compliance requirements."

### Key Takeaways

- **Automated Security**: CI/CD pipelines can perform security analysis automatically
- **Service Account Integration**: Kubernetes service accounts work seamlessly
- **Policy Protection**: Even automated systems are subject to policy controls
- **Artifact Management**: Secure artifact publishing and management
- **Complete Auditability**: All automated activities are logged and traceable

---

## Scenario 3: Multi-Tenant Data Analytics

**Duration**: 12 minutes  
**Audience**: Data Engineers, Analytics Teams  
**Prerequisites**: Multi-tenant environment setup

### Overview
Demonstrate how multiple tenants can securely access their own data analytics tools while maintaining complete isolation and compliance.

### Setup

1. **Configure Multi-Tenant Environment**
   ```yaml
   # multi-tenant-config.yaml
   tenants:
     - name: "acme-corp"
       groups: ["acme.analysts", "acme.users"]
       roots:
         - virtual: "mcp://data/"
           real: "s3://analytics-bucket/acme-corp/"
           readOnly: true
         - virtual: "mcp://reports/"
           real: "s3://reports-bucket/acme-corp/"
           readOnly: false
     
     - name: "beta-inc"
       groups: ["beta.analysts", "beta.users"]
       roots:
         - virtual: "mcp://data/"
           real: "s3://analytics-bucket/beta-inc/"
           readOnly: true
         - virtual: "mcp://reports/"
           real: "s3://reports-bucket/beta-inc/"
           readOnly: false
   
   policy:
     rules: |
       package airlock.authz
       import rego.v1
       
       default allow := false
       
       # Tenant isolation
       allow if {
           input.tenant == "acme-corp"
           input.groups[_] in ["acme.analysts", "acme.users"]
           allowed_resource_for_tenant("acme-corp", input.resource)
       }
       
       allow if {
           input.tenant == "beta-inc"
           input.groups[_] in ["beta.analysts", "beta.users"]
           allowed_resource_for_tenant("beta-inc", input.resource)
       }
       
       allowed_resource_for_tenant(tenant, resource) if {
           startswith(resource, "mcp://data/")
           # Additional tenant-specific validation would go here
       }
   ```

### Demo Script

#### Step 1: Tenant A Analytics (4 minutes)

**Narrator**: "Let's start with Acme Corp's data analyst accessing their analytics environment."

```bash
# Get Acme Corp analyst token
echo "=== Acme Corp Analyst Authentication ==="
ACME_TOKEN=$(generate_demo_token "alice@acme-corp.com" "acme-corp" '["acme.analysts"]')

# Discover available analytics tools
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACME_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "acme-1",
    "method": "tools/list"
  }' | jq '.result.tools[] | select(.name | contains("analytics"))'

# Query Acme Corp's data
echo "=== Querying Acme Corp Data ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACME_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "acme-2",
    "method": "tools/call",
    "params": {
      "name": "query_data",
      "arguments": {
        "dataset": "mcp://data/sales/2024/",
        "query": "SELECT region, SUM(revenue) FROM sales GROUP BY region",
        "format": "json"
      }
    }
  }' | jq .
```

**Narrator**: "Acme Corp's analyst can successfully access their sales data. Notice how the virtual path maps to their specific S3 bucket partition."

#### Step 2: Tenant B Analytics (4 minutes)

**Narrator**: "Now let's see Beta Inc's analyst accessing their completely separate data environment."

```bash
# Get Beta Inc analyst token
echo "=== Beta Inc Analyst Authentication ==="
BETA_TOKEN=$(generate_demo_token "bob@beta-inc.com" "beta-inc" '["beta.analysts"]')

# Query Beta Inc's data
echo "=== Querying Beta Inc Data ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $BETA_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "beta-1",
    "method": "tools/call",
    "params": {
      "name": "query_data",
      "arguments": {
        "dataset": "mcp://data/customer/2024/",
        "query": "SELECT segment, COUNT(*) FROM customers GROUP BY segment",
        "format": "json"
      }
    }
  }' | jq .

# Generate Beta Inc report
echo "=== Generating Beta Inc Report ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $BETA_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "beta-2",
    "method": "tools/call",
    "params": {
      "name": "generate_report",
      "arguments": {
        "report_type": "customer_analysis",
        "data_source": "mcp://data/customer/2024/",
        "output_path": "mcp://reports/customer-analysis-2024.pdf"
      }
    }
  }' | jq .
```

**Narrator**: "Beta Inc's analyst can access their customer data and generate reports, completely isolated from Acme Corp's environment."

#### Step 3: Cross-Tenant Access Prevention (2 minutes)

**Narrator**: "Let's demonstrate the tenant isolation by showing what happens when Acme Corp tries to access Beta Inc's data."

```bash
echo "=== Attempting Cross-Tenant Access ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACME_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "acme-3",
    "method": "tools/call",
    "params": {
      "name": "query_data",
      "arguments": {
        "dataset": "mcp://data/customer/2024/",
        "query": "SELECT * FROM customers LIMIT 10"
      }
    }
  }' | jq .

# Expected: Policy denial due to tenant isolation
```

**Narrator**: "Excellent! The policy engine correctly prevented cross-tenant data access, maintaining strict isolation between Acme Corp and Beta Inc."

#### Step 4: Data Redaction Demo (2 minutes)

**Narrator**: "Let's see how sensitive data is automatically redacted in analytics queries."

```bash
echo "=== Querying Data with PII ==="
curl -X POST https://airlock-demo.company.com/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACME_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": "acme-4",
    "method": "tools/call",
    "params": {
      "name": "query_data",
      "arguments": {
        "dataset": "mcp://data/customers/",
        "query": "SELECT name, email, ssn FROM customers LIMIT 5",
        "include_pii": false
      }
    }
  }' | jq .

# Expected: Results with PII automatically redacted
```

**Narrator**: "Notice how email addresses and SSNs were automatically redacted, ensuring compliance with data protection regulations."

### Key Takeaways

- **Perfect Tenant Isolation**: Each tenant can only access their own data
- **Consistent Interface**: Same tools and APIs across all tenants
- **Automatic PII Protection**: Sensitive data is redacted automatically
- **Policy-Based Security**: Fine-grained access control per tenant
- **Compliance Ready**: Complete audit trail for regulatory requirements

---

## Scenario 4: Security Incident Response

**Duration**: 8 minutes  
**Audience**: Security Teams, SOC Analysts  
**Prerequisites**: Security monitoring setup

### Overview
Demonstrate how MCP Airlock's security controls and audit capabilities support incident response workflows.

### Demo Script

#### Step 1: Suspicious Activity Detection (2 minutes)

**Narrator**: "Let's simulate a security incident where we detect suspicious activity in our audit logs."

```bash
echo "=== Detecting Suspicious Activity ==="
# Simulate multiple failed authentication attempts
for i in {1..5}; do
  curl -X POST https://airlock-demo.company.com/mcp \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer invalid-token-$i" \
    -d '{
      "jsonrpc": "2.0",
      "id": "suspicious-'$i'",
      "method": "tools/list"
    }' > /dev/null 2>&1
done

# Check for authentication failures
kubectl logs -n airlock-system -l app.kubernetes.io/name=airlock --tail=20 | grep -i "auth.*fail"
```

**Narrator**: "We've detected multiple authentication failures from the same source. Let's investigate further."

#### Step 2: Incident Investigation (3 minutes)

**Narrator**: "Now let's use MCP Airlock's audit capabilities to investigate this incident."

```bash
echo "=== Investigating Security Incident ==="
# Query audit database for suspicious activity
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT timestamp, subject, action, decision, reason, metadata 
   FROM audit_events 
   WHERE action = 'token_validate' 
   AND decision = 'deny' 
   AND timestamp > datetime('now', '-1 hour')
   ORDER BY timestamp DESC;"

# Check for correlation patterns
echo "=== Analyzing Attack Patterns ==="
kubectl exec -n airlock-system deployment/airlock -- \
  sqlite3 /var/lib/airlock/audit.db \
  "SELECT COUNT(*) as attempts, 
          json_extract(metadata, '$.source_ip') as source_ip,
          MIN(timestamp) as first_attempt,
          MAX(timestamp) as last_attempt
   FROM audit_events 
   WHERE action = 'token_validate' 
   AND decision = 'deny' 
   AND timestamp > datetime('now', '-1 hour')
   GROUP BY json_extract(metadata, '$.source_ip')
   HAVING attempts > 3;"
```

**Narrator**: "We can see a clear pattern of brute force attacks from specific IP addresses. The audit trail provides complete visibility into the attack."

#### Step 3: Automated Response (2 minutes)

**Narrator**: "Let's demonstrate how we can implement automated response to this security incident."

```bash
echo "=== Implementing Automated Response ==="
# Block suspicious IP addresses
curl -X POST https://airlock-demo.company.com/admin/security/block \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "action": "block_ip",
    "ip_addresses": ["192.168.1.100", "10.0.0.50"],
    "duration": "1h",
    "reason": "Brute force attack detected"
  }'

# Increase rate limiting temporarily
curl -X POST https://airlock-demo.company.com/admin/config/update \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "rate_limiting": {
      "per_ip": "10/min",
      "per_token": "50/min",
      "temporary": true,
      "duration": "2h"
    }
  }'
```

**Narrator**: "We've automatically blocked the attacking IP addresses and temporarily increased rate limiting to prevent further attacks."

#### Step 4: Compliance Reporting (1 minute)

**Narrator**: "Finally, let's generate a compliance report for this security incident."

```bash
echo "=== Generating Incident Report ==="
curl -X POST https://airlock-demo.company.com/admin/reports/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{
    "report_type": "security_incident",
    "incident_id": "INC-2024-001",
    "time_range": {
      "start": "2024-01-15T09:00:00Z",
      "end": "2024-01-15T10:00:00Z"
    },
    "include_sections": [
      "timeline",
      "affected_systems",
      "response_actions",
      "audit_trail"
    ],
    "format": "pdf"
  }' | jq .
```

**Narrator**: "The incident report has been generated with complete audit trail information, ready for compliance and forensic analysis."

### Key Takeaways

- **Complete Visibility**: Every security event is logged and auditable
- **Pattern Detection**: Audit data enables attack pattern analysis
- **Automated Response**: Security controls can be dynamically adjusted
- **Compliance Ready**: Detailed incident reports for regulatory requirements
- **Forensic Capability**: Hash-chained audit logs provide tamper-evident records

---

## Demo Environment Setup

### Prerequisites

```bash
# Install required tools
kubectl version --client
helm version
curl --version
jq --version

# Verify cluster access
kubectl cluster-info
```

### Quick Demo Environment

```bash
#!/bin/bash
# setup-demo.sh

set -e

NAMESPACE="airlock-demo"
DOMAIN="airlock-demo.company.com"

echo "Setting up MCP Airlock demo environment..."

# Create namespace
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

# Deploy demo MCP servers
kubectl apply -f examples/mcp-servers/ -n $NAMESPACE

# Install Airlock with demo configuration
helm install airlock-demo ./helm/airlock \
  -n $NAMESPACE \
  -f demo-values.yaml \
  --set global.domain=$DOMAIN \
  --wait

# Wait for deployment
kubectl wait --for=condition=available deployment/airlock -n $NAMESPACE --timeout=300s

echo "Demo environment ready at https://$DOMAIN"
echo "Use the following tokens for demos:"
echo "Developer: $(generate_demo_token 'dev@company.com' 'demo-tenant' '[\"developers\"]')"
echo "Analyst: $(generate_demo_token 'analyst@company.com' 'demo-tenant' '[\"analysts\"]')"
echo "Admin: $(generate_demo_token 'admin@company.com' 'demo-tenant' '[\"admins\"]')"
```

### Demo Token Generation

```bash
#!/bin/bash
# generate_demo_token.sh

generate_demo_token() {
  local subject=$1
  local tenant=$2
  local groups=$3
  
  # Create JWT payload
  local payload=$(cat << EOF | base64 -w 0
{
  "sub": "$subject",
  "tid": "$tenant",
  "groups": $groups,
  "aud": "mcp-airlock",
  "iss": "https://demo-idp.company.com",
  "exp": $(($(date +%s) + 3600)),
  "iat": $(date +%s)
}
EOF
)
  
  # Create demo JWT (not cryptographically secure - for demo only)
  echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.$payload.demo-signature"
}
```

### Cleanup

```bash
#!/bin/bash
# cleanup-demo.sh

NAMESPACE="airlock-demo"

echo "Cleaning up demo environment..."

# Uninstall Helm release
helm uninstall airlock-demo -n $NAMESPACE

# Delete namespace
kubectl delete namespace $NAMESPACE

echo "Demo environment cleaned up"
```

## Presentation Tips

### For Technical Audiences

1. **Show the Code**: Display actual curl commands and responses
2. **Explain the Why**: Connect each demo step to real-world use cases
3. **Interactive Elements**: Let audience suggest test scenarios
4. **Performance Metrics**: Show response times and resource usage

### For Business Audiences

1. **Focus on Outcomes**: Emphasize security, compliance, and productivity benefits
2. **Use Scenarios**: Relate to their specific industry or use cases
3. **Quantify Benefits**: Show time savings, risk reduction, cost benefits
4. **Visual Dashboards**: Use Grafana dashboards to show monitoring

### For Security Audiences

1. **Threat Modeling**: Explain how each control addresses specific threats
2. **Compliance Mapping**: Show how features map to regulatory requirements
3. **Incident Response**: Demonstrate forensic and response capabilities
4. **Attack Scenarios**: Show how various attacks are prevented

### Common Questions and Answers

**Q: How does this compare to VPN access?**
A: MCP Airlock provides zero-trust, application-level security with complete audit trails, unlike network-level VPN access.

**Q: What about performance impact?**
A: Typical overhead is <10ms per request, with sub-60ms p95 response times for most operations.

**Q: How do we handle token rotation?**
A: Automatic OIDC refresh tokens handle rotation transparently, with configurable refresh intervals.

**Q: Can we integrate with our existing IdP?**
A: Yes, any OIDC-compatible identity provider works, including Okta, Azure AD, Auth0, and others.

**Q: What about high availability?**
A: Horizontal pod autoscaling, multiple replicas, and health checks ensure high availability.

---

These demo scenarios provide comprehensive coverage of MCP Airlock's capabilities while being engaging and informative for different audiences. Each scenario can be customized based on specific organizational needs and use cases.
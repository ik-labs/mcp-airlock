#!/bin/bash

# MCP Airlock Hackathon Demo Script
# This script demonstrates all security features of Airlock

set -e

echo "🚀 Starting MCP Airlock Hackathon Demo"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_step() {
    echo -e "${BLUE}📋 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check prerequisites
print_step "Checking prerequisites..."

if ! command -v go &> /dev/null; then
    print_error "Go is not installed. Please install Go 1.22 or later."
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3."
    exit 1
fi

print_success "Prerequisites check passed"

# Install Python dependencies
print_step "Installing Python dependencies..."
if ! python3 -c "import jwt" &> /dev/null; then
    print_step "PyJWT not found, attempting to install..."
    
    # Try different installation methods
    if pip3 install -r requirements.txt &> /dev/null; then
        print_success "Dependencies installed from requirements.txt"
    elif pip3 install --user -r requirements.txt &> /dev/null; then
        print_success "Dependencies installed from requirements.txt (user mode)"
    elif pip3 install --break-system-packages -r requirements.txt &> /dev/null; then
        print_success "Dependencies installed from requirements.txt (system packages)"
    elif pip3 install PyJWT &> /dev/null; then
        print_success "PyJWT installed directly"
    elif pip3 install --user PyJWT &> /dev/null; then
        print_success "PyJWT installed directly (user mode)"
    elif pip3 install --break-system-packages PyJWT &> /dev/null; then
        print_success "PyJWT installed directly (system packages)"
    else
        print_error "Failed to install PyJWT. Please install manually:"
        echo "  pip3 install -r requirements.txt"
        echo "  or: pip3 install PyJWT"
        echo "  or: pip3 install --user PyJWT"
        echo "  or: pip3 install --break-system-packages PyJWT"
        exit 1
    fi
else
    print_success "PyJWT already installed"
fi

# Build Airlock
print_step "Building MCP Airlock..."
make build
print_success "Airlock built successfully"

# Generate demo tokens
print_step "Generating demo JWT tokens..."
python3 scripts/generate-demo-tokens.py
print_success "Demo tokens generated"

# Create temp directories
print_step "Setting up demo environment..."
mkdir -p /tmp/airlock-demo
mkdir -p scripts
print_success "Demo environment ready"

# Start MCP servers in background
print_step "Starting MCP servers..."

# Kill any existing processes
pkill -f "docs-server.py" 2>/dev/null || true
pkill -f "analytics-server.py" 2>/dev/null || true
sleep 2

# Start servers with proper environment variables for macOS
DOCS_ROOT="./examples/sample-docs" MCP_SOCKET_PATH="/tmp/docs.sock" python3 examples/mcp-servers/docs-server.py &
DOCS_PID=$!
ANALYTICS_DB_PATH="/tmp/analytics.db" MCP_SOCKET_PATH="/tmp/analytics.sock" python3 examples/mcp-servers/analytics-server.py &
ANALYTICS_PID=$!

# Wait for servers to start
sleep 3

# Check if servers are running
if ! kill -0 $DOCS_PID 2>/dev/null; then
    print_error "Docs server failed to start"
    exit 1
fi

if ! kill -0 $ANALYTICS_PID 2>/dev/null; then
    print_error "Analytics server failed to start"
    exit 1
fi

print_success "MCP servers started (PIDs: $DOCS_PID, $ANALYTICS_PID)"

# Create config with current directory paths (portable for any user)
print_step "Creating demo configuration with current directory paths..."
CURRENT_DIR=$(pwd)
cat > /tmp/config-demo-resolved.yaml << EOF
# MCP Airlock Hackathon Demo Configuration (Auto-generated)
# Showcases all security features with current directory paths

server:
  addr: ":8080"
  public_base_url: "http://localhost:8080"
  timeouts:
    read: "30s"
    write: "30s"
    idle: "120s"

# JWT Authentication (demo mode)
auth:
  jwt_secret: "demo-secret-key-for-hackathon-only"  # DO NOT use in production
  audience: "mcp-airlock"
  issuer: "airlock-demo"
  clock_skew: "5m"
  required_groups: ["users"]  # Basic group requirement for demo

# OPA Policy Engine with hot-reload
policy:
  rego_file: "${CURRENT_DIR}/configs/policy.rego"
  cache_ttl: "10s"  # Fast reload for demo
  reload_signal: "SIGHUP"

# Virtual root mappings with security
roots:
  - name: "public-docs"
    type: "fs"
    virtual: "mcp://docs/"
    real: "${CURRENT_DIR}/examples/sample-docs/public"
    read_only: true
  - name: "sensitive-docs"
    type: "fs" 
    virtual: "mcp://sensitive/"
    real: "${CURRENT_DIR}/examples/sample-docs/sensitive"
    read_only: true
  - name: "temp-storage"
    type: "fs"
    virtual: "mcp://temp/"
    real: "/tmp/airlock-demo"
    read_only: false

# Data Loss Prevention - showcases PII redaction
dlp:
  patterns:
    - name: "email"
      regex: '(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
      replace: "[REDACTED-EMAIL]"
    - name: "phone"
      regex: '(?i)(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'
      replace: "[REDACTED-PHONE]"
    - name: "ssn"
      regex: '(?i)\b\d{3}-?\d{2}-?\d{4}\b'
      replace: "[REDACTED-SSN]"
    - name: "credit_card"
      regex: '(?i)\b(?:\d{4}[-\s]?){3}\d{4}\b'
      replace: "[REDACTED-CC]"
    - name: "bearer_token"
      regex: '(?i)bearer\s+[a-z0-9._-]+'
      replace: "[REDACTED-TOKEN]"
    - name: "api_key"
      regex: '(?i)(api[_-]?key|token|secret)["\s]*[:=]["\s]*[a-z0-9._-]+'
      replace: "[REDACTED-API-KEY]"
    - name: "aws_key"
      regex: '(?i)(AKIA[0-9A-Z]{16})'
      replace: "[REDACTED-AWS-KEY]"
    - name: "password"
      regex: '(?i)(password|pass)["\s]*[:=]["\s]*[^\s\n]+'
      replace: "[REDACTED-PASSWORD]"

# Role-based rate limiting
rate_limiting:
  per_token: "100/min"  # Default for demo
  per_ip: "500/min"
  burst: 20

# MCP Server connections
upstreams:
  - name: "docs-server"
    type: "unix"
    socket: "/tmp/docs.sock"
    timeout: "30s"
    allow_tools: ["search_docs", "read_file", "list_directory"]
  - name: "analytics-server"
    type: "unix"
    socket: "/tmp/analytics.sock"
    timeout: "30s"
    allow_tools: ["query_metrics", "generate_report", "export_data", "get_dashboard_data"]

# Comprehensive audit logging with hash chaining
audit:
  backend: "sqlite"
  database: "/tmp/airlock-demo-audit.db"
  retention: "168h"  # 7 days
  export_format: "jsonl"
  hash_chain: true  # Tamper-evident logging
  include_request_body: true
  include_response_body: true

# Full observability for demo
observability:
  metrics:
    enabled: true
    path: "/metrics"
  tracing:
    enabled: false  # Keep simple for demo
  logging:
    level: "info"
    format: "json"
EOF

# Start Airlock
print_step "Starting MCP Airlock with demo configuration..."
./airlock --config /tmp/config-demo-resolved.yaml &
AIRLOCK_PID=$!

# Wait for Airlock to start
sleep 5

# Check if Airlock is running
if ! kill -0 $AIRLOCK_PID 2>/dev/null; then
    print_error "Airlock failed to start"
    exit 1
fi

print_success "Airlock started (PID: $AIRLOCK_PID)"

# Test health endpoints
print_step "Testing health endpoints..."
curl -s http://localhost:8080/live > /dev/null && print_success "Liveness check passed"
curl -s http://localhost:8080/ready > /dev/null && print_success "Readiness check passed"
curl -s http://localhost:8080/info > /dev/null && print_success "Info endpoint working"

echo ""
echo "🎉 MCP Airlock Demo is now running!"
echo "=================================="
echo ""
echo "📊 Demo Features Showcase:"
echo "• Zero-trust authentication with JWT tokens"
echo "• OPA/Rego policy enforcement with role-based access"
echo "• Data loss prevention with PII redaction"
echo "• Virtual root mapping with path security"
echo "• Comprehensive audit logging with hash chaining"
echo "• Rate limiting based on user roles"
echo ""
echo "🔑 Demo Tokens (saved in demo-tokens.json):"
echo ""

# Display tokens
if [ -f "demo-tokens.json" ]; then
    python3 -c "
import json
with open('demo-tokens.json') as f:
    tokens = json.load(f)
for role, token in tokens.items():
    print(f'{role.upper()} TOKEN: {token[:50]}...')
"
fi

echo ""
echo "🧪 Try these demo commands:"
echo ""
echo "1. Test without authentication (should fail):"
echo "   curl http://localhost:8080/mcp/tools"
echo ""
echo "2. Test with admin token (full access):"
echo "   curl -H \"Authorization: Bearer \$(cat demo-tokens.json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"admin\"])')\" http://localhost:8080/mcp/tools"
echo ""
echo "3. Search docs (should work for all roles):"
echo "   curl -H \"Authorization: Bearer \$(cat demo-tokens.json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"viewer\"])')\" -H \"Content-Type: application/json\" -d '{\"name\":\"search_docs\",\"arguments\":{\"query\":\"API\"}}' http://localhost:8080/mcp/tools/call"
echo ""
echo "4. Try to read sensitive file (should be blocked for non-admin):"
echo "   curl -H \"Authorization: Bearer \$(cat demo-tokens.json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"developer\"])')\" -H \"Content-Type: application/json\" -d '{\"name\":\"read_file\",\"arguments\":{\"file_path\":\"sensitive/secrets.txt\"}}' http://localhost:8080/mcp/tools/call"
echo ""
echo "5. View metrics and audit logs:"
echo "   curl http://localhost:8080/metrics"
echo "   sqlite3 /tmp/airlock-demo-audit.db \"SELECT * FROM audit_log LIMIT 5;\""
echo ""
echo "📱 Endpoints:"
echo "• Health: http://localhost:8080/live"
echo "• Metrics: http://localhost:8080/metrics"
echo "• MCP Tools: http://localhost:8080/mcp/tools"
echo ""
echo "🛑 To stop the demo:"
echo "   kill $AIRLOCK_PID $DOCS_PID $ANALYTICS_PID"
echo ""
echo "Press Ctrl+C to stop all services..."

# Cleanup function
cleanup() {
    echo ""
    print_step "Stopping demo services..."
    kill $AIRLOCK_PID $DOCS_PID $ANALYTICS_PID 2>/dev/null || true
    print_success "Demo stopped"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Keep script running
wait
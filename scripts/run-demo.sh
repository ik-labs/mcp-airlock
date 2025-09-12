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
pip3 install PyJWT &> /dev/null || {
    print_warning "Could not install PyJWT. Token generation may not work."
}

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

# Start servers
python3 examples/mcp-servers/docs-server.py &
DOCS_PID=$!
python3 examples/mcp-servers/analytics-server.py &
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

# Start Airlock
print_step "Starting MCP Airlock with demo configuration..."
./airlock -config config-demo.yaml &
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
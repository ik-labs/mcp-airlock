#!/bin/bash

# MCP Airlock Secret Management Script
# This script helps manage secrets for different deployment scenarios

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SECRETS_DIR="$PROJECT_ROOT/secrets"
TEMPLATES_DIR="$PROJECT_ROOT/configs/templates"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Show usage
show_usage() {
    cat << EOF
MCP Airlock Secret Management Script

Usage: $0 <command> [options]

Commands:
    init <env>              Initialize secrets directory for environment
    generate <env>          Generate configuration from template
    rotate <secret>         Rotate a specific secret
    validate <env>          Validate secrets for environment
    backup                  Backup current secrets
    restore <backup>        Restore secrets from backup

Environments:
    development             Local development environment
    kubernetes              Kubernetes deployment
    production              Production deployment

Examples:
    $0 init development
    $0 generate kubernetes
    $0 rotate oidc_client_secret
    $0 validate production

EOF
}

# Initialize secrets directory
init_secrets() {
    local env="$1"
    
    print_info "Initializing secrets for environment: $env"
    
    # Create secrets directory
    mkdir -p "$SECRETS_DIR/$env"
    
    # Create secret files with placeholder values
    case "$env" in
        "development")
            init_dev_secrets
            ;;
        "kubernetes")
            init_k8s_secrets
            ;;
        "production")
            init_prod_secrets
            ;;
        *)
            print_error "Unknown environment: $env"
            exit 1
            ;;
    esac
    
    print_success "Secrets directory initialized for $env"
    print_warning "Please update the secret files with actual values!"
}

# Initialize development secrets
init_dev_secrets() {
    local secrets_dir="$SECRETS_DIR/development"
    
    cat > "$secrets_dir/oidc_client_secret.txt" << EOF
dev-client-secret-change-me
EOF

    cat > "$secrets_dir/database_url.txt" << EOF
postgres://airlock:password@localhost:5432/airlock
EOF

    cat > "$secrets_dir/code_server_api_key.txt" << EOF
dev-api-key-change-me
EOF

    # Generate self-signed certificate for development
    if command -v openssl >/dev/null 2>&1; then
        print_info "Generating self-signed certificate for development"
        openssl req -x509 -newkey rsa:4096 -keyout "$secrets_dir/tls_key.pem" \
            -out "$secrets_dir/tls_cert.pem" -days 365 -nodes \
            -subj "/C=US/ST=Dev/L=Dev/O=MCP Airlock/CN=localhost" 2>/dev/null
    else
        print_warning "OpenSSL not found, creating placeholder TLS files"
        echo "# Placeholder TLS certificate" > "$secrets_dir/tls_cert.pem"
        echo "# Placeholder TLS key" > "$secrets_dir/tls_key.pem"
    fi
}

# Initialize Kubernetes secrets
init_k8s_secrets() {
    local secrets_dir="$SECRETS_DIR/kubernetes"
    
    cat > "$secrets_dir/oidc_client_secret.txt" << EOF
CHANGE-ME-k8s-oidc-client-secret
EOF

    cat > "$secrets_dir/database_url.txt" << EOF
postgres://airlock:CHANGE-ME@postgres-service:5432/airlock
EOF

    cat > "$secrets_dir/s3_bucket_url.txt" << EOF
s3://your-airlock-bucket/
EOF

    cat > "$secrets_dir/code_server_api_key.txt" << EOF
CHANGE-ME-k8s-api-key
EOF

    cat > "$secrets_dir/storage_encryption_key.txt" << EOF
CHANGE-ME-32-char-encryption-key
EOF

    echo "# Add your TLS certificate here" > "$secrets_dir/tls_cert.pem"
    echo "# Add your TLS private key here" > "$secrets_dir/tls_key.pem"
}

# Initialize production secrets
init_prod_secrets() {
    local secrets_dir="$SECRETS_DIR/production"
    
    cat > "$secrets_dir/oidc_client_secret.txt" << EOF
CHANGE-ME-prod-oidc-client-secret
EOF

    cat > "$secrets_dir/database_url.txt" << EOF
postgres://airlock:CHANGE-ME@prod-db.example.com:5432/airlock
EOF

    cat > "$secrets_dir/s3_bucket_url.txt" << EOF
s3://prod-airlock-bucket/
EOF

    cat > "$secrets_dir/logs_s3_bucket_url.txt" << EOF
s3://prod-airlock-logs/
EOF

    cat > "$secrets_dir/code_server_api_key.txt" << EOF
CHANGE-ME-prod-api-key
EOF

    cat > "$secrets_dir/storage_encryption_key.txt" << EOF
CHANGE-ME-32-char-encryption-key
EOF

    echo "# Add your production TLS certificate here" > "$secrets_dir/tls_cert.pem"
    echo "# Add your production TLS private key here" > "$secrets_dir/tls_key.pem"
}

# Generate configuration from template
generate_config() {
    local env="$1"
    local template_file=""
    local output_file=""
    
    case "$env" in
        "development")
            template_file="$TEMPLATES_DIR/docker-compose.yaml.template"
            output_file="$PROJECT_ROOT/config-dev.yaml"
            ;;
        "kubernetes")
            template_file="$TEMPLATES_DIR/kubernetes.yaml.template"
            output_file="$PROJECT_ROOT/config-k8s.yaml"
            ;;
        "production")
            template_file="$TEMPLATES_DIR/production.yaml.template"
            output_file="$PROJECT_ROOT/config-prod.yaml"
            ;;
        *)
            print_error "Unknown environment: $env"
            exit 1
            ;;
    esac
    
    if [[ ! -f "$template_file" ]]; then
        print_error "Template file not found: $template_file"
        exit 1
    fi
    
    print_info "Generating configuration for $env from template"
    
    # Copy template to output file
    cp "$template_file" "$output_file"
    
    print_success "Configuration generated: $output_file"
    print_warning "Remember to set environment variables or mount secrets appropriately!"
}

# Rotate a specific secret
rotate_secret() {
    local secret_name="$1"
    
    print_info "Rotating secret: $secret_name"
    
    case "$secret_name" in
        "oidc_client_secret")
            rotate_oidc_secret
            ;;
        "api_key")
            rotate_api_key
            ;;
        "encryption_key")
            rotate_encryption_key
            ;;
        "tls_cert")
            rotate_tls_cert
            ;;
        *)
            print_error "Unknown secret type: $secret_name"
            print_info "Supported secrets: oidc_client_secret, api_key, encryption_key, tls_cert"
            exit 1
            ;;
    esac
}

# Rotate OIDC client secret
rotate_oidc_secret() {
    local new_secret
    new_secret=$(openssl rand -base64 32)
    
    print_info "Generated new OIDC client secret"
    print_warning "Update your OIDC provider with the new secret:"
    echo "$new_secret"
    
    # Update secret files
    for env_dir in "$SECRETS_DIR"/*; do
        if [[ -d "$env_dir" ]]; then
            echo "$new_secret" > "$env_dir/oidc_client_secret.txt"
        fi
    done
    
    print_success "OIDC client secret rotated"
}

# Rotate API key
rotate_api_key() {
    local new_key
    new_key=$(openssl rand -hex 32)
    
    print_info "Generated new API key: $new_key"
    
    # Update secret files
    for env_dir in "$SECRETS_DIR"/*; do
        if [[ -d "$env_dir" ]]; then
            echo "$new_key" > "$env_dir/code_server_api_key.txt"
        fi
    done
    
    print_success "API key rotated"
}

# Rotate encryption key
rotate_encryption_key() {
    local new_key
    new_key=$(openssl rand -base64 32)
    
    print_info "Generated new encryption key"
    print_warning "This will invalidate existing encrypted data!"
    
    # Update secret files
    for env_dir in "$SECRETS_DIR"/*; do
        if [[ -d "$env_dir" ]]; then
            echo "$new_key" > "$env_dir/storage_encryption_key.txt"
        fi
    done
    
    print_success "Encryption key rotated"
}

# Rotate TLS certificate
rotate_tls_cert() {
    print_info "Generating new TLS certificate"
    
    for env_dir in "$SECRETS_DIR"/*; do
        if [[ -d "$env_dir" ]]; then
            local env_name
            env_name=$(basename "$env_dir")
            
            if [[ "$env_name" == "development" ]]; then
                # Generate self-signed for development
                openssl req -x509 -newkey rsa:4096 -keyout "$env_dir/tls_key.pem" \
                    -out "$env_dir/tls_cert.pem" -days 365 -nodes \
                    -subj "/C=US/ST=Dev/L=Dev/O=MCP Airlock/CN=localhost" 2>/dev/null
            else
                print_warning "For $env_name, please obtain a proper certificate from your CA"
                echo "# Replace with actual certificate" > "$env_dir/tls_cert.pem"
                echo "# Replace with actual private key" > "$env_dir/tls_key.pem"
            fi
        fi
    done
    
    print_success "TLS certificates rotated"
}

# Validate secrets for environment
validate_secrets() {
    local env="$1"
    local secrets_dir="$SECRETS_DIR/$env"
    local errors=0
    
    print_info "Validating secrets for environment: $env"
    
    if [[ ! -d "$secrets_dir" ]]; then
        print_error "Secrets directory not found: $secrets_dir"
        print_info "Run: $0 init $env"
        exit 1
    fi
    
    # Check required secret files
    local required_secrets=()
    case "$env" in
        "development")
            required_secrets=("oidc_client_secret.txt" "database_url.txt" "code_server_api_key.txt")
            ;;
        "kubernetes"|"production")
            required_secrets=("oidc_client_secret.txt" "database_url.txt" "s3_bucket_url.txt" 
                             "code_server_api_key.txt" "storage_encryption_key.txt" 
                             "tls_cert.pem" "tls_key.pem")
            ;;
    esac
    
    for secret in "${required_secrets[@]}"; do
        local secret_file="$secrets_dir/$secret"
        if [[ ! -f "$secret_file" ]]; then
            print_error "Missing secret file: $secret"
            ((errors++))
        elif [[ ! -s "$secret_file" ]]; then
            print_error "Empty secret file: $secret"
            ((errors++))
        elif grep -q "CHANGE-ME" "$secret_file" 2>/dev/null; then
            print_warning "Secret file contains placeholder: $secret"
            ((errors++))
        else
            print_success "Valid secret file: $secret"
        fi
    done
    
    if [[ $errors -eq 0 ]]; then
        print_success "All secrets validated successfully for $env"
    else
        print_error "Found $errors issues with secrets"
        exit 1
    fi
}

# Backup secrets
backup_secrets() {
    local backup_dir="$SECRETS_DIR/backups"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$backup_dir/secrets_backup_$timestamp.tar.gz"
    
    print_info "Creating secrets backup"
    
    mkdir -p "$backup_dir"
    
    tar -czf "$backup_file" -C "$SECRETS_DIR" \
        --exclude="backups" \
        --exclude="*.bak" \
        .
    
    print_success "Secrets backed up to: $backup_file"
}

# Restore secrets from backup
restore_secrets() {
    local backup_file="$1"
    
    if [[ ! -f "$backup_file" ]]; then
        print_error "Backup file not found: $backup_file"
        exit 1
    fi
    
    print_warning "This will overwrite existing secrets!"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Restoring secrets from backup"
        
        # Create backup of current secrets
        backup_secrets
        
        # Restore from backup
        tar -xzf "$backup_file" -C "$SECRETS_DIR"
        
        print_success "Secrets restored from: $backup_file"
    else
        print_info "Restore cancelled"
    fi
}

# Main script logic
main() {
    if [[ $# -eq 0 ]]; then
        show_usage
        exit 1
    fi
    
    local command="$1"
    shift
    
    case "$command" in
        "init")
            if [[ $# -ne 1 ]]; then
                print_error "Usage: $0 init <environment>"
                exit 1
            fi
            init_secrets "$1"
            ;;
        "generate")
            if [[ $# -ne 1 ]]; then
                print_error "Usage: $0 generate <environment>"
                exit 1
            fi
            generate_config "$1"
            ;;
        "rotate")
            if [[ $# -ne 1 ]]; then
                print_error "Usage: $0 rotate <secret_name>"
                exit 1
            fi
            rotate_secret "$1"
            ;;
        "validate")
            if [[ $# -ne 1 ]]; then
                print_error "Usage: $0 validate <environment>"
                exit 1
            fi
            validate_secrets "$1"
            ;;
        "backup")
            backup_secrets
            ;;
        "restore")
            if [[ $# -ne 1 ]]; then
                print_error "Usage: $0 restore <backup_file>"
                exit 1
            fi
            restore_secrets "$1"
            ;;
        *)
            print_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
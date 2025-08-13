# Multi-stage Docker build for MCP Airlock with security hardening
# Stage 1: Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Create non-root user for build
RUN adduser -D -g '' appuser

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build arguments for version information
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

# Build the application with security flags
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME}" \
    -a -installsuffix cgo \
    -o airlock \
    ./cmd/airlock

# Stage 2: Runtime stage with security hardening
FROM alpine:3.19

# Install runtime dependencies and security updates
RUN apk --no-cache add ca-certificates tzdata sqlite dumb-init && \
    apk --no-cache upgrade && \
    rm -rf /var/cache/apk/* && \
    # Remove unnecessary packages and files
    rm -rf /tmp/* /var/tmp/* && \
    # Remove shell access for security
    rm -f /bin/sh /bin/ash /bin/bash 2>/dev/null || true

# Create non-root user and group with no shell and no home
RUN addgroup -g 1001 -S airlock && \
    adduser -u 1001 -S airlock -G airlock -s /sbin/nologin -h /nonexistent

# Create necessary directories with proper permissions
RUN mkdir -p /app /var/lib/airlock /var/log/airlock /etc/airlock /tmp/airlock && \
    chown -R airlock:airlock /app /var/lib/airlock /var/log/airlock /etc/airlock /tmp/airlock && \
    chmod 750 /app /var/lib/airlock /var/log/airlock /etc/airlock && \
    chmod 1777 /tmp/airlock

# Copy CA certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary from builder stage
COPY --from=builder /build/airlock /app/airlock

# Copy default configuration and security profiles
COPY --chown=airlock:airlock config.yaml /etc/airlock/config.yaml
COPY --chown=airlock:airlock configs/security/seccomp-profile.json /etc/airlock/seccomp-profile.json

# Set proper permissions (read-only for config files)
RUN chmod +x /app/airlock && \
    chmod 644 /etc/airlock/config.yaml && \
    chmod 644 /etc/airlock/seccomp-profile.json && \
    # Make filesystem read-only except for necessary writable directories
    chmod -R a-w /etc /usr /lib /bin /sbin 2>/dev/null || true

# Switch to non-root user
USER airlock:airlock

# Set working directory
WORKDIR /app

# Expose port (non-privileged)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/live || exit 1

# Set environment variables for security
ENV CONFIG_FILE=/etc/airlock/config.yaml \
    LOG_LEVEL=info \
    LOG_FORMAT=json \
    TMPDIR=/tmp/airlock \
    HOME=/nonexistent \
    USER=airlock \
    # Security environment variables
    GODEBUG=madvdontneed=1 \
    CGO_ENABLED=0

# Use dumb-init for proper signal handling and process reaping
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Run the application with security flags
CMD ["/app/airlock", "-config", "/etc/airlock/config.yaml"]
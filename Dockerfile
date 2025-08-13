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

# Stage 2: Runtime stage
FROM alpine:3.19

# Install runtime dependencies and security updates
RUN apk --no-cache add ca-certificates tzdata sqlite && \
    apk --no-cache upgrade && \
    rm -rf /var/cache/apk/*

# Create non-root user and group
RUN addgroup -g 1001 -S airlock && \
    adduser -u 1001 -S airlock -G airlock

# Create necessary directories with proper permissions
RUN mkdir -p /app /var/lib/airlock /var/log/airlock /etc/airlock && \
    chown -R airlock:airlock /app /var/lib/airlock /var/log/airlock /etc/airlock

# Copy CA certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary from builder stage
COPY --from=builder /build/airlock /app/airlock

# Copy default configuration
COPY --chown=airlock:airlock config.yaml /etc/airlock/config.yaml

# Set proper permissions
RUN chmod +x /app/airlock && \
    chmod 644 /etc/airlock/config.yaml

# Switch to non-root user
USER airlock

# Set working directory
WORKDIR /app

# Expose port (non-privileged)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/live || exit 1

# Set environment variables
ENV CONFIG_FILE=/etc/airlock/config.yaml
ENV LOG_LEVEL=info
ENV LOG_FORMAT=json

# Run the application
ENTRYPOINT ["/app/airlock"]
CMD ["-config", "/etc/airlock/config.yaml"]
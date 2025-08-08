# MCP Airlock Makefile

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go variables
GOCMD = go
GOBUILD = $(GOCMD) build
GOCLEAN = $(GOCMD) clean
GOTEST = $(GOCMD) test
GOGET = $(GOCMD) get
GOMOD = $(GOCMD) mod

# Build flags
LDFLAGS = -ldflags "-X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Binary name
BINARY_NAME = airlock
BINARY_PATH = ./cmd/airlock

# Default target
.PHONY: all
all: clean deps test build

# Install dependencies
.PHONY: deps
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Build the binary
.PHONY: build
build:
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) $(BINARY_PATH)

# Build for production (optimized)
.PHONY: build-prod
build-prod:
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) $(LDFLAGS) -a -installsuffix cgo -o $(BINARY_NAME) $(BINARY_PATH)

# Run tests
.PHONY: test
test:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

# Run tests with coverage report
.PHONY: test-coverage
test-coverage: test
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
.PHONY: clean
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

# Run the application
.PHONY: run
run: build
	./$(BINARY_NAME) -config config.yaml

# Run with development configuration
.PHONY: run-dev
run-dev: build
	./$(BINARY_NAME) -config config.yaml

# Format code
.PHONY: fmt
fmt:
	$(GOCMD) fmt ./...

# Run linter (requires golangci-lint)
.PHONY: lint
lint:
	golangci-lint run

# Check for security issues (requires gosec)
.PHONY: security
security:
	gosec ./...

# Run all checks
.PHONY: check
check: fmt lint security test

# Show version
.PHONY: version
version:
	@echo "Version: $(VERSION)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all          - Clean, install deps, test, and build"
	@echo "  deps         - Install Go dependencies"
	@echo "  build        - Build the binary"
	@echo "  build-prod   - Build optimized binary for production"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage report"
	@echo "  clean        - Clean build artifacts"
	@echo "  run          - Build and run the application"
	@echo "  run-dev      - Build and run with development config"
	@echo "  fmt          - Format Go code"
	@echo "  lint         - Run linter"
	@echo "  security     - Run security checks"
	@echo "  check        - Run all checks (fmt, lint, security, test)"
	@echo "  version      - Show version information"
	@echo "  help         - Show this help message"
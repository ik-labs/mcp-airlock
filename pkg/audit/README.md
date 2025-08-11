# Audit Package

The audit package provides tamper-evident audit logging with Blake3 hash chaining for compliance and security monitoring in the MCP Airlock gateway.

## Features

- **Blake3 Hash Chaining**: Tamper-evident audit trail with cryptographic integrity
- **SQLite Backend**: High-performance WAL mode with per-pod storage
- **Structured Events**: Rich audit events with correlation IDs and metadata
- **Concurrent Safe**: Thread-safe operations with proper synchronization
- **Query Interface**: Flexible filtering and pagination for audit queries
- **Export Support**: JSONL export format for external analysis
- **Performance Optimized**: Sub-millisecond hash computation, batched writes

## Quick Start

```go
package main

import (
    "context"
    "log"
    
    "github.com/ik-labs/mcp-airlock/pkg/audit"
)

func main() {
    // Create audit logger
    config := audit.DefaultConfig("/var/lib/airlock/audit.db")
    logger, err := audit.NewAuditLogger(config)
    if err != nil {
        log.Fatal(err)
    }
    defer logger.Close()
    
    ctx := context.Background()
    
    // Log an authentication event
    event := audit.NewAuthenticationEvent(
        "corr-123",
        "user@example.com", 
        audit.DecisionAllow,
        "valid JWT token",
    )
    
    if err := logger.LogEvent(ctx, event); err != nil {
        log.Fatal(err)
    }
    
    // Query events
    events, err := logger.Query(ctx, &audit.QueryFilter{
        Subject: "user@example.com",
        Limit:   10,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Found %d events", len(events))
}
```

## Event Types

The package provides helper functions for common audit events:

- `NewAuthenticationEvent()` - JWT validation, login/logout
- `NewAuthorizationEvent()` - Policy decisions, access control
- `NewResourceAccessEvent()` - File/resource access
- `NewRedactionEvent()` - DLP redaction counts
- `NewSecurityViolationEvent()` - Security violations, attacks
- `NewRateLimitEvent()` - Rate limiting events

## Hash Chain Integrity

The audit system uses Blake3 hash chaining to ensure tamper detection:

```go
// Validate entire chain
if err := logger.ValidateChain(ctx); err != nil {
    log.Fatal("Chain integrity compromised:", err)
}
```

## Configuration

```go
config := &audit.AuditConfig{
    Backend:       "sqlite",
    Database:      "/var/lib/airlock/audit.db",
    RetentionDays: 30,
    ExportFormat:  "jsonl",
    BatchSize:     100,
    FlushTimeout:  5 * time.Second,
}
```

## Requirements Compliance

This implementation satisfies the following MCP Airlock requirements:

- **R3.1**: All MCP interactions logged with request ID and timestamp
- **R3.3**: Blake3 hash chaining for tamper detection with rotation and JSONL export  
- **R8.1**: Policy decisions logged with rule ID and input digest
- **R8.2**: Redaction counts logged without exposing original data

## Performance

- Hash computation: ~1.8μs per event (Blake3)
- Batch writes: 100 events per transaction (configurable)
- WAL mode: High-performance concurrent reads
- Memory efficient: Streaming for large exports

## Security

- Cryptographic integrity via Blake3 hash chaining
- No sensitive data in logs (only redaction counts)
- Persistent salt for chain validation across restarts
- Tamper detection through hash validation
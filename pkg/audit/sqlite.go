package audit

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// SQLiteAuditLogger implements AuditLogger using SQLite with WAL mode
type SQLiteAuditLogger struct {
	db     *sql.DB
	hasher *Hasher
	config *AuditConfig

	// Buffering for high-performance writes
	eventBuffer []*AuditEvent
	bufferMutex sync.Mutex
	flushTimer  *time.Timer

	// Shutdown coordination
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewSQLiteAuditLogger creates a new SQLite-based audit logger
func NewSQLiteAuditLogger(config *AuditConfig) (*SQLiteAuditLogger, error) {
	// Set defaults
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.FlushTimeout == 0 {
		config.FlushTimeout = 5 * time.Second
	}
	if config.RetentionDays == 0 {
		config.RetentionDays = 30
	}

	// Open SQLite database with WAL mode for performance
	db, err := sql.Open("sqlite3", config.Database+"?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=10000")
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(1) // SQLite works best with single writer
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping SQLite database: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	logger := &SQLiteAuditLogger{
		db:          db,
		config:      config,
		eventBuffer: make([]*AuditEvent, 0, config.BatchSize),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Initialize database schema first
	if err := logger.initSchema(); err != nil {
		logger.Close()
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	// Load or create hasher with persistent salt
	hasher, err := logger.loadOrCreateHasher()
	if err != nil {
		logger.Close()
		return nil, fmt.Errorf("failed to initialize hasher: %w", err)
	}
	logger.hasher = hasher

	// Start background flush routine
	logger.wg.Add(1)
	go logger.flushRoutine()

	return logger, nil
}

// initSchema creates the audit_events table with proper indexes
func (s *SQLiteAuditLogger) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		timestamp INTEGER NOT NULL,
		correlation_id TEXT NOT NULL,
		tenant TEXT NOT NULL,
		subject TEXT NOT NULL,
		action TEXT NOT NULL,
		resource TEXT NOT NULL,
		decision TEXT NOT NULL,
		reason TEXT NOT NULL,
		metadata TEXT, -- JSON
		hash TEXT NOT NULL UNIQUE,
		previous_hash TEXT NOT NULL,
		latency_ms INTEGER DEFAULT 0,
		redaction_count INTEGER DEFAULT 0,
		created_at INTEGER DEFAULT (strftime('%s', 'now'))
	);
	
	-- Indexes for common queries
	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events(tenant);
	CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_events(subject);
	CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
	CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision);
	CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_events(correlation_id);
	CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at);
	
	-- Composite index for common filter combinations
	CREATE INDEX IF NOT EXISTS idx_audit_tenant_timestamp ON audit_events(tenant, timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_subject_timestamp ON audit_events(subject, timestamp);
	
	-- Table for storing hasher salt (for chain validation)
	CREATE TABLE IF NOT EXISTS audit_metadata (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		created_at INTEGER DEFAULT (strftime('%s', 'now'))
	);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

// loadOrCreateHasher loads an existing hasher salt from the database or creates a new one
func (s *SQLiteAuditLogger) loadOrCreateHasher() (*Hasher, error) {
	// Try to load existing salt
	var saltHex string
	err := s.db.QueryRow("SELECT value FROM audit_metadata WHERE key = 'hasher_salt'").Scan(&saltHex)

	if err == sql.ErrNoRows {
		// No existing salt, create new hasher and store salt
		hasher := NewHasher()
		salt := hasher.GetSalt()

		_, err := s.db.Exec(`
			INSERT INTO audit_metadata (key, value) 
			VALUES ('hasher_salt', ?)
		`, fmt.Sprintf("%x", salt))
		if err != nil {
			return nil, fmt.Errorf("failed to store hasher salt: %w", err)
		}

		return hasher, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to query hasher salt: %w", err)
	}

	// Decode existing salt
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hasher salt: %w", err)
	}

	if len(salt) != 32 {
		return nil, fmt.Errorf("invalid salt length: expected 32, got %d", len(salt))
	}

	return NewHasherWithSalt(salt), nil
}

// LogEvent adds an audit event to the buffer for batch processing
func (s *SQLiteAuditLogger) LogEvent(ctx context.Context, event *AuditEvent) error {
	// Serialize hash computation and chaining to prevent race conditions
	s.bufferMutex.Lock()
	defer s.bufferMutex.Unlock()

	// Get the last hash for chaining (must be done under lock)
	lastHash, err := s.getLastHashUnsafe(ctx)
	if err != nil {
		return fmt.Errorf("failed to get last hash: %w", err)
	}

	// Set up hash chaining
	event.PreviousHash = lastHash

	// Compute event hash
	hash, err := s.hasher.HashEvent(event)
	if err != nil {
		return fmt.Errorf("failed to compute event hash: %w", err)
	}
	event.Hash = hash

	// Add to buffer
	s.eventBuffer = append(s.eventBuffer, event)

	// Flush if buffer is full
	if len(s.eventBuffer) >= s.config.BatchSize {
		return s.flushBuffer()
	}

	// Reset flush timer
	if s.flushTimer != nil {
		s.flushTimer.Stop()
	}
	s.flushTimer = time.AfterFunc(s.config.FlushTimeout, func() {
		s.bufferMutex.Lock()
		defer s.bufferMutex.Unlock()
		s.flushBuffer()
	})

	return nil
}

// flushBuffer writes buffered events to the database
func (s *SQLiteAuditLogger) flushBuffer() error {
	if len(s.eventBuffer) == 0 {
		return nil
	}

	// Prepare batch insert
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO audit_events (
			id, timestamp, correlation_id, tenant, subject, action, 
			resource, decision, reason, metadata, hash, previous_hash,
			latency_ms, redaction_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	// Insert all buffered events
	for _, event := range s.eventBuffer {
		metadataJSON, _ := json.Marshal(event.Metadata)

		_, err := stmt.Exec(
			event.ID,
			event.Timestamp.UnixNano(),
			event.CorrelationID,
			event.Tenant,
			event.Subject,
			event.Action,
			event.Resource,
			event.Decision,
			event.Reason,
			string(metadataJSON),
			event.Hash,
			event.PreviousHash,
			event.LatencyMs,
			event.RedactionCount,
		)
		if err != nil {
			return fmt.Errorf("failed to insert event %s: %w", event.ID, err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Clear buffer
	s.eventBuffer = s.eventBuffer[:0]

	return nil
}

// Query retrieves audit events based on filter criteria
func (s *SQLiteAuditLogger) Query(ctx context.Context, filter *QueryFilter) ([]*AuditEvent, error) {
	query := "SELECT id, timestamp, correlation_id, tenant, subject, action, resource, decision, reason, metadata, hash, previous_hash, latency_ms, redaction_count FROM audit_events"
	args := []interface{}{}
	conditions := []string{}

	// Build WHERE clause
	if filter.StartTime != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.StartTime.UnixNano())
	}
	if filter.EndTime != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.EndTime.UnixNano())
	}
	if filter.Tenant != "" {
		conditions = append(conditions, "tenant = ?")
		args = append(args, filter.Tenant)
	}
	if filter.Subject != "" {
		conditions = append(conditions, "subject = ?")
		args = append(args, filter.Subject)
	}
	if filter.Action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, filter.Action)
	}
	if filter.Decision != "" {
		conditions = append(conditions, "decision = ?")
		args = append(args, filter.Decision)
	}
	if filter.CorrelationID != "" {
		conditions = append(conditions, "correlation_id = ?")
		args = append(args, filter.CorrelationID)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	// Add ordering
	orderBy := "timestamp"
	if filter.OrderBy != "" {
		orderBy = filter.OrderBy
	}
	query += " ORDER BY " + orderBy
	if filter.OrderDesc {
		query += " DESC"
	}

	// Add pagination
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)

		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	// Execute query
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	// Parse results
	var events []*AuditEvent
	for rows.Next() {
		event := &AuditEvent{}
		var timestampNano int64
		var metadataJSON string

		err := rows.Scan(
			&event.ID,
			&timestampNano,
			&event.CorrelationID,
			&event.Tenant,
			&event.Subject,
			&event.Action,
			&event.Resource,
			&event.Decision,
			&event.Reason,
			&metadataJSON,
			&event.Hash,
			&event.PreviousHash,
			&event.LatencyMs,
			&event.RedactionCount,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		event.Timestamp = time.Unix(0, timestampNano)

		// Parse metadata JSON
		if metadataJSON != "" {
			if err := json.Unmarshal([]byte(metadataJSON), &event.Metadata); err != nil {
				// Log error but don't fail the query
				event.Metadata = map[string]interface{}{"parse_error": err.Error()}
			}
		}

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return events, nil
}

// Export writes audit events to the provided writer in JSONL format
func (s *SQLiteAuditLogger) Export(ctx context.Context, format string, writer io.Writer) error {
	// For now, only support JSONL format
	if format != "jsonl" {
		return fmt.Errorf("unsupported export format: %s", format)
	}

	// Query all events (could be optimized with streaming for large datasets)
	events, err := s.Query(ctx, &QueryFilter{
		OrderBy: "timestamp",
	})
	if err != nil {
		return fmt.Errorf("failed to query events for export: %w", err)
	}

	// Write each event as a JSON line
	for _, event := range events {
		jsonData, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("failed to marshal event %s: %w", event.ID, err)
		}

		if _, err := writer.Write(jsonData); err != nil {
			return fmt.Errorf("failed to write event %s: %w", event.ID, err)
		}

		if _, err := writer.Write([]byte("\n")); err != nil {
			return fmt.Errorf("failed to write newline: %w", err)
		}
	}

	return nil
}

// GetLastHash returns the hash of the most recent audit event
func (s *SQLiteAuditLogger) GetLastHash(ctx context.Context) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		"SELECT hash FROM audit_events ORDER BY timestamp DESC, id DESC LIMIT 1",
	).Scan(&hash)

	if err == sql.ErrNoRows {
		return "", nil // Empty chain
	}
	if err != nil {
		return "", fmt.Errorf("failed to get last hash: %w", err)
	}

	return hash, nil
}

// getLastHashUnsafe returns the hash of the most recent audit event, considering buffered events
// This method must be called with bufferMutex held
func (s *SQLiteAuditLogger) getLastHashUnsafe(ctx context.Context) (string, error) {
	// Check if there are buffered events first
	if len(s.eventBuffer) > 0 {
		return s.eventBuffer[len(s.eventBuffer)-1].Hash, nil
	}

	// Otherwise, get from database
	return s.GetLastHash(ctx)
}

// ValidateChain verifies the integrity of the entire hash chain
func (s *SQLiteAuditLogger) ValidateChain(ctx context.Context) error {
	// Query all events in chronological order
	events, err := s.Query(ctx, &QueryFilter{
		OrderBy: "timestamp",
	})
	if err != nil {
		return fmt.Errorf("failed to query events for validation: %w", err)
	}

	// Validate the chain
	return s.hasher.ValidateChain(events)
}

// flushRoutine runs in the background to periodically flush buffered events
func (s *SQLiteAuditLogger) flushRoutine() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.FlushTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			// Final flush before shutdown
			s.bufferMutex.Lock()
			s.flushBuffer()
			s.bufferMutex.Unlock()
			return

		case <-ticker.C:
			s.bufferMutex.Lock()
			s.flushBuffer()
			s.bufferMutex.Unlock()
		}
	}
}

// Close gracefully shuts down the audit logger
func (s *SQLiteAuditLogger) Close() error {
	// Stop background routines
	s.cancel()
	s.wg.Wait()

	// Final flush
	s.bufferMutex.Lock()
	err := s.flushBuffer()
	s.bufferMutex.Unlock()

	// Close database
	if dbErr := s.db.Close(); dbErr != nil && err == nil {
		err = dbErr
	}

	return err
}

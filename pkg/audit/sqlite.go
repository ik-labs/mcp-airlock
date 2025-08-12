package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
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

	// S3 client for exports
	s3Client S3Client
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
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 24 * time.Hour // Daily cleanup by default
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

	// Initialize S3 client if S3 settings are provided
	if config.S3Bucket != "" {
		awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(config.S3Region))
		if err != nil {
			logger.Close()
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}
		logger.s3Client = s3.NewFromConfig(awsConfig)
	}

	// Start background routines
	logger.wg.Add(1)
	go logger.flushRoutine()

	logger.wg.Add(1)
	go logger.cleanupRoutine()

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
	
	-- Table for tracking tombstoned subjects
	CREATE TABLE IF NOT EXISTS audit_tombstones (
		subject TEXT PRIMARY KEY,
		tombstone_event_id TEXT NOT NULL,
		created_at INTEGER DEFAULT (strftime('%s', 'now')),
		reason TEXT NOT NULL
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
	// Load tombstoned subjects first
	tombstones, err := s.loadTombstones(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load tombstones: %w", err)
	}

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

		// Check if subject has been tombstoned and redact if necessary
		if event.Action != ActionTombstone {
			event = s.applyTombstoneRedactionWithMap(event, tombstones)
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

// Flush ensures all pending events are written to the database
func (s *SQLiteAuditLogger) Flush() error {
	s.bufferMutex.Lock()
	defer s.bufferMutex.Unlock()
	return s.flushBuffer()
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

// cleanupRoutine runs in the background to periodically clean up expired events
func (s *SQLiteAuditLogger) cleanupRoutine() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return

		case <-ticker.C:
			if deleted, err := s.CleanupExpiredEvents(s.ctx); err != nil {
				// Log error but continue running
				fmt.Printf("Retention cleanup failed: %v\n", err)
			} else if deleted > 0 {
				// Log successful cleanup
				correlationID := uuid.New().String()
				cutoffTime := time.Now().UTC().AddDate(0, 0, -s.config.RetentionDays)
				cleanupEvent := NewRetentionCleanupEvent(correlationID, deleted, cutoffTime)
				s.LogEvent(s.ctx, cleanupEvent)
			}
		}
	}
}

// CleanupExpiredEvents removes events older than the retention period
func (s *SQLiteAuditLogger) CleanupExpiredEvents(ctx context.Context) (int, error) {
	cutoffTime := time.Now().UTC().AddDate(0, 0, -s.config.RetentionDays)
	cutoffNano := cutoffTime.UnixNano()

	// Delete expired events (but preserve tombstone events)
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM audit_events 
		WHERE timestamp < ? AND action != ?
	`, cutoffNano, ActionTombstone)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired events: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rowsAffected), nil
}

// CreateTombstone creates a tombstone event for subject erasure
func (s *SQLiteAuditLogger) CreateTombstone(ctx context.Context, subject, reason string) error {
	// First, ensure all pending events are flushed to maintain proper hash chain
	s.bufferMutex.Lock()
	err := s.flushBuffer()
	s.bufferMutex.Unlock()
	if err != nil {
		return fmt.Errorf("failed to flush pending events before tombstone: %w", err)
	}

	correlationID := uuid.New().String()
	tombstone := NewTombstoneEvent(correlationID, subject, reason)

	// Log the tombstone event - this preserves the hash chain
	if err := s.LogEvent(ctx, tombstone); err != nil {
		return fmt.Errorf("failed to log tombstone event: %w", err)
	}

	// Wait for flush to ensure tombstone is persisted
	s.bufferMutex.Lock()
	err = s.flushBuffer()
	s.bufferMutex.Unlock()
	if err != nil {
		return fmt.Errorf("failed to flush tombstone event: %w", err)
	}

	// Create a separate tombstone table to track erased subjects
	// This preserves the original audit events and their hash chain
	// Record the subject as erased

	// Record the subject as erased
	_, err = s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO audit_tombstones (subject, tombstone_event_id, reason)
		VALUES (?, ?, ?)
	`, subject, tombstone.ID, reason)
	if err != nil {
		return fmt.Errorf("failed to record tombstone: %w", err)
	}

	return nil
}

// ExportToS3 exports audit events to S3 with optional KMS encryption
func (s *SQLiteAuditLogger) ExportToS3(ctx context.Context, bucket, prefix string, kmsKeyID string) error {
	if s.s3Client == nil {
		return fmt.Errorf("S3 client not initialized")
	}

	// Generate export filename with timestamp
	timestamp := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	key := fmt.Sprintf("%s/audit-export-%s.jsonl", strings.TrimSuffix(prefix, "/"), timestamp)

	// Export to buffer first
	var buffer bytes.Buffer
	if err := s.Export(ctx, "jsonl", &buffer); err != nil {
		return fmt.Errorf("failed to export to buffer: %w", err)
	}

	// Prepare S3 put object input
	putInput := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(buffer.Bytes()),
		ContentType: aws.String("application/x-jsonlines"),
		Metadata: map[string]string{
			"export-timestamp": timestamp,
			"source":           "mcp-airlock-audit",
		},
	}

	// Add KMS encryption if specified
	if kmsKeyID != "" {
		putInput.ServerSideEncryption = types.ServerSideEncryptionAwsKms
		putInput.SSEKMSKeyId = aws.String(kmsKeyID)
	}

	// Upload to S3
	_, err := s.s3Client.PutObject(ctx, putInput)
	if err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	return nil
}

// loadTombstones loads all tombstoned subjects into a map
func (s *SQLiteAuditLogger) loadTombstones(ctx context.Context) (map[string]bool, error) {
	tombstones := make(map[string]bool)

	rows, err := s.db.QueryContext(ctx, "SELECT subject FROM audit_tombstones")
	if err != nil {
		return tombstones, nil // Return empty map if table doesn't exist yet
	}
	defer rows.Close()

	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			continue // Skip invalid rows
		}
		tombstones[subject] = true
	}

	return tombstones, nil
}

// queryRaw retrieves audit events without applying tombstone redaction (for internal use)
func (s *SQLiteAuditLogger) queryRaw(ctx context.Context, filter *QueryFilter) ([]*AuditEvent, error) {
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

	// Parse results (without tombstone redaction)
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

// applyTombstoneRedactionWithMap checks if a subject has been tombstoned and redacts it using a pre-loaded map
func (s *SQLiteAuditLogger) applyTombstoneRedactionWithMap(event *AuditEvent, tombstones map[string]bool) *AuditEvent {
	if !tombstones[event.Subject] {
		return event // Return original event if not tombstoned
	}

	// Create a copy of the event with redacted subject
	redactedEvent := *event
	redactedEvent.Subject = fmt.Sprintf("erased_%x", s.hasher.HashString(event.Subject))

	// Add metadata indicating erasure
	if redactedEvent.Metadata == nil {
		redactedEvent.Metadata = make(map[string]interface{})
	}
	redactedEvent.Metadata["original_subject_erased"] = true

	return &redactedEvent
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

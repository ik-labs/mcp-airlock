package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// MockS3Client implements a mock S3 client for testing
type MockS3Client struct {
	putObjectCalls []s3.PutObjectInput
	putObjectError error
}

func (m *MockS3Client) PutObject(_ context.Context, params *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.putObjectCalls == nil {
		m.putObjectCalls = make([]s3.PutObjectInput, 0)
	}
	m.putObjectCalls = append(m.putObjectCalls, *params)

	if m.putObjectError != nil {
		return nil, m.putObjectError
	}

	return &s3.PutObjectOutput{
		ETag: aws.String("mock-etag"),
	}, nil
}

func TestSQLiteAuditLogger_ExportToS3(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_s3_export.db")

	config := &AuditConfig{
		Backend:         "sqlite",
		Database:        dbPath,
		RetentionDays:   30,
		BatchSize:       1,
		FlushTimeout:    10 * time.Millisecond,
		CleanupInterval: time.Hour,
		S3Bucket:        "test-audit-bucket",
		S3Prefix:        "audit-logs",
		S3Region:        "us-east-1",
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func(logger *SQLiteAuditLogger) {
		err := logger.Close()
		if err != nil {

		}
	}(logger)

	// Replace the S3 client with our mock
	mockS3 := &MockS3Client{}
	logger.s3Client = mockS3

	ctx := context.Background()

	// Create some test events
	events := []*AuditEvent{
		NewAuthenticationEvent("s3-export-1", "user1@example.com", DecisionAllow, "valid token"),
		NewAuthorizationEvent("s3-export-2", "tenant-1", "user2@example.com", "mcp://repo/file.txt", DecisionDeny, "policy denied"),
	}

	for _, event := range events {
		event.Tenant = "tenant-1"
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("Failed to log event: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Test export without KMS
	if err := logger.ExportToS3(ctx, "test-bucket", "audit-logs", ""); err != nil {
		t.Fatalf("Failed to export to S3: %v", err)
	}

	// Verify S3 call was made
	if len(mockS3.putObjectCalls) != 1 {
		t.Fatalf("Expected 1 S3 PutObject call, got %d", len(mockS3.putObjectCalls))
	}

	putCall := mockS3.putObjectCalls[0]

	// Verify bucket and key
	if *putCall.Bucket != "test-bucket" {
		t.Errorf("Expected bucket 'test-bucket', got '%s'", *putCall.Bucket)
	}

	if !containsString(*putCall.Key, "audit-logs/audit-export-") {
		t.Errorf("Expected key to contain 'audit-logs/audit-export-', got '%s'", *putCall.Key)
	}

	if !containsString(*putCall.Key, ".jsonl") {
		t.Errorf("Expected key to end with '.jsonl', got '%s'", *putCall.Key)
	}

	// Verify content type
	if *putCall.ContentType != "application/x-jsonlines" {
		t.Errorf("Expected content type 'application/x-jsonlines', got '%s'", *putCall.ContentType)
	}

	// Verify metadata
	if putCall.Metadata["source"] != "mcp-airlock-audit" {
		t.Errorf("Expected source metadata 'mcp-airlock-audit', got '%s'", putCall.Metadata["source"])
	}

	// Verify no encryption was set
	if putCall.ServerSideEncryption != "" {
		t.Errorf("Expected no server-side encryption, got '%s'", putCall.ServerSideEncryption)
	}
}

func TestSQLiteAuditLogger_ExportToS3WithKMS(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_s3_kms_export.db")

	config := &AuditConfig{
		Backend:         "sqlite",
		Database:        dbPath,
		RetentionDays:   30,
		BatchSize:       1,
		FlushTimeout:    10 * time.Millisecond,
		CleanupInterval: time.Hour,
		S3Bucket:        "test-audit-bucket",
		S3Prefix:        "audit-logs",
		S3Region:        "us-east-1",
		KMSKeyID:        "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func(logger *SQLiteAuditLogger) {
		err := logger.Close()
		if err != nil {

		}
	}(logger)

	// Replace the S3 client with our mock
	mockS3 := &MockS3Client{}
	logger.s3Client = mockS3

	ctx := context.Background()

	// Create a test event
	event := NewAuthenticationEvent("kms-test", "user@example.com", DecisionAllow, "valid token")
	event.Tenant = "tenant-1"

	if err := logger.LogEvent(ctx, event); err != nil {
		t.Fatalf("Failed to log event: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	// Test export with KMS
	kmsKeyID := "arn:aws:kms:us-east-1:123456789012:key/test-key"
	if err := logger.ExportToS3(ctx, "test-bucket", "encrypted-logs", kmsKeyID); err != nil {
		t.Fatalf("Failed to export to S3 with KMS: %v", err)
	}

	// Verify S3 call was made with KMS encryption
	if len(mockS3.putObjectCalls) != 1 {
		t.Fatalf("Expected 1 S3 PutObject call, got %d", len(mockS3.putObjectCalls))
	}

	putCall := mockS3.putObjectCalls[0]

	// Verify KMS encryption was set
	if putCall.ServerSideEncryption != types.ServerSideEncryptionAwsKms {
		t.Errorf("Expected KMS encryption, got '%s'", putCall.ServerSideEncryption)
	}

	if *putCall.SSEKMSKeyId != kmsKeyID {
		t.Errorf("Expected KMS key ID '%s', got '%s'", kmsKeyID, *putCall.SSEKMSKeyId)
	}
}

func TestSQLiteAuditLogger_ExportToS3WithoutClient(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_s3_no_client.db")

	config := &AuditConfig{
		Backend:         "sqlite",
		Database:        dbPath,
		RetentionDays:   30,
		BatchSize:       1,
		FlushTimeout:    10 * time.Millisecond,
		CleanupInterval: time.Hour,
		// No S3 configuration - client won't be initialized
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func(logger *SQLiteAuditLogger) {
		err := logger.Close()
		if err != nil {

		}
	}(logger)

	ctx := context.Background()

	// Try to export without S3 client - should fail
	err = logger.ExportToS3(ctx, "test-bucket", "test-prefix", "")
	if err == nil {
		t.Fatal("Expected error when exporting without S3 client")
	}

	if !containsString(err.Error(), "S3 client not initialized") {
		t.Errorf("Expected 'S3 client not initialized' error, got: %v", err)
	}
}

func TestSQLiteAuditLogger_ExportToS3EmptyData(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_s3_empty.db")

	config := &AuditConfig{
		Backend:         "sqlite",
		Database:        dbPath,
		RetentionDays:   30,
		BatchSize:       1,
		FlushTimeout:    10 * time.Millisecond,
		CleanupInterval: time.Hour,
		S3Bucket:        "test-audit-bucket",
		S3Prefix:        "audit-logs",
		S3Region:        "us-east-1",
	}

	logger, err := NewSQLiteAuditLogger(config)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer func(logger *SQLiteAuditLogger) {
		err := logger.Close()
		if err != nil {

		}
	}(logger)

	// Replace the S3 client with our mock
	mockS3 := &MockS3Client{}
	logger.s3Client = mockS3

	ctx := context.Background()

	// Export without any events
	if err := logger.ExportToS3(ctx, "test-bucket", "empty-logs", ""); err != nil {
		t.Fatalf("Failed to export empty data to S3: %v", err)
	}

	// Verify S3 call was still made (with empty content)
	if len(mockS3.putObjectCalls) != 1 {
		t.Fatalf("Expected 1 S3 PutObject call, got %d", len(mockS3.putObjectCalls))
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

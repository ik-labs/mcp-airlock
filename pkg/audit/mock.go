package audit

import (
	"context"
	"io"
)

// MockAuditLogger implements AuditLogger for testing
type MockAuditLogger struct {
	events []*AuditEvent
}

// NewMockAuditLogger creates a new mock audit logger
func NewMockAuditLogger() *MockAuditLogger {
	return &MockAuditLogger{
		events: make([]*AuditEvent, 0),
	}
}

func (m *MockAuditLogger) LogEvent(ctx context.Context, event *AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *MockAuditLogger) Query(ctx context.Context, filter *QueryFilter) ([]*AuditEvent, error) {
	return m.events, nil
}

func (m *MockAuditLogger) Export(ctx context.Context, format string, writer io.Writer) error {
	return nil
}

func (m *MockAuditLogger) CleanupExpiredEvents(ctx context.Context) (int, error) {
	return 0, nil
}

func (m *MockAuditLogger) CreateTombstone(ctx context.Context, subject, reason string) error {
	return nil
}

func (m *MockAuditLogger) ExportToS3(ctx context.Context, bucket, prefix string, kmsKeyID string) error {
	return nil
}

func (m *MockAuditLogger) Close() error {
	return nil
}

func (m *MockAuditLogger) GetLastHash(ctx context.Context) (string, error) {
	return "test-hash", nil
}

func (m *MockAuditLogger) ValidateChain(ctx context.Context) error {
	return nil
}

func (m *MockAuditLogger) GetEvents() []*AuditEvent {
	return m.events
}

func (m *MockAuditLogger) Reset() {
	m.events = make([]*AuditEvent, 0)
}

package redact

import (
	"context"
	"io"
)

// Redactor interface defines the contract for data redaction
type RedactorInterface interface {
	// LoadPatterns compiles and loads redaction patterns
	LoadPatterns(patterns []Pattern) error

	// RedactRequest applies redaction patterns to request data
	RedactRequest(ctx context.Context, data []byte) (*RedactionResult, error)

	// RedactResponse applies redaction patterns to response data
	RedactResponse(ctx context.Context, data []byte) (*RedactionResult, error)

	// RedactStream applies redaction patterns to streaming data
	RedactStream(ctx context.Context, reader io.Reader, writer io.Writer) (*RedactionResult, error)

	// GetPatterns returns the currently loaded patterns
	GetPatterns() []CompiledPattern

	// Stats returns redactor statistics
	Stats() map[string]interface{}
}

// Ensure Redactor implements RedactorInterface
var _ RedactorInterface = (*Redactor)(nil)

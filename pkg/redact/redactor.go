package redact

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"
)

// Pattern represents a redaction pattern configuration
type Pattern struct {
	Name    string   `yaml:"name" json:"name"`
	Regex   string   `yaml:"regex" json:"regex"`
	Replace string   `yaml:"replace" json:"replace"`
	Fields  []string `yaml:"fields,omitempty" json:"fields,omitempty"` // for structured redaction
}

// RedactionResult contains the result of a redaction operation
type RedactionResult struct {
	Data           []byte         `json:"data"`
	RedactionCount int            `json:"redaction_count"`
	PatternsHit    map[string]int `json:"patterns_hit"`
	ProcessingTime time.Duration  `json:"processing_time"`
}

// CompiledPattern holds a compiled regex pattern with metadata
type CompiledPattern struct {
	Name    string
	Regex   *regexp.Regexp
	Replace string
	Fields  []string
}

// Redactor provides memory-efficient redaction capabilities
type Redactor struct {
	patterns []CompiledPattern
	bufPool  *sync.Pool
	mutex    sync.RWMutex
}

// NewRedactor creates a new redactor instance with buffer pooling
func NewRedactor() *Redactor {
	return &Redactor{
		patterns: make([]CompiledPattern, 0),
		bufPool: &sync.Pool{
			New: func() interface{} {
				// 64KB buffers for efficient streaming
				return make([]byte, 64*1024)
			},
		},
	}
}

// LoadPatterns compiles and loads redaction patterns
func (r *Redactor) LoadPatterns(patterns []Pattern) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	compiled := make([]CompiledPattern, 0, len(patterns))

	for _, pattern := range patterns {
		regex, err := regexp.Compile(pattern.Regex)
		if err != nil {
			return fmt.Errorf("failed to compile pattern %s: %w", pattern.Name, err)
		}

		compiled = append(compiled, CompiledPattern{
			Name:    pattern.Name,
			Regex:   regex,
			Replace: pattern.Replace,
			Fields:  pattern.Fields,
		})
	}

	r.patterns = compiled
	return nil
}

// RedactRequest applies redaction patterns to request data
func (r *Redactor) RedactRequest(ctx context.Context, data []byte) (*RedactionResult, error) {
	return r.redactData(ctx, data, "request")
}

// RedactResponse applies redaction patterns to response data
func (r *Redactor) RedactResponse(ctx context.Context, data []byte) (*RedactionResult, error) {
	return r.redactData(ctx, data, "response")
}

// RedactStream applies redaction patterns to streaming data
func (r *Redactor) RedactStream(ctx context.Context, reader io.Reader, writer io.Writer) (*RedactionResult, error) {
	start := time.Now()

	r.mutex.RLock()
	patterns := r.patterns
	r.mutex.RUnlock()

	if len(patterns) == 0 {
		// No patterns, just copy through
		_, err := io.Copy(writer, reader)
		return &RedactionResult{
			RedactionCount: 0,
			PatternsHit:    make(map[string]int),
			ProcessingTime: time.Since(start),
		}, err
	}

	// Get buffer from pool
	buf := r.bufPool.Get().([]byte)
	defer r.bufPool.Put(buf) //nolint:SA6002 // buf is a slice, this is the correct pattern for buffer pools

	scanner := bufio.NewScanner(reader)
	// Use a slice of the buffer to avoid allocations
	scanner.Buffer(buf[:0], cap(buf))

	totalRedactions := 0
	patternsHit := make(map[string]int)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		line := scanner.Bytes()
		redactedLine, redactionCount, hitPatterns := r.applyPatterns(line, patterns)

		totalRedactions += redactionCount
		for pattern, count := range hitPatterns {
			patternsHit[pattern] += count
		}

		if _, err := writer.Write(redactedLine); err != nil {
			return nil, fmt.Errorf("failed to write redacted data: %w", err)
		}

		if _, err := writer.Write([]byte("\n")); err != nil {
			return nil, fmt.Errorf("failed to write newline: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading stream: %w", err)
	}

	return &RedactionResult{
		RedactionCount: totalRedactions,
		PatternsHit:    patternsHit,
		ProcessingTime: time.Since(start),
	}, nil
}

// redactData applies redaction patterns to byte data
func (r *Redactor) redactData(ctx context.Context, data []byte, _ string) (*RedactionResult, error) {
	start := time.Now()

	r.mutex.RLock()
	patterns := r.patterns
	r.mutex.RUnlock()

	if len(patterns) == 0 {
		return &RedactionResult{
			Data:           data,
			RedactionCount: 0,
			PatternsHit:    make(map[string]int),
			ProcessingTime: time.Since(start),
		}, nil
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	redactedData, redactionCount, patternsHit := r.applyPatterns(data, patterns)

	return &RedactionResult{
		Data:           redactedData,
		RedactionCount: redactionCount,
		PatternsHit:    patternsHit,
		ProcessingTime: time.Since(start),
	}, nil
}

// applyPatterns applies all compiled patterns to the data
func (r *Redactor) applyPatterns(data []byte, patterns []CompiledPattern) ([]byte, int, map[string]int) {
	result := data
	totalRedactions := 0
	patternsHit := make(map[string]int)

	for _, pattern := range patterns {
		// Apply pattern and count matches
		matches := pattern.Regex.FindAll(result, -1)
		if len(matches) > 0 {
			result = pattern.Regex.ReplaceAll(result, []byte(pattern.Replace))
			patternsHit[pattern.Name] = len(matches)
			totalRedactions += len(matches)
		}
	}

	return result, totalRedactions, patternsHit
}

// GetPatterns returns the currently loaded patterns (for testing/debugging)
func (r *Redactor) GetPatterns() []CompiledPattern {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Return a copy to prevent external modification
	patterns := make([]CompiledPattern, len(r.patterns))
	copy(patterns, r.patterns)
	return patterns
}

// Stats returns redactor statistics
func (r *Redactor) Stats() map[string]interface{} {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	return map[string]interface{}{
		"pattern_count":    len(r.patterns),
		"buffer_pool_size": "64KB",
	}
}

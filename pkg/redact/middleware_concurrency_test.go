package redact

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestConcurrentConfigurationAccess tests that configuration can be safely accessed concurrently
func TestConcurrentConfigurationAccess(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	// Load test patterns
	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[redacted-email]",
		},
	}

	err := middleware.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, correlationIDKey, "concurrent-test")

	testData := []byte("Contact user@example.com for support")

	// Run concurrent operations
	var wg sync.WaitGroup
	numGoroutines := 50
	numOperations := 100

	// Start goroutines that read configuration and process requests
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				// Alternate between different operations
				switch j % 4 {
				case 0:
					_, err := middleware.ProcessRequest(ctx, testData)
					if err != nil {
						t.Errorf("ProcessRequest failed in goroutine %d: %v", id, err)
					}
				case 1:
					_, err := middleware.ProcessResponse(ctx, testData)
					if err != nil {
						t.Errorf("ProcessResponse failed in goroutine %d: %v", id, err)
					}
				case 2:
					_, err := middleware.RedactForLogging(ctx, testData)
					if err != nil {
						t.Errorf("RedactForLogging failed in goroutine %d: %v", id, err)
					}
				case 3:
					stats := middleware.GetStats()
					if stats == nil {
						t.Errorf("GetStats returned nil in goroutine %d", id)
					}
				}
			}
		}(i)
	}

	// Start a goroutine that periodically updates configuration
	wg.Add(1)
	go func() {
		defer wg.Done()

		for i := 0; i < 10; i++ {
			time.Sleep(10 * time.Millisecond)

			config := &MiddlewareConfig{
				Enabled:           i%2 == 0, // Toggle enabled state
				RedactRequests:    true,
				RedactResponses:   true,
				RedactBeforeLog:   i%3 == 0, // Vary this setting
				RedactBeforeProxy: true,
			}

			middleware.UpdateConfig(config)
		}
	}()

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify final state
	stats := middleware.GetStats()
	if stats == nil {
		t.Error("Final GetStats returned nil")
	}

	// Verify we can still process requests after concurrent access
	result, err := middleware.ProcessRequest(ctx, testData)
	if err != nil {
		t.Errorf("Final ProcessRequest failed: %v", err)
	}

	if result == nil {
		t.Error("Final ProcessRequest returned nil result")
	}
}

// TestConfigurationUpdateAtomicity tests that configuration updates are atomic
func TestConfigurationUpdateAtomicity(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	// Initial configuration
	initialConfig := &MiddlewareConfig{
		Enabled:           true,
		RedactRequests:    true,
		RedactResponses:   true,
		RedactBeforeLog:   true,
		RedactBeforeProxy: true,
	}
	middleware.UpdateConfig(initialConfig)

	var wg sync.WaitGroup
	numReaders := 20
	numUpdates := 50

	// Track inconsistent states
	inconsistentStates := make(chan bool, numReaders*numUpdates)

	// Start readers that check for consistent configuration states
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for j := 0; j < numUpdates; j++ {
				stats := middleware.GetStats()

				// Check for impossible states (e.g., enabled=false but redact_requests=true when we only set consistent configs)
				enabled := stats["enabled"].(bool)
				redactRequests := stats["redact_requests"].(bool)
				redactResponses := stats["redact_responses"].(bool)
				redactBeforeLog := stats["redact_before_log"].(bool)
				redactBeforeProxy := stats["redact_before_proxy"].(bool)

				// In our test, we only set configurations where if enabled=true, all redact flags are true
				// and if enabled=false, all redact flags are false
				if enabled {
					if !redactRequests || !redactResponses || !redactBeforeProxy {
						inconsistentStates <- true
						return
					}
				} else {
					if redactRequests || redactResponses || redactBeforeLog || redactBeforeProxy {
						inconsistentStates <- true
						return
					}
				}

				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	// Start updater that alternates between two consistent configurations
	wg.Add(1)
	go func() {
		defer wg.Done()

		for i := 0; i < numUpdates; i++ {
			var config *MiddlewareConfig
			if i%2 == 0 {
				config = &MiddlewareConfig{
					Enabled:           true,
					RedactRequests:    true,
					RedactResponses:   true,
					RedactBeforeLog:   true,
					RedactBeforeProxy: true,
				}
			} else {
				config = &MiddlewareConfig{
					Enabled:           false,
					RedactRequests:    false,
					RedactResponses:   false,
					RedactBeforeLog:   false,
					RedactBeforeProxy: false,
				}
			}

			middleware.UpdateConfig(config)
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// Wait for all goroutines to complete
	wg.Wait()
	close(inconsistentStates)

	// Check if any inconsistent states were detected
	for inconsistent := range inconsistentStates {
		if inconsistent {
			t.Error("Detected inconsistent configuration state during concurrent access")
			break
		}
	}
}

// TestConcurrentProcessingWithConfigChanges tests processing requests while configuration changes
func TestConcurrentProcessingWithConfigChanges(t *testing.T) {
	redactor := NewRedactor()
	logger := zap.NewNop()
	middleware := NewRedactionMiddleware(redactor, logger, nil)

	// Load test patterns
	patterns := []Pattern{
		{
			Name:    "email",
			Regex:   `(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}`,
			Replace: "[redacted-email]",
		},
	}

	err := middleware.LoadPatterns(patterns)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, correlationIDKey, "processing-test")

	testData := []byte("Contact user@example.com for support")

	var wg sync.WaitGroup
	numProcessors := 10
	numRequests := 100
	processingErrors := make(chan error, numProcessors*numRequests)

	// Start processors
	for i := 0; i < numProcessors; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numRequests; j++ {
				result, err := middleware.ProcessRequest(ctx, testData)
				if err != nil {
					processingErrors <- err
					return
				}

				// Verify result is not nil
				if result == nil {
					processingErrors <- fmt.Errorf("ProcessRequest returned nil result in processor %d", id)
					return
				}

				time.Sleep(1 * time.Millisecond)
			}
		}(i)
	}

	// Start configuration updater
	wg.Add(1)
	go func() {
		defer wg.Done()

		for i := 0; i < 20; i++ {
			config := &MiddlewareConfig{
				Enabled:           i%3 != 0, // Mostly enabled, occasionally disabled
				RedactRequests:    true,
				RedactResponses:   true,
				RedactBeforeLog:   i%2 == 0,
				RedactBeforeProxy: true,
			}

			middleware.UpdateConfig(config)
			time.Sleep(5 * time.Millisecond)
		}
	}()

	// Wait for all goroutines to complete
	wg.Wait()
	close(processingErrors)

	// Check for any processing errors
	for err := range processingErrors {
		t.Errorf("Processing error during concurrent access: %v", err)
	}
}

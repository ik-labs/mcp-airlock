package errors

import (
	"context"
	"testing"
	"time"
)

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	if config.MaxAttempts != 3 {
		t.Errorf("expected MaxAttempts 3, got %d", config.MaxAttempts)
	}

	if config.InitialDelay != 100*time.Millisecond {
		t.Errorf("expected InitialDelay 100ms, got %v", config.InitialDelay)
	}

	if config.MaxDelay != 5*time.Second {
		t.Errorf("expected MaxDelay 5s, got %v", config.MaxDelay)
	}

	if config.Multiplier != 2.0 {
		t.Errorf("expected Multiplier 2.0, got %f", config.Multiplier)
	}

	if config.JitterPercent != 0.1 {
		t.Errorf("expected JitterPercent 0.1, got %f", config.JitterPercent)
	}
}

func TestRetrySuccess(t *testing.T) {
	config := &RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  10 * time.Millisecond,
		MaxDelay:      100 * time.Millisecond,
		Multiplier:    2.0,
		JitterPercent: 0,
	}

	attempts := 0
	fn := func(ctx context.Context) error {
		attempts++
		if attempts < 2 {
			return NewUpstreamFailureError(502, "test")
		}
		return nil
	}

	ctx := context.Background()
	result := Retry(ctx, config, fn)

	if result.Attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", result.Attempts)
	}

	if result.LastError != nil {
		t.Errorf("expected no error, got %v", result.LastError)
	}

	if attempts != 2 {
		t.Errorf("expected function called 2 times, got %d", attempts)
	}
}

func TestRetryMaxAttemptsReached(t *testing.T) {
	config := &RetryConfig{
		MaxAttempts:   2,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      10 * time.Millisecond,
		Multiplier:    2.0,
		JitterPercent: 0,
	}

	attempts := 0
	expectedErr := NewUpstreamFailureError(502, "test")
	fn := func(ctx context.Context) error {
		attempts++
		return expectedErr
	}

	ctx := context.Background()
	result := Retry(ctx, config, fn)

	if result.Attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", result.Attempts)
	}

	if result.LastError != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, result.LastError)
	}

	if attempts != 2 {
		t.Errorf("expected function called 2 times, got %d", attempts)
	}
}

func TestRetryNonRetryableError(t *testing.T) {
	config := &RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  10 * time.Millisecond,
		MaxDelay:      100 * time.Millisecond,
		Multiplier:    2.0,
		JitterPercent: 0,
	}

	attempts := 0
	expectedErr := NewAuthenticationError("invalid token", "test")
	fn := func(ctx context.Context) error {
		attempts++
		return expectedErr
	}

	ctx := context.Background()
	result := Retry(ctx, config, fn)

	if result.Attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", result.Attempts)
	}

	if result.LastError != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, result.LastError)
	}

	if attempts != 1 {
		t.Errorf("expected function called 1 time, got %d", attempts)
	}
}

func TestRetryContextCancellation(t *testing.T) {
	config := &RetryConfig{
		MaxAttempts:   5,
		InitialDelay:  50 * time.Millisecond,
		MaxDelay:      200 * time.Millisecond,
		Multiplier:    2.0,
		JitterPercent: 0,
	}

	attempts := 0
	fn := func(ctx context.Context) error {
		attempts++
		return NewUpstreamFailureError(502, "test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()

	result := Retry(ctx, config, fn)

	// Should have attempted at least once, but not all 5 attempts
	if result.Attempts == 0 {
		t.Error("expected at least 1 attempt")
	}

	if result.Attempts >= 5 {
		t.Errorf("expected fewer than 5 attempts due to timeout, got %d", result.Attempts)
	}

	if result.LastError != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got %v", result.LastError)
	}
}

func TestCalculateDelay(t *testing.T) {
	config := &RetryConfig{
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      1 * time.Second,
		Multiplier:    2.0,
		JitterPercent: 0, // No jitter for predictable testing
	}

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{5, 1 * time.Second}, // Capped at MaxDelay
		{6, 1 * time.Second}, // Still capped
	}

	for _, tt := range tests {
		t.Run("attempt_"+string(rune(tt.attempt+'0')), func(t *testing.T) {
			delay := config.calculateDelay(tt.attempt)
			if delay != tt.expected {
				t.Errorf("attempt %d: expected delay %v, got %v", tt.attempt, tt.expected, delay)
			}
		})
	}
}

func TestCalculateDelayWithJitter(t *testing.T) {
	config := &RetryConfig{
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      1 * time.Second,
		Multiplier:    2.0,
		JitterPercent: 0.1, // 10% jitter
	}

	baseDelay := 100 * time.Millisecond
	delay := config.calculateDelay(1)

	// With 10% jitter, delay should be within ±10% of base delay
	minDelay := time.Duration(float64(baseDelay) * 0.9)
	maxDelay := time.Duration(float64(baseDelay) * 1.1)

	if delay < minDelay || delay > maxDelay {
		t.Errorf("delay %v not within jitter range [%v, %v]", delay, minDelay, maxDelay)
	}
}

func TestDefaultCircuitBreakerConfig(t *testing.T) {
	config := DefaultCircuitBreakerConfig()

	if config.MaxFailures != 5 {
		t.Errorf("expected MaxFailures 5, got %d", config.MaxFailures)
	}

	if config.ResetTimeout != 30*time.Second {
		t.Errorf("expected ResetTimeout 30s, got %v", config.ResetTimeout)
	}

	if config.HalfOpenMax != 3 {
		t.Errorf("expected HalfOpenMax 3, got %d", config.HalfOpenMax)
	}

	if config.FailureWindow != 60*time.Second {
		t.Errorf("expected FailureWindow 60s, got %v", config.FailureWindow)
	}
}

func TestCircuitBreakerStates(t *testing.T) {
	tests := []struct {
		state    CircuitState
		expected string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
		{CircuitState(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.state.String()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestCircuitBreakerBasicOperation(t *testing.T) {
	config := &CircuitBreakerConfig{
		MaxFailures:   2,
		ResetTimeout:  100 * time.Millisecond,
		HalfOpenMax:   1,
		FailureWindow: 1 * time.Second,
	}

	cb := NewCircuitBreaker(config)

	// Initially closed
	if cb.GetState() != CircuitClosed {
		t.Errorf("expected initial state closed, got %v", cb.GetState())
	}

	// First failure
	err1 := NewUpstreamFailureError(502, "test")
	err := cb.Execute(context.Background(), func(ctx context.Context) error {
		return err1
	})

	if err != err1 {
		t.Errorf("expected error %v, got %v", err1, err)
	}

	if cb.GetState() != CircuitClosed {
		t.Errorf("expected state closed after 1 failure, got %v", cb.GetState())
	}

	if cb.GetFailures() != 1 {
		t.Errorf("expected 1 failure, got %d", cb.GetFailures())
	}

	// Second failure - should open circuit
	err2 := NewUpstreamFailureError(503, "test")
	err = cb.Execute(context.Background(), func(ctx context.Context) error {
		return err2
	})

	if err != err2 {
		t.Errorf("expected error %v, got %v", err2, err)
	}

	if cb.GetState() != CircuitOpen {
		t.Errorf("expected state open after 2 failures, got %v", cb.GetState())
	}

	// Third attempt should fail immediately with circuit open error
	err = cb.Execute(context.Background(), func(ctx context.Context) error {
		t.Error("function should not be called when circuit is open")
		return nil
	})

	if !IsServerError(err) {
		t.Errorf("expected server error when circuit is open, got %v", err)
	}

	// Wait for reset timeout
	time.Sleep(150 * time.Millisecond)

	// Should transition to half-open and allow one attempt
	err = cb.Execute(context.Background(), func(ctx context.Context) error {
		return nil // Success
	})

	if err != nil {
		t.Errorf("expected no error after reset timeout, got %v", err)
	}

	if cb.GetState() != CircuitClosed {
		t.Errorf("expected state closed after successful attempt, got %v", cb.GetState())
	}

	if cb.GetFailures() != 0 {
		t.Errorf("expected 0 failures after reset, got %d", cb.GetFailures())
	}
}

func TestCircuitBreakerNonRetryableErrors(t *testing.T) {
	config := &CircuitBreakerConfig{
		MaxFailures:   2,
		ResetTimeout:  100 * time.Millisecond,
		HalfOpenMax:   1,
		FailureWindow: 1 * time.Second,
	}

	cb := NewCircuitBreaker(config)

	// Non-retryable error should not count as failure
	authErr := NewAuthenticationError("invalid token", "test")
	err := cb.Execute(context.Background(), func(ctx context.Context) error {
		return authErr
	})

	if err != authErr {
		t.Errorf("expected error %v, got %v", authErr, err)
	}

	if cb.GetState() != CircuitClosed {
		t.Errorf("expected state closed after non-retryable error, got %v", cb.GetState())
	}

	if cb.GetFailures() != 0 {
		t.Errorf("expected 0 failures after non-retryable error, got %d", cb.GetFailures())
	}
}

func TestCircuitBreakerReset(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker(config)

	// Force some failures
	for i := 0; i < config.MaxFailures; i++ {
		cb.recordResult(NewUpstreamFailureError(502, "test"))
	}

	if cb.GetState() != CircuitOpen {
		t.Errorf("expected state open after max failures, got %v", cb.GetState())
	}

	// Manual reset
	cb.Reset()

	if cb.GetState() != CircuitClosed {
		t.Errorf("expected state closed after reset, got %v", cb.GetState())
	}

	if cb.GetFailures() != 0 {
		t.Errorf("expected 0 failures after reset, got %d", cb.GetFailures())
	}
}

func TestRetryWithCircuitBreaker(t *testing.T) {
	retryConfig := &RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  1 * time.Millisecond,
		MaxDelay:      10 * time.Millisecond,
		Multiplier:    2.0,
		JitterPercent: 0,
	}

	cbConfig := &CircuitBreakerConfig{
		MaxFailures:   2,
		ResetTimeout:  100 * time.Millisecond,
		HalfOpenMax:   1,
		FailureWindow: 1 * time.Second,
	}

	attempts := 0
	fn := func(ctx context.Context) error {
		attempts++
		return NewUpstreamFailureError(502, "test")
	}

	ctx := context.Background()
	result, err := RetryWithCircuitBreaker(ctx, retryConfig, cbConfig, fn)

	// Should have attempted multiple times before circuit opened
	if result.Attempts == 0 {
		t.Error("expected at least 1 attempt")
	}

	// Should eventually get circuit breaker error
	if err == nil {
		t.Error("expected circuit breaker error")
	}

	if !IsServerError(err) {
		t.Errorf("expected server error, got %v", err)
	}
}

func TestExponentialBackoff(t *testing.T) {
	eb := &ExponentialBackoff{
		Multiplier:    2.0,
		MaxDelay:      1 * time.Second,
		JitterPercent: 0,
	}

	baseDelay := 100 * time.Millisecond

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{5, 1 * time.Second}, // Capped at MaxDelay
	}

	for _, tt := range tests {
		t.Run("attempt_"+string(rune(tt.attempt+'0')), func(t *testing.T) {
			delay := eb.Calculate(tt.attempt, baseDelay)
			if delay != tt.expected {
				t.Errorf("attempt %d: expected delay %v, got %v", tt.attempt, tt.expected, delay)
			}
		})
	}
}

func TestLinearBackoff(t *testing.T) {
	lb := &LinearBackoff{
		Increment:     50 * time.Millisecond,
		MaxDelay:      300 * time.Millisecond,
		JitterPercent: 0,
	}

	baseDelay := 100 * time.Millisecond

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 150 * time.Millisecond},
		{3, 200 * time.Millisecond},
		{4, 250 * time.Millisecond},
		{5, 300 * time.Millisecond}, // Capped at MaxDelay
		{6, 300 * time.Millisecond}, // Still capped
	}

	for _, tt := range tests {
		t.Run("attempt_"+string(rune(tt.attempt+'0')), func(t *testing.T) {
			delay := lb.Calculate(tt.attempt, baseDelay)
			if delay != tt.expected {
				t.Errorf("attempt %d: expected delay %v, got %v", tt.attempt, tt.expected, delay)
			}
		})
	}
}

// Benchmark tests
func BenchmarkRetrySuccess(b *testing.B) {
	config := DefaultRetryConfig()
	fn := func(ctx context.Context) error {
		return nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		Retry(ctx, config, fn)
	}
}

func BenchmarkRetryWithFailures(b *testing.B) {
	config := &RetryConfig{
		MaxAttempts:   2,
		InitialDelay:  1 * time.Microsecond,
		MaxDelay:      10 * time.Microsecond,
		Multiplier:    2.0,
		JitterPercent: 0,
	}

	fn := func(ctx context.Context) error {
		return NewUpstreamFailureError(502, "test")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		Retry(ctx, config, fn)
	}
}

func BenchmarkCircuitBreakerExecute(b *testing.B) {
	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig())
	fn := func(ctx context.Context) error {
		return nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		cb.Execute(ctx, fn)
	}
}

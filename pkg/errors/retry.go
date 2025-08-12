// Package errors provides retry and backoff logic for upstream failures
package errors

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"
)

// RetryConfig defines configuration for retry behavior
type RetryConfig struct {
	MaxAttempts   int           `yaml:"max_attempts" json:"max_attempts"`
	InitialDelay  time.Duration `yaml:"initial_delay" json:"initial_delay"`
	MaxDelay      time.Duration `yaml:"max_delay" json:"max_delay"`
	Multiplier    float64       `yaml:"multiplier" json:"multiplier"`
	JitterPercent float64       `yaml:"jitter_percent" json:"jitter_percent"`
}

// DefaultRetryConfig returns a default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      5 * time.Second,
		Multiplier:    2.0,
		JitterPercent: 0.1, // 10% jitter
	}
}

// RetryableFunc is a function that can be retried
type RetryableFunc func(ctx context.Context) error

// RetryResult contains the result of a retry operation
type RetryResult struct {
	Attempts  int
	LastError error
	Duration  time.Duration
}

// Retry executes a function with exponential backoff retry logic
func Retry(ctx context.Context, config *RetryConfig, fn RetryableFunc) *RetryResult {
	if config == nil {
		config = DefaultRetryConfig()
	}

	startTime := time.Now()
	var lastError error

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		// Check context cancellation before each attempt
		select {
		case <-ctx.Done():
			return &RetryResult{
				Attempts:  attempt - 1,
				LastError: ctx.Err(),
				Duration:  time.Since(startTime),
			}
		default:
		}

		// Execute the function
		err := fn(ctx)
		if err == nil {
			// Success
			return &RetryResult{
				Attempts:  attempt,
				LastError: nil,
				Duration:  time.Since(startTime),
			}
		}

		lastError = err

		// Don't retry on client errors (4xx) or non-retryable errors
		if !IsRetryableError(err) {
			return &RetryResult{
				Attempts:  attempt,
				LastError: err,
				Duration:  time.Since(startTime),
			}
		}

		// Don't sleep after the last attempt
		if attempt == config.MaxAttempts {
			break
		}

		// Calculate delay with exponential backoff and jitter
		delay := config.calculateDelay(attempt)

		// Sleep with context cancellation support
		select {
		case <-ctx.Done():
			return &RetryResult{
				Attempts:  attempt,
				LastError: ctx.Err(),
				Duration:  time.Since(startTime),
			}
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return &RetryResult{
		Attempts:  config.MaxAttempts,
		LastError: lastError,
		Duration:  time.Since(startTime),
	}
}

// calculateDelay calculates the delay for the given attempt with exponential backoff and jitter
func (c *RetryConfig) calculateDelay(attempt int) time.Duration {
	// Exponential backoff: delay = initial_delay * multiplier^(attempt-1)
	delay := float64(c.InitialDelay) * math.Pow(c.Multiplier, float64(attempt-1))

	// Cap at max delay
	if delay > float64(c.MaxDelay) {
		delay = float64(c.MaxDelay)
	}

	// Add jitter to prevent thundering herd
	if c.JitterPercent > 0 {
		jitter := delay * c.JitterPercent * (rand.Float64()*2 - 1) // ±jitter_percent
		delay += jitter
	}

	// Ensure delay is not negative
	if delay < 0 {
		delay = float64(c.InitialDelay)
	}

	return time.Duration(delay)
}

// RetryWithCircuitBreaker combines retry logic with circuit breaker pattern
type CircuitBreaker struct {
	config       *CircuitBreakerConfig
	state        CircuitState
	failures     int
	lastFailTime time.Time
	nextRetry    time.Time
}

// CircuitBreakerConfig defines circuit breaker configuration
type CircuitBreakerConfig struct {
	MaxFailures   int           `yaml:"max_failures" json:"max_failures"`
	ResetTimeout  time.Duration `yaml:"reset_timeout" json:"reset_timeout"`
	HalfOpenMax   int           `yaml:"half_open_max" json:"half_open_max"`
	FailureWindow time.Duration `yaml:"failure_window" json:"failure_window"`
}

// CircuitState represents the state of a circuit breaker
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// String returns the string representation of the circuit state
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// DefaultCircuitBreakerConfig returns a default circuit breaker configuration
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		MaxFailures:   5,
		ResetTimeout:  30 * time.Second,
		HalfOpenMax:   3,
		FailureWindow: 60 * time.Second,
	}
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}

	return &CircuitBreaker{
		config: config,
		state:  CircuitClosed,
	}
}

// Execute executes a function through the circuit breaker
func (cb *CircuitBreaker) Execute(ctx context.Context, fn RetryableFunc) error {
	// Check if circuit is open
	if cb.state == CircuitOpen {
		if time.Now().Before(cb.nextRetry) {
			correlationID := getCorrelationID(ctx)
			retryAfter := time.Until(cb.nextRetry)
			return NewCircuitOpenError(retryAfter, correlationID)
		}
		// Transition to half-open
		cb.state = CircuitHalfOpen
	}

	// Execute the function
	err := fn(ctx)

	// Update circuit breaker state based on result
	cb.recordResult(err)

	return err
}

// recordResult updates the circuit breaker state based on the execution result
func (cb *CircuitBreaker) recordResult(err error) {
	now := time.Now()

	if err == nil {
		// Success - reset failure count and close circuit
		cb.failures = 0
		cb.state = CircuitClosed
		return
	}

	// Only count retryable errors as failures
	if !IsRetryableError(err) {
		return
	}

	// Record failure
	cb.failures++
	cb.lastFailTime = now

	// Check if we should open the circuit
	if cb.failures >= cb.config.MaxFailures {
		cb.state = CircuitOpen
		cb.nextRetry = now.Add(cb.config.ResetTimeout)
	}
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() CircuitState {
	return cb.state
}

// GetFailures returns the current failure count
func (cb *CircuitBreaker) GetFailures() int {
	return cb.failures
}

// Reset manually resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.state = CircuitClosed
	cb.failures = 0
	cb.lastFailTime = time.Time{}
	cb.nextRetry = time.Time{}
}

// RetryWithCircuitBreaker combines retry logic with circuit breaker
func RetryWithCircuitBreaker(ctx context.Context, retryConfig *RetryConfig, cbConfig *CircuitBreakerConfig, fn RetryableFunc) (*RetryResult, error) {
	cb := NewCircuitBreaker(cbConfig)

	wrappedFn := func(ctx context.Context) error {
		return cb.Execute(ctx, fn)
	}

	result := Retry(ctx, retryConfig, wrappedFn)

	// If circuit is open, return circuit breaker error
	if cb.GetState() == CircuitOpen {
		correlationID := getCorrelationID(ctx)
		retryAfter := time.Until(cb.nextRetry)
		circuitErr := NewCircuitOpenError(retryAfter, correlationID)
		return result, circuitErr
	}

	return result, result.LastError
}

// BackoffCalculator provides different backoff strategies
type BackoffCalculator interface {
	Calculate(attempt int, baseDelay time.Duration) time.Duration
}

// ExponentialBackoff implements exponential backoff strategy
type ExponentialBackoff struct {
	Multiplier    float64
	MaxDelay      time.Duration
	JitterPercent float64
}

// Calculate implements BackoffCalculator
func (eb *ExponentialBackoff) Calculate(attempt int, baseDelay time.Duration) time.Duration {
	delay := float64(baseDelay) * math.Pow(eb.Multiplier, float64(attempt-1))

	if delay > float64(eb.MaxDelay) {
		delay = float64(eb.MaxDelay)
	}

	// Add jitter
	if eb.JitterPercent > 0 {
		jitter := delay * eb.JitterPercent * (rand.Float64()*2 - 1)
		delay += jitter
	}

	if delay < 0 {
		delay = float64(baseDelay)
	}

	return time.Duration(delay)
}

// LinearBackoff implements linear backoff strategy
type LinearBackoff struct {
	Increment     time.Duration
	MaxDelay      time.Duration
	JitterPercent float64
}

// Calculate implements BackoffCalculator
func (lb *LinearBackoff) Calculate(attempt int, baseDelay time.Duration) time.Duration {
	delay := float64(baseDelay) + float64(lb.Increment)*float64(attempt-1)

	if delay > float64(lb.MaxDelay) {
		delay = float64(lb.MaxDelay)
	}

	// Add jitter
	if lb.JitterPercent > 0 {
		jitter := delay * lb.JitterPercent * (rand.Float64()*2 - 1)
		delay += jitter
	}

	if delay < 0 {
		delay = float64(baseDelay)
	}

	return time.Duration(delay)
}

// RetryStats provides statistics about retry operations
type RetryStats struct {
	TotalAttempts     int64
	SuccessfulRetries int64
	FailedRetries     int64
	AverageAttempts   float64
	TotalDuration     time.Duration
}

// String returns a string representation of retry stats
func (rs *RetryStats) String() string {
	return fmt.Sprintf("RetryStats{Total: %d, Success: %d, Failed: %d, AvgAttempts: %.2f, Duration: %v}",
		rs.TotalAttempts, rs.SuccessfulRetries, rs.FailedRetries, rs.AverageAttempts, rs.TotalDuration)
}

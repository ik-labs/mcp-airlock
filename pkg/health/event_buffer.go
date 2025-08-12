package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// EventBuffer implements BufferedEventHandler for audit store failures
type EventBuffer struct {
	events    []interface{}
	maxSize   int
	mutex     sync.RWMutex
	logger    *zap.Logger
	flushFunc func(ctx context.Context, events []interface{}) error
}

// NewEventBuffer creates a new event buffer with the specified maximum size
func NewEventBuffer(maxSize int, logger *zap.Logger, flushFunc func(ctx context.Context, events []interface{}) error) *EventBuffer {
	return &EventBuffer{
		events:    make([]interface{}, 0),
		maxSize:   maxSize,
		logger:    logger,
		flushFunc: flushFunc,
	}
}

// BufferEvent adds an event to the buffer
func (eb *EventBuffer) BufferEvent(event interface{}) error {
	eb.mutex.Lock()
	defer eb.mutex.Unlock()

	// Check if buffer is full
	if len(eb.events) >= eb.maxSize {
		// Drop oldest event to make room (FIFO)
		eb.events = eb.events[1:]
		eb.logger.Warn("Event buffer full, dropping oldest event",
			zap.Int("buffer_size", eb.maxSize),
		)
	}

	eb.events = append(eb.events, event)

	eb.logger.Debug("Event buffered",
		zap.Int("buffer_count", len(eb.events)),
		zap.Int("buffer_max", eb.maxSize),
	)

	return nil
}

// FlushBufferedEvents attempts to flush all buffered events
func (eb *EventBuffer) FlushBufferedEvents(ctx context.Context) error {
	eb.mutex.Lock()
	defer eb.mutex.Unlock()

	if len(eb.events) == 0 {
		return nil
	}

	if eb.flushFunc == nil {
		return fmt.Errorf("no flush function configured")
	}

	// Create a copy of events to flush
	eventsToFlush := make([]interface{}, len(eb.events))
	copy(eventsToFlush, eb.events)

	// Try to flush events
	err := eb.flushFunc(ctx, eventsToFlush)
	if err != nil {
		eb.logger.Error("Failed to flush buffered events",
			zap.Error(err),
			zap.Int("event_count", len(eventsToFlush)),
		)
		return fmt.Errorf("failed to flush buffered events: %w", err)
	}

	// Clear buffer on successful flush
	eb.events = eb.events[:0]

	eb.logger.Info("Successfully flushed buffered events",
		zap.Int("event_count", len(eventsToFlush)),
	)

	return nil
}

// GetBufferedEventCount returns the number of currently buffered events
func (eb *EventBuffer) GetBufferedEventCount() int {
	eb.mutex.RLock()
	defer eb.mutex.RUnlock()
	return len(eb.events)
}

// GetBufferedEvents returns a copy of all buffered events
func (eb *EventBuffer) GetBufferedEvents() []interface{} {
	eb.mutex.RLock()
	defer eb.mutex.RUnlock()

	events := make([]interface{}, len(eb.events))
	copy(events, eb.events)
	return events
}

// Clear removes all buffered events
func (eb *EventBuffer) Clear() {
	eb.mutex.Lock()
	defer eb.mutex.Unlock()

	eventCount := len(eb.events)
	eb.events = eb.events[:0]

	if eventCount > 0 {
		eb.logger.Info("Cleared event buffer",
			zap.Int("cleared_events", eventCount),
		)
	}
}

// IsFull returns true if the buffer is at maximum capacity
func (eb *EventBuffer) IsFull() bool {
	eb.mutex.RLock()
	defer eb.mutex.RUnlock()
	return len(eb.events) >= eb.maxSize
}

// GetCapacity returns the maximum buffer capacity
func (eb *EventBuffer) GetCapacity() int {
	return eb.maxSize
}

// GetUsagePercent returns the buffer usage as a percentage
func (eb *EventBuffer) GetUsagePercent() float64 {
	eb.mutex.RLock()
	defer eb.mutex.RUnlock()

	if eb.maxSize == 0 {
		return 0
	}

	return float64(len(eb.events)) / float64(eb.maxSize) * 100
}

// PeriodicFlushManager manages periodic attempts to flush buffered events
type PeriodicFlushManager struct {
	buffer   *EventBuffer
	interval time.Duration
	logger   *zap.Logger
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
}

// NewPeriodicFlushManager creates a new periodic flush manager
func NewPeriodicFlushManager(buffer *EventBuffer, interval time.Duration, logger *zap.Logger) *PeriodicFlushManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &PeriodicFlushManager{
		buffer:   buffer,
		interval: interval,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
}

// Start begins periodic flush attempts
func (pfm *PeriodicFlushManager) Start() {
	go pfm.run()
}

// Stop stops the periodic flush manager
func (pfm *PeriodicFlushManager) Stop() {
	pfm.cancel()
	<-pfm.done
}

// run executes the periodic flush loop
func (pfm *PeriodicFlushManager) run() {
	defer close(pfm.done)

	ticker := time.NewTicker(pfm.interval)
	defer ticker.Stop()

	pfm.logger.Info("Starting periodic event buffer flush",
		zap.Duration("interval", pfm.interval),
	)

	for {
		select {
		case <-ticker.C:
			if pfm.buffer.GetBufferedEventCount() > 0 {
				pfm.logger.Debug("Attempting periodic flush of buffered events",
					zap.Int("buffered_count", pfm.buffer.GetBufferedEventCount()),
				)

				flushCtx, cancel := context.WithTimeout(pfm.ctx, 30*time.Second)
				err := pfm.buffer.FlushBufferedEvents(flushCtx)
				cancel()

				if err != nil {
					pfm.logger.Warn("Periodic flush failed, events remain buffered",
						zap.Error(err),
						zap.Int("buffered_count", pfm.buffer.GetBufferedEventCount()),
					)
				}
			}

		case <-pfm.ctx.Done():
			pfm.logger.Info("Stopping periodic event buffer flush")
			return
		}
	}
}

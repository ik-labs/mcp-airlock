package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

func TestEventBuffer_BufferEvent(t *testing.T) {
	logger := zaptest.NewLogger(t)
	flushFunc := func(ctx context.Context, events []interface{}) error {
		return nil
	}

	eb := NewEventBuffer(3, logger, flushFunc)

	// Test buffering events
	err := eb.BufferEvent("event1")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if eb.GetBufferedEventCount() != 1 {
		t.Errorf("Expected 1 buffered event, got %d", eb.GetBufferedEventCount())
	}

	// Buffer more events
	eb.BufferEvent("event2")
	eb.BufferEvent("event3")

	if eb.GetBufferedEventCount() != 3 {
		t.Errorf("Expected 3 buffered events, got %d", eb.GetBufferedEventCount())
	}

	// Test buffer overflow (should drop oldest)
	eb.BufferEvent("event4")

	if eb.GetBufferedEventCount() != 3 {
		t.Errorf("Expected 3 buffered events after overflow, got %d", eb.GetBufferedEventCount())
	}

	// Verify FIFO behavior
	events := eb.GetBufferedEvents()
	if len(events) != 3 {
		t.Errorf("Expected 3 events, got %d", len(events))
	}

	// Should have event2, event3, event4 (event1 dropped)
	expected := []interface{}{"event2", "event3", "event4"}
	for i, event := range events {
		if event != expected[i] {
			t.Errorf("Expected event %v at index %d, got %v", expected[i], i, event)
		}
	}
}

func TestEventBuffer_FlushBufferedEvents(t *testing.T) {
	logger := zaptest.NewLogger(t)
	var flushedEvents []interface{}

	flushFunc := func(ctx context.Context, events []interface{}) error {
		flushedEvents = make([]interface{}, len(events))
		copy(flushedEvents, events)
		return nil
	}

	eb := NewEventBuffer(5, logger, flushFunc)

	// Buffer some events
	eb.BufferEvent("event1")
	eb.BufferEvent("event2")
	eb.BufferEvent("event3")

	// Flush events
	ctx := context.Background()
	err := eb.FlushBufferedEvents(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Check that events were flushed
	if len(flushedEvents) != 3 {
		t.Errorf("Expected 3 flushed events, got %d", len(flushedEvents))
	}

	// Check that buffer is empty after flush
	if eb.GetBufferedEventCount() != 0 {
		t.Errorf("Expected 0 buffered events after flush, got %d", eb.GetBufferedEventCount())
	}

	// Verify flushed events
	expected := []interface{}{"event1", "event2", "event3"}
	for i, event := range flushedEvents {
		if event != expected[i] {
			t.Errorf("Expected flushed event %v at index %d, got %v", expected[i], i, event)
		}
	}
}

func TestEventBuffer_FlushBufferedEvents_Error(t *testing.T) {
	logger := zaptest.NewLogger(t)
	flushError := errors.New("flush failed")

	flushFunc := func(ctx context.Context, events []interface{}) error {
		return flushError
	}

	eb := NewEventBuffer(5, logger, flushFunc)

	// Buffer some events
	eb.BufferEvent("event1")
	eb.BufferEvent("event2")

	// Attempt to flush (should fail)
	ctx := context.Background()
	err := eb.FlushBufferedEvents(ctx)
	if err == nil {
		t.Error("Expected flush error, got nil")
	}

	// Events should still be buffered after failed flush
	if eb.GetBufferedEventCount() != 2 {
		t.Errorf("Expected 2 buffered events after failed flush, got %d", eb.GetBufferedEventCount())
	}
}

func TestEventBuffer_FlushBufferedEvents_NoFlushFunc(t *testing.T) {
	logger := zaptest.NewLogger(t)
	eb := NewEventBuffer(5, logger, nil)

	eb.BufferEvent("event1")

	ctx := context.Background()
	err := eb.FlushBufferedEvents(ctx)
	if err == nil {
		t.Error("Expected error when no flush function configured, got nil")
	}
}

func TestEventBuffer_Clear(t *testing.T) {
	logger := zaptest.NewLogger(t)
	flushFunc := func(ctx context.Context, events []interface{}) error {
		return nil
	}

	eb := NewEventBuffer(5, logger, flushFunc)

	// Buffer some events
	eb.BufferEvent("event1")
	eb.BufferEvent("event2")
	eb.BufferEvent("event3")

	if eb.GetBufferedEventCount() != 3 {
		t.Errorf("Expected 3 buffered events, got %d", eb.GetBufferedEventCount())
	}

	// Clear buffer
	eb.Clear()

	if eb.GetBufferedEventCount() != 0 {
		t.Errorf("Expected 0 buffered events after clear, got %d", eb.GetBufferedEventCount())
	}
}

func TestEventBuffer_IsFull(t *testing.T) {
	logger := zaptest.NewLogger(t)
	flushFunc := func(ctx context.Context, events []interface{}) error {
		return nil
	}

	eb := NewEventBuffer(2, logger, flushFunc)

	if eb.IsFull() {
		t.Error("Expected buffer not to be full initially")
	}

	eb.BufferEvent("event1")
	if eb.IsFull() {
		t.Error("Expected buffer not to be full with 1 event")
	}

	eb.BufferEvent("event2")
	if !eb.IsFull() {
		t.Error("Expected buffer to be full with 2 events")
	}
}

func TestEventBuffer_GetUsagePercent(t *testing.T) {
	logger := zaptest.NewLogger(t)
	flushFunc := func(ctx context.Context, events []interface{}) error {
		return nil
	}

	eb := NewEventBuffer(4, logger, flushFunc)

	if eb.GetUsagePercent() != 0 {
		t.Errorf("Expected 0%% usage initially, got %.1f%%", eb.GetUsagePercent())
	}

	eb.BufferEvent("event1")
	if eb.GetUsagePercent() != 25.0 {
		t.Errorf("Expected 25%% usage with 1/4 events, got %.1f%%", eb.GetUsagePercent())
	}

	eb.BufferEvent("event2")
	if eb.GetUsagePercent() != 50.0 {
		t.Errorf("Expected 50%% usage with 2/4 events, got %.1f%%", eb.GetUsagePercent())
	}

	eb.BufferEvent("event3")
	eb.BufferEvent("event4")
	if eb.GetUsagePercent() != 100.0 {
		t.Errorf("Expected 100%% usage with 4/4 events, got %.1f%%", eb.GetUsagePercent())
	}
}

func TestPeriodicFlushManager(t *testing.T) {
	logger := zaptest.NewLogger(t)
	flushCount := 0

	flushFunc := func(ctx context.Context, events []interface{}) error {
		flushCount++
		return nil
	}

	eb := NewEventBuffer(5, logger, flushFunc)
	pfm := NewPeriodicFlushManager(eb, 50*time.Millisecond, logger)

	// Buffer some events
	eb.BufferEvent("event1")
	eb.BufferEvent("event2")

	// Start periodic flush manager
	pfm.Start()

	// Wait for at least one flush cycle
	time.Sleep(100 * time.Millisecond)

	// Stop the manager
	pfm.Stop()

	// Should have flushed at least once
	if flushCount == 0 {
		t.Error("Expected at least one flush, got 0")
	}

	// Buffer should be empty after flush
	if eb.GetBufferedEventCount() != 0 {
		t.Errorf("Expected 0 buffered events after flush, got %d", eb.GetBufferedEventCount())
	}
}

func TestPeriodicFlushManager_NoEventsToFlush(t *testing.T) {
	logger := zaptest.NewLogger(t)
	flushCount := 0

	flushFunc := func(ctx context.Context, events []interface{}) error {
		flushCount++
		return nil
	}

	eb := NewEventBuffer(5, logger, flushFunc)
	pfm := NewPeriodicFlushManager(eb, 50*time.Millisecond, logger)

	// Start periodic flush manager without buffering events
	pfm.Start()

	// Wait for potential flush cycles
	time.Sleep(100 * time.Millisecond)

	// Stop the manager
	pfm.Stop()

	// Should not have flushed since no events were buffered
	if flushCount != 0 {
		t.Errorf("Expected 0 flushes with no events, got %d", flushCount)
	}
}

func TestPeriodicFlushManager_FlushError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	flushError := errors.New("flush failed")

	flushFunc := func(ctx context.Context, events []interface{}) error {
		return flushError
	}

	eb := NewEventBuffer(5, logger, flushFunc)
	pfm := NewPeriodicFlushManager(eb, 50*time.Millisecond, logger)

	// Buffer some events
	eb.BufferEvent("event1")

	// Start periodic flush manager
	pfm.Start()

	// Wait for flush attempt
	time.Sleep(100 * time.Millisecond)

	// Stop the manager
	pfm.Stop()

	// Events should still be buffered after failed flush
	if eb.GetBufferedEventCount() != 1 {
		t.Errorf("Expected 1 buffered event after failed flush, got %d", eb.GetBufferedEventCount())
	}
}

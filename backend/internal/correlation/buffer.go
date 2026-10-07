package correlation

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/correlic/correlic-backend/internal/event"
)

// EventBuffer is a thread-safe, non-blocking event queue for streaming correlation.
type EventBuffer struct {
	events  chan *event.Event
	done    chan struct{}
	closed  atomic.Bool
	dropped atomic.Int64
	mu      sync.RWMutex
}

// NewEventBuffer creates a new event buffer with the specified capacity.
func NewEventBuffer(size int) *EventBuffer {
	return &EventBuffer{
		events: make(chan *event.Event, size),
		done:   make(chan struct{}),
	}
}

// Push adds an event to the buffer. Returns error if buffer is full (non-blocking).
func (b *EventBuffer) Push(evt *event.Event) error {
	if b.closed.Load() {
		return fmt.Errorf("buffer closed")
	}

	select {
	case b.events <- evt:
		return nil
	case <-b.done:
		return fmt.Errorf("buffer closed")
	default:
		// Buffer full - drop event and increment counter
		b.dropped.Add(1)
		return fmt.Errorf("buffer full, event dropped (total dropped: %d)", b.dropped.Load())
	}
}

// Subscribe returns a read-only channel for consuming events.
func (b *EventBuffer) Subscribe() <-chan *event.Event {
	return b.events
}

// DroppedCount returns the number of events dropped due to buffer overflow.
func (b *EventBuffer) DroppedCount() int64 {
	return b.dropped.Load()
}

// Len returns the current number of events in the buffer.
func (b *EventBuffer) Len() int {
	return len(b.events)
}

// Cap returns the buffer capacity.
func (b *EventBuffer) Cap() int {
	return cap(b.events)
}

// Close closes the buffer and signals consumers to stop.
func (b *EventBuffer) Close() {
	if b.closed.CompareAndSwap(false, true) {
		close(b.done)
		close(b.events)
	}
}

// Done returns a channel that is closed when the buffer is closed.
func (b *EventBuffer) Done() <-chan struct{} {
	return b.done
}

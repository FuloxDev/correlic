package correlation

import (
	"context"
	"sync"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

// CorrelationWindow holds events for a specific host within a time window.
type CorrelationWindow struct {
	hostID      string
	events      []*event.Event
	startTime   time.Time
	lastEventAt time.Time
	maxAge      time.Duration
	mu          sync.RWMutex
}

// NewCorrelationWindow creates a new correlation window for a host.
func NewCorrelationWindow(hostID string, maxAge time.Duration) *CorrelationWindow {
	return &CorrelationWindow{
		hostID:    hostID,
		events:    make([]*event.Event, 0, 1000),
		startTime: time.Now(),
		maxAge:    maxAge,
	}
}

// Add adds an event to the window.
func (w *CorrelationWindow) Add(evt *event.Event) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.events = append(w.events, evt)
	w.lastEventAt = time.Now()
}

// ShouldFlush returns true if the window should be flushed.
func (w *CorrelationWindow) ShouldFlush(now time.Time) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Flush if window is old or has many events
	age := now.Sub(w.startTime)
	return age >= w.maxAge || len(w.events) >= 1000
}

// IsIdle returns true if no events have been added recently.
func (w *CorrelationWindow) IsIdle(now time.Time, idleThreshold time.Duration) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if len(w.events) == 0 {
		return false
	}

	return now.Sub(w.lastEventAt) >= idleThreshold
}

// BuildAndPersist builds the correlation graph and persists to Neo4j.
func (w *CorrelationWindow) BuildAndPersist(ctx context.Context, persister GraphPersister) error {
	w.mu.RLock()
	events := make([]event.Event, len(w.events))
	for i, evt := range w.events {
		events[i] = *evt
	}
	w.mu.RUnlock()

	if len(events) == 0 {
		return nil
	}

	// Order events by timestamp
	OrderEvents(events)

	// Build correlation graph
	graph := BuildGraph(events)

	// Persist to Neo4j
	if persister != nil {
		return persister.PersistGraph(ctx, events, graph)
	}

	return nil
}

// EventCount returns the number of events in the window.
func (w *CorrelationWindow) EventCount() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.events)
}

// Clear removes all events from the window.
func (w *CorrelationWindow) Clear() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.events = make([]*event.Event, 0, 1000)
	w.startTime = time.Now()
}

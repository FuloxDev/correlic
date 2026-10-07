package correlation

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

// Worker processes events from the buffer and builds correlation graphs in real-time.
type Worker struct {
	buffer         *EventBuffer
	graphPersister GraphPersister
	windowSize     time.Duration
	flushInterval  time.Duration
	windows        map[string]*CorrelationWindow
	mu             sync.RWMutex
	wg             sync.WaitGroup
}

// NewWorker creates a new correlation worker.
func NewWorker(buffer *EventBuffer, graphPersister GraphPersister, windowSize, flushInterval time.Duration) *Worker {
	return &Worker{
		buffer:         buffer,
		graphPersister: graphPersister,
		windowSize:     windowSize,
		flushInterval:  flushInterval,
		windows:        make(map[string]*CorrelationWindow),
	}
}

// Start begins processing events from the buffer.
func (w *Worker) Start(ctx context.Context) {
	w.wg.Add(2)

	// Event processing goroutine
	go func() {
		defer w.wg.Done()
		w.processEvents(ctx)
	}()

	// Periodic flush goroutine
	go func() {
		defer w.wg.Done()
		w.periodicFlush(ctx)
	}()
}

// processEvents consumes events from the buffer and adds them to correlation windows.
func (w *Worker) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			log.Println("Correlation worker stopping (context cancelled)")
			return
		case <-w.buffer.Done():
			log.Println("Correlation worker stopping (buffer closed)")
			w.flushAll(ctx)
			return
		case evt := <-w.buffer.Subscribe():
			if evt == nil {
				continue
			}
			w.processEvent(ctx, evt)
		}
	}
}

// processEvent adds an event to the appropriate correlation window.
func (w *Worker) processEvent(ctx context.Context, evt *event.Event) {
	hostID := evt.HostID
	if hostID == "" {
		return
	}

	w.mu.Lock()
	window, exists := w.windows[hostID]
	if !exists {
		window = NewCorrelationWindow(hostID, w.windowSize)
		w.windows[hostID] = window
		// Window open log removed — fires on every first event per host
	}
	w.mu.Unlock()

	window.Add(evt)

	// Check if window should be flushed
	if window.ShouldFlush(time.Now()) {
		w.flushWindow(ctx, hostID)
	}
}

// periodicFlush periodically flushes idle windows.
func (w *Worker) periodicFlush(ctx context.Context) {
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.buffer.Done():
			return
		case <-ticker.C:
			w.flushIdleWindows(ctx)
		}
	}
}

// flushIdleWindows flushes windows that haven't received events recently.
func (w *Worker) flushIdleWindows(ctx context.Context) {
	now := time.Now()
	idleThreshold := w.flushInterval

	w.mu.RLock()
	var toFlush []string
	for hostID, window := range w.windows {
		if window.IsIdle(now, idleThreshold) {
			toFlush = append(toFlush, hostID)
		}
	}
	w.mu.RUnlock()

	if len(toFlush) > 0 {
		log.Printf("correlation: periodic flush — flushing %d idle window(s) of %d total",
			len(toFlush), len(w.windows))
	}
	for _, hostID := range toFlush {
		w.flushWindow(ctx, hostID)
	}
}

// flushWindow builds correlation graph and persists to Neo4j.
func (w *Worker) flushWindow(ctx context.Context, hostID string) {
	w.mu.Lock()
	window, exists := w.windows[hostID]
	if !exists {
		w.mu.Unlock()
		return
	}
	delete(w.windows, hostID)
	w.mu.Unlock()

	eventCount := window.EventCount()
	if eventCount == 0 {
		return
	}

	// Build and persist graph
	if err := window.BuildAndPersist(ctx, w.graphPersister); err != nil {
		log.Printf("WARN: Failed to persist correlation graph for host %s (%d events): %v", hostID, eventCount, err)
		// Don't retry - just log and continue
	} else {
		log.Printf("Flushed correlation window for host %s (%d events)", hostID, eventCount)
	}
}

// flushAll flushes all windows (called on shutdown).
func (w *Worker) flushAll(ctx context.Context) {
	w.mu.RLock()
	hostIDs := make([]string, 0, len(w.windows))
	for hostID := range w.windows {
		hostIDs = append(hostIDs, hostID)
	}
	w.mu.RUnlock()

	log.Printf("Flushing %d correlation windows on shutdown", len(hostIDs))
	for _, hostID := range hostIDs {
		w.flushWindow(ctx, hostID)
	}
}

// Wait waits for the worker to finish processing.
func (w *Worker) Wait() {
	w.wg.Wait()
}

// Stats returns worker statistics.
func (w *Worker) Stats() WorkerStats {
	w.mu.RLock()
	defer w.mu.RUnlock()

	totalEvents := 0
	for _, window := range w.windows {
		totalEvents += window.EventCount()
	}

	return WorkerStats{
		ActiveWindows: len(w.windows),
		TotalEvents:   totalEvents,
		DroppedEvents: w.buffer.DroppedCount(),
		BufferSize:    w.buffer.Len(),
		BufferCap:     w.buffer.Cap(),
	}
}

// WorkerStats contains worker statistics.
type WorkerStats struct {
	ActiveWindows int
	TotalEvents   int
	DroppedEvents int64
	BufferSize    int
	BufferCap     int
}

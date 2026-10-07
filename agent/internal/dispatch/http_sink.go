package dispatch

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
)

const defaultIngestBatchSize = 10

// IngestClient sends canonical events to the backend (e.g. POST /ingest/events).
type IngestClient interface {
	SendCanonicalEvents(ctx context.Context, events []event.Event) error
}

// HTTPSink buffers canonical events and POSTs them to telemetry_url/ingest/events.
// On failure it logs and drops; no retry.
type HTTPSink struct {
	client IngestClient
	buf    []event.Event
	maxBuf int
	mu     sync.Mutex
}

// NewHTTPSink returns a sink that batches up to maxBatch events, then POSTs.
// If maxBatch <= 0, defaultIngestBatchSize is used.
func NewHTTPSink(client IngestClient, maxBatch int) *HTTPSink {
	if maxBatch <= 0 {
		maxBatch = defaultIngestBatchSize
	}
	return &HTTPSink{client: client, maxBuf: maxBatch}
}

// Start runs a periodic flusher to ensure low latency even for small batches.
func (s *HTTPSink) Start(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Best-effort final flush so buffered events survive a shutdown.
			flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			s.mu.Lock()
			_ = s.flush(flushCtx)
			s.mu.Unlock()
			cancel()
			return
		case <-ticker.C:
			s.mu.Lock()
			_ = s.flush(ctx)
			s.mu.Unlock()
		}
	}
}

// Dispatch adds the event to the buffer and flushes when the buffer is full.
func (s *HTTPSink) Dispatch(ctx context.Context, evt event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, evt)
	if len(s.buf) < s.maxBuf {
		return nil
	}
	return s.flush(ctx)
}

// flush sends the buffer. Caller must hold lock.
func (s *HTTPSink) flush(ctx context.Context) error {
	if len(s.buf) == 0 {
		return nil
	}
	toSend := make([]event.Event, len(s.buf))
	copy(toSend, s.buf)
	s.buf = s.buf[:0]

	// Release lock during network call to avoid blocking Dispatch
	// We made a copy, so this is safe.
	s.mu.Unlock()

	// Send outside the lock
	err := s.client.SendCanonicalEvents(ctx, toSend)

	// Re-acquire lock to satisfy caller expectation (if any) or just return
	// The caller of flush() expects to hold the lock?
	// Let's check call sites:
	// 1. Dispatch() holds lock, calls flush().
	// 2. Start() holds lock, calls flush().

	// If we unlock here, Dispatch() proceeds.
	// But Dispatch() has `defer s.mu.Unlock()`.
	// If we unlock here, and then return, Dispatch() will unlock AGAIN -> Panic!

	// So we must re-acquire lock before returning.
	s.mu.Lock()

	if err != nil {
		slog.Warn("ingest/events failed, dropping batch", "error", err, "count", len(toSend))
		return err
	}
	slog.Debug("ingest/events batch sent", "count", len(toSend))
	return nil
}

package dispatch

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/health"
	"github.com/correlic/correlic-agent/internal/transport"
)

const (
	defaultIngestBatchSize = 10
	// defaultIngestMaxQueue bounds the number of batches waiting for delivery
	// while the backend is unreachable. With 100-event batches this is ~20k
	// events; the oldest batch is dropped when the queue is full.
	defaultIngestMaxQueue = 200
	ingestMinBackoff      = 1 * time.Second
	ingestMaxBackoff      = 30 * time.Second
	ingestFlushInterval   = 500 * time.Millisecond
	ingestShutdownFlush   = 3 * time.Second
	ingestComponent       = "ingest"
)

// IngestClient sends canonical events to the backend (e.g. POST /ingest/events).
type IngestClient interface {
	SendCanonicalEvents(ctx context.Context, events []event.Event) error
}

// HTTPSink buffers canonical events into batches and POSTs them to
// telemetry_url/ingest/events from a single sender goroutine.
//
// Delivery is reliable for transient failures: 5xx responses and network
// errors are retried with exponential backoff (1s..30s) while the batch stays
// at the head of a bounded queue; when the queue is full the oldest batch is
// dropped and counted. 401/403 are permanent (the key is rejected): the batch
// is dropped and the condition is surfaced through the health package at WARN
// once per minute. Other 4xx responses (bad payload) drop the batch.
type HTTPSink struct {
	client   IngestClient
	maxBatch int
	maxQueue int

	mu    sync.Mutex
	buf   []event.Event   // events not yet forming a full batch
	queue [][]event.Event // batches waiting for delivery, oldest first
	wake  chan struct{}

	minBackoff time.Duration
	maxBackoff time.Duration

	droppedBatches atomic.Int64
	droppedEvents  atomic.Int64
	sentBatches    atomic.Int64
}

// NewHTTPSink returns a sink that batches up to maxBatch events, then POSTs.
// If maxBatch <= 0, defaultIngestBatchSize is used.
func NewHTTPSink(client IngestClient, maxBatch int) *HTTPSink {
	if maxBatch <= 0 {
		maxBatch = defaultIngestBatchSize
	}
	return &HTTPSink{
		client:     client,
		maxBatch:   maxBatch,
		maxQueue:   defaultIngestMaxQueue,
		wake:       make(chan struct{}, 1),
		minBackoff: ingestMinBackoff,
		maxBackoff: ingestMaxBackoff,
	}
}

// Dispatch adds the event to the current batch; a full batch is queued for
// the sender. It never blocks on the network.
func (s *HTTPSink) Dispatch(_ context.Context, evt event.Event) error {
	s.mu.Lock()
	s.buf = append(s.buf, evt)
	if len(s.buf) >= s.maxBatch {
		s.enqueueLocked()
	}
	s.mu.Unlock()
	return nil
}

// enqueueLocked moves the partial buffer into the queue. Caller holds s.mu.
func (s *HTTPSink) enqueueLocked() {
	if len(s.buf) == 0 {
		return
	}
	batch := s.buf
	s.buf = make([]event.Event, 0, s.maxBatch)
	s.queue = append(s.queue, batch)
	for len(s.queue) > s.maxQueue {
		dropped := s.queue[0]
		s.queue[0] = nil
		s.queue = s.queue[1:]
		s.droppedBatches.Add(1)
		s.droppedEvents.Add(int64(len(dropped)))
		health.ReportFailure(ingestComponent, 0, nil, int64(len(dropped)))
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// head returns the oldest queued batch without removing it.
func (s *HTTPSink) head() ([]event.Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return nil, false
	}
	return s.queue[0], true
}

// pop removes the oldest queued batch.
func (s *HTTPSink) pop() {
	s.mu.Lock()
	if len(s.queue) > 0 {
		s.queue[0] = nil
		s.queue = s.queue[1:]
	}
	s.mu.Unlock()
}

// Stats returns delivery counters (sent batches, dropped batches, dropped events).
func (s *HTTPSink) Stats() (sent, droppedBatches, droppedEvents int64) {
	return s.sentBatches.Load(), s.droppedBatches.Load(), s.droppedEvents.Load()
}

// Start runs the periodic partial-batch flusher and the sender loop until ctx
// is done, then flushes what it can within a short deadline.
func (s *HTTPSink) Start(ctx context.Context) {
	ticker := time.NewTicker(ingestFlushInterval)
	defer ticker.Stop()

	var backoff time.Duration
	for {
		batch, ok := s.head()
		if !ok {
			select {
			case <-ctx.Done():
				s.shutdownFlush(ctx)
				return
			case <-ticker.C:
				s.mu.Lock()
				s.enqueueLocked()
				s.mu.Unlock()
			case <-s.wake:
			}
			continue
		}

		err := s.client.SendCanonicalEvents(ctx, batch)
		switch {
		case err == nil:
			s.pop()
			s.sentBatches.Add(1)
			backoff = 0
			health.ReportOK(ingestComponent)
			slog.Debug("ingest/events batch sent", "count", len(batch))
		case ctx.Err() != nil:
			// Cancelled mid-send: leave the batch queued for the final flush.
			s.shutdownFlush(ctx)
			return
		case transport.IsAuthError(err):
			s.pop()
			s.droppedBatches.Add(1)
			s.droppedEvents.Add(int64(len(batch)))
			health.ReportAuthRejected(ingestComponent, transport.StatusOf(err), err)
		case transport.IsPermanent(err):
			s.pop()
			s.droppedBatches.Add(1)
			s.droppedEvents.Add(int64(len(batch)))
			slog.Warn("ingest/events rejected by backend, dropping batch",
				"status", transport.StatusOf(err), "count", len(batch), "error", err)
		default:
			backoff = nextBackoff(backoff, s.minBackoff, s.maxBackoff)
			health.ReportFailure(ingestComponent, transport.StatusOf(err), err, 0)
			slog.Debug("ingest/events failed, will retry", "error", err, "count", len(batch), "backoff", backoff)
			select {
			case <-ctx.Done():
				s.shutdownFlush(ctx)
				return
			case <-time.After(backoff):
			}
		}
	}
}

// shutdownFlush sends whatever is queued, best effort, within ingestShutdownFlush.
func (s *HTTPSink) shutdownFlush(ctx context.Context) {
	s.mu.Lock()
	s.enqueueLocked()
	pending := len(s.queue)
	s.mu.Unlock()
	if pending == 0 {
		return
	}
	flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ingestShutdownFlush)
	defer cancel()
	for {
		batch, ok := s.head()
		if !ok {
			return
		}
		if err := s.client.SendCanonicalEvents(flushCtx, batch); err != nil {
			s.mu.Lock()
			left := len(s.queue)
			s.mu.Unlock()
			slog.Warn("ingest/events shutdown flush failed; dropping queued batches",
				"batches", left, "error", err)
			return
		}
		s.pop()
		s.sentBatches.Add(1)
	}
}

// nextBackoff doubles the backoff, starting at min and capping at max.
func nextBackoff(cur, min, max time.Duration) time.Duration {
	if cur == 0 {
		return min
	}
	cur *= 2
	if cur > max {
		return max
	}
	return cur
}

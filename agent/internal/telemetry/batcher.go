package telemetry

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/correlic/correlic-agent/internal/health"
	"github.com/correlic/correlic-agent/internal/model"
	"github.com/correlic/correlic-agent/internal/transport"
)

const telemetryComponent = "telemetry"

// Batcher is the batcher for the telemetry events.
type Batcher struct {
	agentID       string
	transport     transport.Transport
	flushInterval time.Duration
	maxBatch      int
	maxBuffered   int
	minBackoff    time.Duration
	maxBackoff    time.Duration
	ch            chan model.TelemetryEvent
	sendCh        chan []model.TelemetryEvent
	done          chan struct{}
}

// NewBatcher creates a new Batcher with the given agent ID and transport.
func NewBatcher(agentID string, t transport.Transport) *Batcher {
	return &Batcher{
		agentID:   agentID,
		transport: t,
		// Lower interval + larger batches reduces end-to-end latency and helps avoid
		// producer bursts filling the in-memory queue (common with eBPF events).
		flushInterval: 2 * time.Second,
		maxBatch:      500,   // Increased from 200 to 500 to reduce HTTP overhead
		maxBuffered:   50000, // Increased from 5000 to match BufferedDispatcher
		minBackoff:    1 * time.Second,
		maxBackoff:    30 * time.Second,
		// Large ingress buffer: eBPF can burst (especially file events).
		ch: make(chan model.TelemetryEvent, 20000),
		// Small batch handoff channel to the sender loop.
		sendCh: make(chan []model.TelemetryEvent, 100), // Increased from 16 to 100
		done:   make(chan struct{}),
	}
}

// Done is closed once Start has returned and the sender loop has finished its
// shutdown flush.
func (b *Batcher) Done() <-chan struct{} {
	return b.done
}

// Start starts the batcher. It returns after ctx is done and the final flush
// has completed.
func (b *Batcher) Start(ctx context.Context) {
	defer close(b.done)

	// Dedicated sender loop so ingestion never blocks on network I/O.
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		b.sendLoop(ctx)
	}()

	// create a new ticker for the flush interval.
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	// create a buffer for the telemetry events.
	var buf []model.TelemetryEvent

	// flushMaybe hands off buffered telemetry to the sender loop.
	// It never blocks the ingestion loop.
	flushMaybe := func() {
		// if the buffer is empty, return.
		if len(buf) == 0 {
			return
		}
		batch := buf
		buf = nil
		select {
		case b.sendCh <- batch:
			return
		default:
			// Sender is backed up. Re-queue into buf (bounded) and keep going.
			buf = append(buf, batch...)
			if b.maxBuffered > 0 && len(buf) > b.maxBuffered {
				dropped := len(buf) - b.maxBuffered
				buf = buf[dropped:]
				slog.Warn("telemetry buffer full, dropping oldest events", "dropped", dropped, "max_buffered", b.maxBuffered)
			}
			slog.Warn("telemetry sender busy; delaying flush", "queued", len(buf))
			return
		}
	}

	for {
		select {
		case <-ctx.Done():
			// Best-effort final flush (direct) on shutdown of what never
			// reached the sender; the sender flushes its own queue.
			if len(buf) > 0 {
				shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
				_ = b.transport.SendTelemetryBatch(shutdownCtx, model.TelemetryBatch{Events: buf})
				cancel()
			}
			<-senderDone
			return

		// if an event is received, add it to the buffer.
		case ev := <-b.ch:
			buf = append(buf, ev)
			if b.maxBuffered > 0 && len(buf) > b.maxBuffered {
				// Drop oldest to maintain bounded memory.
				dropped := len(buf) - b.maxBuffered
				buf = buf[dropped:]
				slog.Warn("telemetry buffer full, dropping oldest events", "dropped", dropped, "max_buffered", b.maxBuffered)
			}
			if len(buf) >= b.maxBatch {
				flushMaybe()
			}

		case <-ticker.C:
			flushMaybe()
		}
	}
}

func (b *Batcher) sendLoop(ctx context.Context) {
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	var queue []model.TelemetryEvent
	var nextAttempt time.Time
	var backoff time.Duration

	chunkSize := func() int {
		n := b.maxBatch
		if n <= 0 {
			n = 200
		}
		if n > len(queue) {
			n = len(queue)
		}
		return n
	}

	trySend := func(sendCtx context.Context) {
		if len(queue) == 0 {
			return
		}
		now := time.Now()
		if !nextAttempt.IsZero() && now.Before(nextAttempt) {
			return
		}

		// Send in chunks to avoid huge payloads during bursts.
		n := chunkSize()
		chunk := queue[:n]

		flushCtx, cancel := context.WithTimeout(sendCtx, 10*time.Second)
		err := b.transport.SendTelemetryBatch(flushCtx, model.TelemetryBatch{Events: chunk})
		cancel()

		if err != nil {
			switch {
			case transport.IsAuthError(err):
				// Rejected key: permanent until the operator fixes agent.yaml.
				// Surface it at WARN once per minute, not once per chunk.
				health.ReportAuthRejected(telemetryComponent, transport.StatusOf(err), err)
				queue = queue[n:]
				nextAttempt = time.Time{}
				backoff = 0
			case transport.IsPermanent(err):
				slog.Warn("telemetry flush failed (permanent), dropping chunk", "error", err, "count", len(chunk))
				queue = queue[n:]
				nextAttempt = time.Time{}
				backoff = 0
			default:
				if backoff == 0 {
					backoff = b.minBackoff
				} else {
					backoff *= 2
					if backoff > b.maxBackoff {
						backoff = b.maxBackoff
					}
				}
				nextAttempt = now.Add(backoff)
				health.ReportFailure(telemetryComponent, transport.StatusOf(err), err, 0)
				slog.Debug("telemetry flush failed (transient), will retry", "error", err, "count", len(chunk), "backoff", backoff.String())
			}
			return
		}

		// Success: dequeue chunk and reset backoff.
		queue = queue[n:]
		nextAttempt = time.Time{}
		backoff = 0
		health.ReportOK(telemetryComponent)
		slog.Debug("telemetry batch delivered", "count", n, "remaining_queue", len(queue))
	}

	enqueue := func(batch []model.TelemetryEvent) {
		if len(batch) == 0 {
			return
		}
		queue = append(queue, batch...)
		if b.maxBuffered > 0 && len(queue) > b.maxBuffered {
			dropped := len(queue) - b.maxBuffered
			queue = queue[dropped:]
			slog.Warn("telemetry send queue full, dropping oldest events", "dropped", dropped, "max_buffered", b.maxBuffered)
		}
	}

	for {
		select {
		case <-ctx.Done():
			// Drain hand-offs that raced with cancellation, then flush the
			// retry queue best-effort within a short deadline. Backoff is
			// ignored here: this is the last chance to deliver.
			for {
				select {
				case batch := <-b.sendCh:
					enqueue(batch)
					continue
				default:
				}
				break
			}
			if len(queue) == 0 {
				return
			}
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			for len(queue) > 0 && shutdownCtx.Err() == nil {
				n := chunkSize()
				if err := b.transport.SendTelemetryBatch(shutdownCtx, model.TelemetryBatch{Events: queue[:n]}); err != nil {
					slog.Warn("telemetry shutdown flush failed; dropping queued events", "remaining", len(queue), "error", err)
					return
				}
				queue = queue[n:]
			}
			return
		case batch := <-b.sendCh:
			enqueue(batch)
			// Try sending immediately after enqueue.
			trySend(ctx)
		case <-ticker.C:
			trySend(ctx)
		}
	}
}

// Enqueue adds a telemetry event to the batcher. It never blocks.
// Returns false if the internal buffer is full (event dropped).
func (b *Batcher) Enqueue(eventType string, payload any) bool {
	raw, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("telemetry payload marshal failed", "error", err)
		return false
	}

	ev := model.TelemetryEvent{
		AgentID:   b.agentID,
		EventType: eventType,
		Timestamp: time.Now().UTC(),
		Payload:   raw,
	}

	select {
	// if the channel is not full, add the event to the channel.
	case b.ch <- ev:
		return true
	default:
		slog.Warn("telemetry queue full, dropping event", "event_type", eventType)
		return false
	}
}

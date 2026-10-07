package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/correlic/correlic-agent/internal/model"
	"github.com/correlic/correlic-agent/internal/transport"
)

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
	}
}

// Start starts the batcher.
func (b *Batcher) Start(ctx context.Context) {
	// Dedicated sender loop so ingestion never blocks on network I/O.
	go b.sendLoop(ctx)

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
			// create a new context with a timeout for the shutdown.
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			// Best-effort final flush (direct) on shutdown.
			if len(buf) > 0 {
				_ = b.transport.SendTelemetryBatch(shutdownCtx, model.TelemetryBatch{Events: buf})
			}
			// cancel the context.
			cancel()
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

	trySend := func(sendCtx context.Context) {
		if len(queue) == 0 {
			return
		}
		now := time.Now()
		if !nextAttempt.IsZero() && now.Before(nextAttempt) {
			return
		}

		// Send in chunks to avoid huge payloads during bursts.
		n := b.maxBatch
		if n <= 0 {
			n = 200
		}
		if n > len(queue) {
			n = len(queue)
		}
		chunk := queue[:n]

		flushCtx, cancel := context.WithTimeout(sendCtx, 10*time.Second)
		err := b.transport.SendTelemetryBatch(flushCtx, model.TelemetryBatch{Events: chunk})
		cancel()

		if err != nil {
			if isPermanent(err) {
				slog.Warn("telemetry flush failed (permanent), dropping chunk", "error", err, "count", len(chunk))
				queue = queue[n:]
				nextAttempt = time.Time{}
				backoff = 0
				return
			}

			if backoff == 0 {
				backoff = b.minBackoff
			} else {
				backoff *= 2
				if backoff > b.maxBackoff {
					backoff = b.maxBackoff
				}
			}
			nextAttempt = now.Add(backoff)
			slog.Warn("telemetry flush failed (transient), will retry", "error", err, "count", len(chunk), "backoff", backoff.String())
			return
		}

		// Success: dequeue chunk and reset backoff.
		queue = queue[n:]
		nextAttempt = time.Time{}
		backoff = 0
		slog.Debug("telemetry batch delivered", "count", n, "remaining_queue", len(queue))
	}

	for {
		select {
		case <-ctx.Done():
			return
		case batch := <-b.sendCh:
			if len(batch) == 0 {
				continue
			}
			queue = append(queue, batch...)
			if b.maxBuffered > 0 && len(queue) > b.maxBuffered {
				dropped := len(queue) - b.maxBuffered
				queue = queue[dropped:]
				slog.Warn("telemetry send queue full, dropping oldest events", "dropped", dropped, "max_buffered", b.maxBuffered)
			}
			// Try sending immediately after enqueue.
			trySend(ctx)
		case <-ticker.C:
			trySend(ctx)
		}
	}
}

// isPermanent checks if the error is permanent.
func isPermanent(err error) bool {
	// BackendError is used when the backend responds with a non-2xx status.
	var be *transport.BackendError
	if errors.As(err, &be) {
		// Retry on typical transient statuses.
		if be.Status >= 500 {
			return false
		}
		if be.Status == 408 || be.Status == 429 {
			return false
		}
		// Any other 4xx is treated as permanent (bad payload, unauthorized, too large, etc).
		if be.Status >= 400 && be.Status < 500 {
			return true
		}
	}
	// Unknown/network errors are treated as transient.
	return false
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

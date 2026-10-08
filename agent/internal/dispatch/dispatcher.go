package dispatch

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
)

// DefaultDispatchBufferSize is the default channel capacity when no env is set.
const DefaultDispatchBufferSize = 50000

// DispatchBufferSize returns the buffer size: AGENT_DISPATCH_BUFFER or DISPATCH_BUFFER_SIZE if set, else default.
// Sizes below DefaultDispatchBufferSize are allowed when explicitly set (e.g. 4096 for rate-limited setups).
func DispatchBufferSize() int {
	for _, name := range []string{"AGENT_DISPATCH_BUFFER", "DISPATCH_BUFFER_SIZE"} {
		if s := os.Getenv(name); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				return n
			}
		}
	}
	return DefaultDispatchBufferSize
}

// Dispatcher is the interface for sending canonical events.
// Start begins the dispatch loop; Enqueue adds events (non-blocking, may drop when full).
// RecordDrop records a drop by reason (e.g. exec cleanup); no-op if drop stats not set.
type Dispatcher interface {
	Start(ctx context.Context)
	Enqueue(evt event.Event)
	RecordDrop(eventType, reason string)
}

// DispatcherSink is the actual destination for events (e.g. log, backend).
type DispatcherSink interface {
	Dispatch(ctx context.Context, evt event.Event) error
}

// NopSink discards all events. Used when live ingestion is disabled.
type NopSink struct{}

func (NopSink) Dispatch(context.Context, event.Event) error { return nil }

// Admission optionally applies rate limiting and deduplication before enqueue.
type Admission struct {
	RateLimiter RateLimiter
	Deduper     Deduper
}

// BufferedDispatcher buffers events and dispatches them asynchronously so the eBPF reader is never blocked.
// Optional admission (rate limiter, deduper) and drop stats can be set via WithAdmission/WithDropStats.
type BufferedDispatcher struct {
	ch        chan event.Event
	out       DispatcherSink
	admission *Admission
	drops     *DropStats
}

// NewBufferedDispatcher creates a buffered dispatcher with the given sink and buffer size.
// If size <= 0, uses DispatchBufferSize() (env AGENT_DISPATCH_BUFFER or DISPATCH_BUFFER_SIZE or default).
// For production: use NewBufferedDispatcherFromEnv(sink) so rate limiting, dedupe, and drop stats are enabled from env.
func NewBufferedDispatcher(sink DispatcherSink, size int) *BufferedDispatcher {
	if size <= 0 {
		size = DispatchBufferSize()
	}
	return &BufferedDispatcher{
		ch:  make(chan event.Event, size),
		out: sink,
	}
}

// WithAdmission sets optional rate limiter and deduper. Call before Start.
func (d *BufferedDispatcher) WithAdmission(a *Admission) *BufferedDispatcher {
	d.admission = a
	return d
}

// WithDropStats sets drop counters and enables throttled drop logging and periodic 30s stats. Call before Start.
func (d *BufferedDispatcher) WithDropStats(s *DropStats) *BufferedDispatcher {
	d.drops = s
	return d
}

// NewBufferedDispatcherFromEnv creates a dispatcher with buffer size from env and optional admission (rate limit + dedupe) and drop stats from env.
// Use this for Phase 12A volume control: set AGENT_EXEC_RATE_LIMIT, AGENT_EXEC_DEDUPE_WINDOW_MS, AGENT_DISPATCH_BUFFER as needed.
func NewBufferedDispatcherFromEnv(sink DispatcherSink) *BufferedDispatcher {
	size := DispatchBufferSize()
	d := NewBufferedDispatcher(sink, size)
	limiter := RateLimiterFromEnv()
	deduper := NewDedupeFromEnv()
	if limiter != nil || deduper != nil {
		d.WithAdmission(&Admission{RateLimiter: limiter, Deduper: deduper})
	}
	d.WithDropStats(NewDropStats())
	return d
}

// Start runs the dispatch loop and, when drop stats are set, a 30s periodic logger. Call once from main.
func (d *BufferedDispatcher) Start(ctx context.Context) {
	if d.drops != nil {
		go d.logDropStatsEvery30s(ctx)
	}
	go func() {
		for {
			select {
			case evt := <-d.ch:
				_ = d.out.Dispatch(ctx, evt)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (d *BufferedDispatcher) logDropStatsEvery30s(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rateLimited, bufferFull, deduplicated, cleanupReasons := d.drops.Snapshot(true)
			var any bool
			for _, n := range rateLimited {
				if n > 0 {
					any = true
					break
				}
			}
			for _, n := range bufferFull {
				if n > 0 {
					any = true
					break
				}
			}
			if deduplicated > 0 {
				any = true
			}
			for _, n := range cleanupReasons {
				if n > 0 {
					any = true
					break
				}
			}
			if !any {
				continue
			}
			slog.Info("agent drop stats",
				"rate_limited", rateLimited,
				"buffer_full", bufferFull,
				"deduplicated", deduplicated,
				"exec_cleanup", cleanupReasons,
			)
		}
	}
}

// RecordDrop records a drop by reason (exec cleanup etc.). No-op if drop stats not set.
func (d *BufferedDispatcher) RecordDrop(eventType, reason string) {
	if d.drops != nil {
		d.drops.RecordDrop(eventType, reason)
	}
}

// Enqueue adds an event to the buffer. Applies dedupe (process_exec) and rate limit before enqueue; non-blocking send, drops when full.
func (d *BufferedDispatcher) Enqueue(evt event.Event) {
	if d.admission != nil {
		if d.admission.Deduper != nil && evt.Type == "process_exec" && !d.admission.Deduper.Allow(evt) {
			if d.drops != nil {
				d.drops.AddDeduplicated()
				d.drops.MaybeLogDrop(evt.Type, "deduplicated")
			}
			return
		}
		if d.admission.RateLimiter != nil && !d.admission.RateLimiter.Allow(evt.Type) {
			if d.drops != nil {
				d.drops.AddRateLimited(evt.Type)
				d.drops.MaybeLogDrop(evt.Type, "rate_limited")
			}
			return
		}
	}
	select {
	case d.ch <- evt:
	default:
		if d.drops != nil {
			d.drops.AddBufferFull(evt.Type)
			d.drops.MaybeLogDrop(evt.Type, "buffer_full")
		} else {
			slog.Warn("dispatch buffer full, dropping event", "event_id", evt.ID, "type", evt.Type)
		}
	}
}

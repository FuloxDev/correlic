package esevents

import (
	"context"
	"log/slog"
	"sync/atomic"
)

// Fanout reads one EventSource and splits it into per-runner sources:
// process events (exec, exit, fork) for the ExecRunner, open events for the
// FileRunner and lookup events for the DNSRunner. Each output is buffered;
// when a runner falls behind, its events are dropped and counted rather
// than stalling the source.
type Fanout struct {
	src    EventSource
	logger *slog.Logger

	proc   chan Event
	open   chan Event
	lookup chan Event

	dropped atomic.Uint64
}

// NewFanout creates a fanout over src.
func NewFanout(src EventSource, logger *slog.Logger) *Fanout {
	if logger == nil {
		logger = slog.Default()
	}
	return &Fanout{
		src:    src,
		logger: logger,
		proc:   make(chan Event, 4096),
		open:   make(chan Event, 4096),
		lookup: make(chan Event, 2048),
	}
}

// Process returns the source of exec, exit and fork events.
func (f *Fanout) Process() EventSource { return ChanSource(f.proc) }

// Open returns the source of file open events.
func (f *Fanout) Open() EventSource { return ChanSource(f.open) }

// Lookup returns the source of lookup events.
func (f *Fanout) Lookup() EventSource { return ChanSource(f.lookup) }

// Dropped returns how many events were dropped because a runner's channel
// was full.
func (f *Fanout) Dropped() uint64 { return f.dropped.Load() }

// Start routes events until ctx is cancelled or the source channel closes,
// then closes the output channels so the runners stop too.
func (f *Fanout) Start(ctx context.Context) {
	defer func() {
		close(f.proc)
		close(f.open)
		close(f.lookup)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-f.src.Events():
			if !ok {
				return
			}
			f.route(ev)
		}
	}
}

func (f *Fanout) route(ev Event) {
	var out chan Event
	switch ev.Type {
	case EventExec, EventExit, EventFork:
		out = f.proc
	case EventOpen:
		out = f.open
	case EventLookup:
		out = f.lookup
	default:
		return
	}
	select {
	case out <- ev:
	default:
		n := f.dropped.Add(1)
		if n == 1 || n%1000 == 0 {
			f.logger.Warn("runner channel full, dropping Endpoint Security events", "type", ev.Type.String(), "dropped_total", n)
		}
	}
}

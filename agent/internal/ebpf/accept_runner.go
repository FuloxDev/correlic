//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
)

// AcceptRunner wraps AcceptCollector and dispatches canonical net_accept events.
// Must use the same HostID and Dispatcher as the exec Runner (see runner.go invariant).
type AcceptRunner struct {
	collector  *AcceptCollector
	emit       collect.EventSink
	logger     *slog.Logger
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// NewAcceptRunner creates a new accept runner. disp is required for canonical events.
func NewAcceptRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) (*AcceptRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if disp == nil {
		return nil, fmt.Errorf("dispatcher required for accept runner")
	}
	if hostID == "" {
		hostID = "localhost"
	}

	collector, err := NewAcceptCollector(logger)
	if err != nil {
		return nil, err
	}

	return &AcceptRunner{
		collector:  collector,
		emit:       emit,
		logger:     logger,
		HostID:     hostID,
		Dispatcher: disp,
	}, nil
}

// Start implements the collect.Collector interface.
func (r *AcceptRunner) Start(ctx context.Context) {
	go r.collector.Start(ctx)

	r.logger.Info("eBPF accept runner started, forwarding inbound connection events")

	handler := &AcceptHandler{
		HostID:     r.HostID,
		Dispatcher: r.Dispatcher,
	}

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("eBPF accept runner stopping")
			r.collector.Close()
			return
		case ev := <-r.collector.Events():
			handler.Handle(ev)
			payload := map[string]any{
				"pid":         ev.PID,
				"ppid":        ev.PPID,
				"client_ip":   ev.ClientIP(),
				"client_port": ev.ClientPort,
				"comm":        ev.Comm,
				"source":      "ebpf",
			}
			_ = r.emit("net_accept", payload)
		}
	}
}

// Close releases eBPF resources.
func (r *AcceptRunner) Close() error {
	if r.collector != nil {
		return r.collector.Close()
	}
	return nil
}

//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
)

// MsgRunner wraps MsgCollector and dispatches canonical net_msg events.
// Must use the same HostID and Dispatcher as the exec Runner (see runner.go invariant).
type MsgRunner struct {
	collector  *MsgCollector
	emit       collect.EventSink
	logger     *slog.Logger
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// NewMsgRunner creates a new msg runner.
func NewMsgRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) (*MsgRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if disp == nil {
		return nil, fmt.Errorf("dispatcher required for msg runner")
	}
	if hostID == "" {
		hostID = "localhost"
	}

	collector, err := NewMsgCollector(logger)
	if err != nil {
		return nil, err
	}

	return &MsgRunner{
		collector:  collector,
		emit:       emit,
		logger:     logger,
		HostID:     hostID,
		Dispatcher: disp,
	}, nil
}

// Start implements the collect.Collector interface.
func (r *MsgRunner) Start(ctx context.Context) {
	go r.collector.Start(ctx)

	r.logger.Info("eBPF msg runner started, forwarding IPC message events")

	handler := &MsgHandler{
		HostID:     r.HostID,
		Dispatcher: r.Dispatcher,
	}

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("eBPF msg runner stopping")
			r.collector.Close()
			return
		case ev := <-r.collector.Events():
			handler.Handle(ev)
			dir := "send"
			if ev.Direction == 1 {
				dir = "recv"
			}
			_ = r.emit("net_msg", map[string]any{
				"pid":       ev.PID,
				"fd":        ev.FD,
				"direction": dir,
				"size":      ev.Size,
				"comm":      ev.Comm,
				"source":    "ebpf",
			})
		}
	}
}

// Close releases eBPF resources.
func (r *MsgRunner) Close() error {
	if r.collector != nil {
		return r.collector.Close()
	}
	return nil
}

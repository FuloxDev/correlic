//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/correlic/correlic-agent/internal/dispatch"
)

// ExitRunner runs the exit eBPF collector and forwards events to ExitHandler.
// Uses the same HostID and Dispatcher as the exec runner (Phase 20).
type ExitRunner struct {
	collector  *ExitCollector
	logger     *slog.Logger
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// NewExitRunner creates an ExitRunner. Same hostID and disp as exec for correlation.
func NewExitRunner(logger *slog.Logger, hostID string, disp dispatch.Dispatcher) (*ExitRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if disp == nil {
		return nil, fmt.Errorf("dispatcher required")
	}
	if hostID == "" {
		hostID = "localhost"
	}

	collector, err := NewExitCollector(logger)
	if err != nil {
		return nil, err
	}

	return &ExitRunner{
		collector:  collector,
		logger:     logger,
		HostID:     hostID,
		Dispatcher: disp,
	}, nil
}

// Start runs the exit collector and dispatches canonical process_exit events until ctx is done.
func (r *ExitRunner) Start(ctx context.Context) {
	go r.collector.Start(ctx)

	r.logger.Info("eBPF exit runner started, dispatching process_exit events")

	handler := &ExitHandler{
		HostID:     r.HostID,
		Dispatcher: r.Dispatcher,
	}

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("eBPF exit runner stopping")
			r.collector.Close()
			return
		case ev := <-r.collector.Events():
			pid := uint32(ev.PID)
			// FILTER: Only dispatch exit events for tracked AI processes
			if !GetLineageTracker().IsAI(pid) {
				continue
			}
			r.logger.Debug("AI process exit", "pid", pid, "exit_code", ev.ExitCode)
			handler.Handle(ev)
			// Clean up: remove PID from lineage tracking and BPF maps via removal listeners
			GetLineageTracker().UnregisterProcess(pid)
		}
	}
}

// Close releases eBPF resources.
func (r *ExitRunner) Close() error {
	if r.collector != nil {
		return r.collector.Close()
	}
	return nil
}

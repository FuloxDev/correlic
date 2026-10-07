//go:build darwin && esf

package esf

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/classify"
	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/exechandler"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/procinfo"
)

// ExecRunner converts ESF NOTIFY_EXEC and NOTIFY_EXIT events into canonical events.
// Compared to the kqueue-based exec runner, ESF provides:
//   - Child PID directly on fork (no pgrep delay)
//   - Full cmdline from the kernel (no ps(1) lookup)
//   - Lower latency (<1ms vs polling)
type ExecRunner struct {
	collector *Collector
	emit      collect.EventSink
	logger    *slog.Logger
	hostID    string
	handler   *exechandler.ExecHandler
	disp      dispatch.Dispatcher
}

// NewExecRunner creates an ESF-based process exec/exit runner.
func NewExecRunner(collector *Collector, emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) *ExecRunner {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}
	return &ExecRunner{
		collector: collector,
		emit:      emit,
		logger:    logger,
		hostID:    hostID,
		disp:      disp,
		handler: &exechandler.ExecHandler{
			HostID:     hostID,
			Dispatcher: disp,
		},
	}
}

// Start processes exec and exit events from the ESF collector.
func (r *ExecRunner) Start(ctx context.Context) {
	r.logger.Info("esf exec runner started")
	tracker := lineage.GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("esf exec runner stopping")
			return

		case ev, ok := <-r.collector.ExecEvents():
			if !ok {
				return
			}
			r.handleExec(ev, tracker)

		case ev, ok := <-r.collector.ExitEvents():
			if !ok {
				return
			}
			r.handleExit(ev, tracker)
		}
	}
}

func (r *ExecRunner) handleExec(ev Event, tracker *lineage.LineageTracker) {
	comm := ev.Comm
	pid := ev.PID
	ppid := ev.PPID

	// Lineage: register and filter non-AI processes.
	if !tracker.IsAI(pid) {
		if !tracker.RegisterProcess(pid, ppid, comm) {
			return
		}
	}

	sessionID := procinfo.DetectSessionID(pid)
	role := classify.CheckRole(comm)

	// Flat telemetry.
	if r.emit != nil {
		r.emit("process_exec", map[string]any{
			"pid":    pid,
			"ppid":   ppid,
			"comm":   comm,
			"exe":    ev.ExePath,
			"args":   ev.Args,
			"source": "esf",
			"is_ai":  true,
		})
	}

	// Canonical event via shared exec handler.
	if r.disp != nil {
		r.handler.Handle(exechandler.RawExecEvent{
			PID:       pid,
			PPID:      ppid,
			UID:       ev.UID,
			Comm:      comm,
			Exe:       ev.ExePath,
			Args:      ev.Args,
			SessionID: sessionID,
			Role:      role,
		})
	}
}

func (r *ExecRunner) handleExit(ev Event, tracker *lineage.LineageTracker) {
	pid := ev.PID
	if !tracker.IsAI(pid) {
		return
	}

	sessionID := procinfo.DetectSessionID(pid)

	if r.disp != nil {
		ts := time.Now()
		exitEvt := event.Event{
			SchemaVersion: 1,
			Type:          "process_exit",
			Timestamp:     ts,
			HostID:        r.hostID,
			Source:        "esf",
			Actor: &event.Actor{
				PID:       int(pid),
				PPID:      int(ev.PPID),
				Comm:      ev.Comm,
				SessionID: strconv.FormatUint(uint64(sessionID), 10),
			},
			Context: map[string]any{
				"exit_code": ev.ExitCode,
			},
		}
		exitEvt.ID = event.GenerateID(r.hostID, ts.UnixNano(), "esf", "process_exit", int(pid), "")
		r.disp.Enqueue(exitEvt)
	}

	tracker.UnregisterProcess(pid)
}

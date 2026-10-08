package esevents

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

// ExecRunner converts Endpoint Security exec, exit and fork events into
// canonical events. Compared to the kqueue-based exec runner, Endpoint
// Security provides:
//   - The parent PID on every event (no ps(1) lookup, no race)
//   - Full argv from the kernel
//   - Lower latency than polling
type ExecRunner struct {
	src     EventSource
	source  string
	emit    collect.EventSink
	logger  *slog.Logger
	hostID  string
	handler *exechandler.ExecHandler
	disp    dispatch.Dispatcher
}

// NewExecRunner creates a process exec/exit runner over src. source names the
// collector ("esf" or "eslogger") in the emitted events.
func NewExecRunner(src EventSource, source string, emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) *ExecRunner {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}
	if source == "" {
		source = "esf"
	}
	return &ExecRunner{
		src:    src,
		source: source,
		emit:   emit,
		logger: logger,
		hostID: hostID,
		disp:   disp,
		handler: &exechandler.ExecHandler{
			HostID:     hostID,
			Dispatcher: disp,
		},
	}
}

// Start processes events until ctx is cancelled or the source closes.
func (r *ExecRunner) Start(ctx context.Context) {
	r.logger.Info("exec runner started", "source", r.source)
	tracker := lineage.GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("exec runner stopping", "source", r.source)
			return

		case ev, ok := <-r.src.Events():
			if !ok {
				return
			}
			switch ev.Type {
			case EventExec:
				r.handleExec(ev, tracker)
			case EventExit:
				r.handleExit(ev, tracker)
			case EventFork:
				r.handleFork(ev, tracker)
			}
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
			"source": r.source,
			"is_ai":  true,
		})
	}

	// Canonical event via shared exec handler.
	if r.disp != nil {
		r.handler.Handle(exechandler.RawExecEvent{
			PID:         pid,
			PPID:        ppid,
			UID:         ev.UID,
			Comm:        comm,
			Exe:         ev.ExePath,
			Args:        ev.Args,
			SessionID:   sessionID,
			Role:        role,
			AISessionID: tracker.GetSessionID(pid),
			AIType:      tracker.GetAIType(pid),
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
			Source:        r.source,
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
		tracker.Annotate(exitEvt.Context, pid)
		exitEvt.ID = event.GenerateID(r.hostID, ts.UnixNano(), r.source, "process_exit", int(pid), "")
		r.disp.Enqueue(exitEvt)
	}

	tracker.UnregisterProcess(pid)
}

// handleFork lets a child of an AI process join the parent's session at
// fork time, so a forked worker that never execs (multiprocessing pools,
// fork servers) still has its file and network activity attributed. Nothing
// is dispatched here; the exec event does that. Only sources that subscribe
// to fork (eslogger) deliver these.
func (r *ExecRunner) handleFork(ev Event, tracker *lineage.LineageTracker) {
	if ev.PID == 0 || !tracker.IsAI(ev.PPID) {
		return
	}
	tracker.RegisterProcess(ev.PID, ev.PPID, ev.Comm)
}

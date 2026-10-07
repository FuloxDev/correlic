//go:build darwin

package darwin

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/correlic/correlic-agent/internal/classify"
	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/exechandler"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/procinfo"
)

// procMeta caches process metadata at exec time for use during exit handling,
// when the process may already be reaped and syscalls would fail.
type procMeta struct {
	sessionID uint32
	comm      string
	exe       string
}

// ExecRunner monitors process execution and exit via kqueue and dispatches canonical events.
// Handles both exec and exit events from the ProcCollector (single channel consumer).
type ExecRunner struct {
	collector  *ProcCollector
	emit       collect.EventSink
	logger     *slog.Logger
	HostID     string
	Dispatcher dispatch.Dispatcher
	handler    *exechandler.ExecHandler
	metaCache  sync.Map // uint32 (PID) → procMeta
}

// NewExecRunner creates a new kqueue-based exec runner.
func NewExecRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) (*ExecRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}

	collector, err := NewProcCollector(logger.With("component", "kqueue_proc"))
	if err != nil {
		return nil, err
	}

	return &ExecRunner{
		collector:  collector,
		emit:       emit,
		logger:     logger,
		HostID:     hostID,
		Dispatcher: disp,
		handler: &exechandler.ExecHandler{
			HostID:     hostID,
			Dispatcher: disp,
		},
	}, nil
}

// Collector returns the underlying ProcCollector for PID registration.
func (r *ExecRunner) Collector() *ProcCollector {
	return r.collector
}

// Start implements the collect.Collector interface.
// Handles exec, exit, and fork events from the single ProcCollector channel.
func (r *ExecRunner) Start(ctx context.Context) {
	go r.collector.Start(ctx)

	r.logger.Info("darwin exec runner started (kqueue)")

	tracker := lineage.GetLineageTracker()

	// Auto-watch new AI PIDs in kqueue. When any code path calls
	// RegisterProcess (exec handler, network runner, scanner rescan)
	// and the PID is deemed AI, this listener ensures kqueue tracks it.
	tracker.AddListener(func(pid uint32) {
		if err := r.collector.WatchPID(int(pid)); err != nil {
			r.logger.Debug("failed to auto-watch new AI PID", "pid", pid, "error", err)
		}
	})

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("darwin exec runner stopping")
			return
		case ev, ok := <-r.collector.Events():
			if !ok {
				return
			}

			switch ev.Type {
			case ProcExec:
				r.handleExec(ev, tracker)
			case ProcExit:
				r.handleExit(ev, tracker)
			case ProcFork:
				r.handleFork(ev, tracker)
			}
		}
	}
}

func (r *ExecRunner) handleExec(ev ProcEvent, tracker *lineage.LineageTracker) {
	pid := ev.PID
	cmdline := procinfo.ReadProcCmdline(pid)
	comm := ""
	exe := ""
	if len(cmdline) > 0 {
		exe = cmdline[0]
		// Extract short comm from exe path.
		for i := len(exe) - 1; i >= 0; i-- {
			if exe[i] == '/' {
				comm = exe[i+1:]
				break
			}
		}
		if comm == "" {
			comm = exe
		}
	}

	// Look up PPID so lineage inheritance works at runtime.
	// kqueue NOTE_EXEC doesn't provide PPID directly.
	ppid := procinfo.LookupPPID(pid)

	// Lineage check: register and filter.
	if !tracker.IsAI(pid) {
		if !tracker.RegisterProcess(pid, ppid, comm) {
			return
		}
	}

	sessionID := procinfo.DetectSessionID(pid)
	role := classify.CheckRole(comm)

	// Cache metadata for exit handler (process may be reaped by then).
	r.metaCache.Store(pid, procMeta{sessionID: sessionID, comm: comm, exe: exe})

	// Flat telemetry payload.
	payload := map[string]any{
		"pid":    pid,
		"ppid":   ppid,
		"comm":   comm,
		"exe":    exe,
		"args":   cmdline,
		"source": "kqueue",
		"is_ai":  true,
	}
	if r.emit != nil {
		r.emit("process_exec", payload)
	}

	// Dispatch canonical event via shared exec handler.
	if r.Dispatcher != nil {
		raw := exechandler.RawExecEvent{
			PID:       pid,
			PPID:      ppid,
			UID:       0,
			Comm:      comm,
			Exe:       exe,
			Args:      cmdline,
			SessionID: sessionID,
			Role:      role,
		}
		r.handler.Handle(raw)
	}
}

func (r *ExecRunner) handleExit(ev ProcEvent, tracker *lineage.LineageTracker) {
	pid := ev.PID
	if !tracker.IsAI(pid) {
		return
	}

	// Use cached metadata from exec time — the process may already be reaped.
	var sessionIDStr string
	if cached, ok := r.metaCache.LoadAndDelete(pid); ok {
		m := cached.(procMeta)
		sessionIDStr = strconv.FormatUint(uint64(m.sessionID), 10)
	} else {
		// Fallback: try live lookup (works if process is still a zombie).
		sessionIDStr = strconv.FormatUint(uint64(procinfo.DetectSessionID(pid)), 10)
	}

	// Dispatch canonical exit event.
	if r.Dispatcher != nil {
		ts := time.Now()
		exitEvt := event.Event{
			SchemaVersion: 1,
			Type:          "process_exit",
			Timestamp:     ts,
			HostID:        r.HostID,
			Source:        "kqueue",
			Actor: &event.Actor{
				PID:       int(pid),
				SessionID: sessionIDStr,
			},
		}
		exitEvt.ID = event.GenerateID(
			r.HostID,
			ts.UnixNano(),
			exitEvt.Source,
			exitEvt.Type,
			exitEvt.Actor.PID,
			"",
		)
		r.Dispatcher.Enqueue(exitEvt)
	}

	tracker.UnregisterProcess(pid)
}

func (r *ExecRunner) handleFork(ev ProcEvent, tracker *lineage.LineageTracker) {
	if !tracker.IsAI(ev.PID) {
		return
	}

	r.logger.Debug("AI process forked", "parent_pid", ev.PID)

	// kqueue NOTE_FORK doesn't provide the child PID directly.
	// Discover children via pgrep and register+watch them so we catch
	// their subsequent exec/exit events. The AddListener callback
	// registered in Start() handles the WatchPID call automatically
	// when RegisterProcess succeeds.
	//
	// Small delay: the child may not be visible in the process table
	// immediately after the fork syscall returns.
	go func() {
		time.Sleep(50 * time.Millisecond)
		children := procinfo.LookupChildPIDs(ev.PID)
		for _, childPID := range children {
			if tracker.IsAI(childPID) {
				continue // already tracked
			}
			childComm := ""
			if cmdline := procinfo.ReadProcCmdline(childPID); len(cmdline) > 0 {
				exe := cmdline[0]
				if idx := strings.LastIndex(exe, "/"); idx >= 0 {
					childComm = exe[idx+1:]
				} else {
					childComm = exe
				}
			}
			// RegisterProcess with correct PPID enables inheritance.
			// If it returns true (AI), the AddListener callback auto-watches the child.
			tracker.RegisterProcess(childPID, ev.PID, childComm)
		}
	}()
}

// Close releases kqueue resources.
func (r *ExecRunner) Close() error {
	return r.collector.Close()
}

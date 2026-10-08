//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/enforcer"
)

// Runner wraps the eBPF Collector to implement the collect.Collector interface.
// It reads raw exec events and dispatches canonical event.Event through ExecHandler.
//
// Invariant: All eBPF runners must share the same HostID and Dispatcher
// instance. Mixed dispatchers break correlation and ingest.
type Runner struct {
	collector      *Collector
	emit           collect.EventSink
	logger         *slog.Logger
	HostID         string
	Dispatcher     dispatch.Dispatcher
	dockerResolver *DockerResolver // nil-safe — nil on non-Docker hosts
	enforcer       *enforcer.Enforcer
}

// NewRunner creates a new eBPF Runner that reads exec events and dispatches canonical events via Enqueue.
// dockerResolver is optional (nil-safe) — pass nil on non-Docker hosts.
func NewRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher, dockerResolver *DockerResolver) (*Runner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if disp == nil {
		return nil, fmt.Errorf("dispatcher required")
	}
	if hostID == "" {
		hostID = "localhost"
	}

	collector, err := NewCollector(logger)
	if err != nil {
		return nil, err
	}

	return &Runner{
		collector:      collector,
		emit:           emit,
		logger:         logger,
		HostID:         hostID,
		Dispatcher:     disp,
		dockerResolver: dockerResolver,
	}, nil
}

// SetEnforcer attaches the soft-block enforcer to the exec runner.
func (r *Runner) SetEnforcer(e *enforcer.Enforcer) {
	r.enforcer = e
}

// splitArgs turns the raw argv blob captured by eBPF into tokens. eBPF might
// provide spaces instead of null bytes depending on how userland formatted argv.
func splitArgs(raw string) []string {
	if raw == "" {
		return nil
	}
	separator := "\x00"
	if !strings.Contains(raw[:len(raw)-1], "\x00") { // no inner nulls
		separator = " "
	}
	var out []string
	for _, p := range strings.Split(raw, separator) {
		if cleanP := strings.Trim(p, "\x00 "); cleanP != "" {
			out = append(out, cleanP)
		}
	}
	return out
}

// Start implements the collect.Collector interface.
// It starts the eBPF collector; each raw exec event is passed to ExecHandler.Handle (canonical event + dispatch).
func (r *Runner) Start(ctx context.Context) {
	go r.collector.Start(ctx)

	r.logger.Info("eBPF runner started, dispatching canonical exec events")

	handler := &ExecHandler{
		HostID:     r.HostID,
		Dispatcher: r.Dispatcher,
	}
	tracker := GetLineageTracker()
	debug := r.logger.Enabled(ctx, slog.LevelDebug)

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("eBPF runner stopping")
			r.collector.Close()
			return
		case ev := <-r.collector.Events():
			// Build cmdline FIRST: we need it for AI pattern matching below.
			// AI tools like Claude Code, aider, LangChain run under generic runtimes
			// (node, python) where ev.Comm is just "node"/"python" — the cmdline
			// contains the actual tool name (e.g. "node /path/to/claude", "python -m aider").
			cmdlineArgs := splitArgs(ev.Args)

			// Sometimes eBPF only captures the binary name due to argument races during failed PATH executions
			if len(cmdlineArgs) == 0 || (len(cmdlineArgs) == 1 && cmdlineArgs[0] == ev.Comm) {
				// Fallback: read /proc/PID/cmdline (may lose args for very fast processes, but saves most long-lived ones)
				if procArgs := readProcCmdline(ev.PID); len(procArgs) > 0 {
					cmdlineArgs = procArgs
				}
			}

			// FILTER: Only proceed if this is an AI process or descendant.
			// fork_runner usually registers PIDs before execsnoop sees them;
			// RegisterProcessWithCommand covers the root AI process (inherit
			// first, then comm/exe/argv token matching).
			isAI := tracker.IsAI(ev.PID) ||
				tracker.RegisterProcessWithCommand(ev.PID, ev.PPID, ev.Comm, ev.Filename, cmdlineArgs)

			// If comm/cmdline didn't match, check Docker container name/image.
			// This catches AI tools like OpenClaw running inside containers where
			// the kernel comm is "python" but the container name is "liberty-claws".
			// The cgroup lookup is done at most once per exec.
			var containerID string
			containerResolved := false
			if !isAI && r.dockerResolver != nil {
				containerID = DetectContainerID(ev.PID)
				containerResolved = true
				if containerID != "" {
					if aiType, ok := r.dockerResolver.MatchContainerPatterns(containerID, tracker); ok {
						tracker.MarkAIWithType(ev.PID, ev.PPID, aiType)
						isAI = true
					}
				}
			}

			if !isAI {
				continue
			}

			// Resolve full executable path from /proc/[pid]/exe
			fullPath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", ev.PID))
			if err != nil {
				fullPath = ev.Filename // fallback if process already exited
				if fullPath == "" {
					fullPath = ev.Comm
				}
			}

			// Detect container ID and session ID
			if !containerResolved {
				containerID = DetectContainerID(ev.PID)
			}
			sessionID := detectSessionID(ev.PID)
			aiSessionID, aiType, _ := tracker.AIContext(ev.PID)

			// Soft-block check — kill process if it matches a block rule.
			blocked := applyBlockRule(r.enforcer, r.emit, r.logger, "process_exec", ev.PID, fullPath,
				map[string]any{"exe_path": fullPath, "cmdline": strings.Join(cmdlineArgs, " ")})

			if debug {
				r.logger.Debug("exec captured",
					"pid", ev.PID, "comm", ev.Comm, "exe", fullPath,
					"args_from_ebpf", ev.Args != "", "cmdline", cmdlineArgs,
					"ai_type", aiType, "blocked", blocked)
			}

			role := CheckRole(ev.Comm)
			raw := RawExecEvent{
				TsNano:      int64(ev.TimestampNs),
				PID:         ev.PID,
				PPID:        ev.PPID,
				UID:         ev.UID,
				Comm:        ev.Comm,  // ← pass eBPF-captured short name
				Exe:         fullPath, // ← resolved full path
				Args:        cmdlineArgs,
				Cwd:         "",
				SessionID:   sessionID,
				ContainerID: containerID,
				Role:        role,
				AISessionID: aiSessionID,
				AIType:      aiType,
				Blocked:     blocked,
			}
			handler.Handle(raw)

			// Also send flat telemetry payload for the telemetry_events table
			payload := map[string]any{
				"pid":          ev.PID,
				"ppid":         ev.PPID,
				"gppid":        ev.GPPID,
				"uid":          ev.UID,
				"gid":          ev.GID,
				"exe":          fullPath,
				"comm":         ev.Comm,
				"pcomm":        ev.ParentComm,
				"argv0":        fullPath,
				"cmdline":      argvFor(cmdlineArgs, fullPath),
				"container_id": containerID,
				"session_id":   sessionID,
				"timestamp_ns": ev.TimestampNs,
				"role":         role,
			}
			tracker.Annotate(payload, ev.PID)
			if blocked {
				payload["action"] = "blocked"
			}
			_ = r.emit("process_exec", payload)
		}
	}
}

// argvFor returns args if non-empty, otherwise a single-element slice with fallback.
func argvFor(args []string, fallback string) []string {
	if len(args) > 0 {
		return args
	}
	return []string{fallback}
}

// Close releases eBPF resources.
func (r *Runner) Close() error {
	if r.collector != nil {
		return r.collector.Close()
	}
	return nil
}

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
)

// Runner wraps the eBPF Collector to implement the collect.Collector interface.
// It reads raw exec events and dispatches canonical event.Event through ExecHandler.
//
// Invariant: All eBPF runners (exec, accept, msg, etc.) must share the same HostID
// and Dispatcher instance. Mixed dispatchers break correlation and ingest.
type Runner struct {
	collector      *Collector
	emit           collect.EventSink
	logger         *slog.Logger
	HostID         string
	Dispatcher     dispatch.Dispatcher
	dockerResolver *DockerResolver // nil-safe — nil on non-Docker hosts
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

// Start implements the collect.Collector interface.
// It starts the eBPF collector; each raw exec event is passed to ExecHandler.Handle (canonical event + dispatch).
func (r *Runner) Start(ctx context.Context) {
	go r.collector.Start(ctx)

	r.logger.Info("eBPF runner started, dispatching canonical exec events")

	handler := &ExecHandler{
		HostID:     r.HostID,
		Dispatcher: r.Dispatcher,
	}

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
			var cmdlineArgs []string
			if ev.Args != "" {
				// eBPF might provide spaces instead of null bytes depending on how userland formatted argv
				separator := "\x00"
				if !strings.Contains(ev.Args[:len(ev.Args)-1], "\x00") { // Check if there are any inner nulls
					separator = " "
				}

				parts := strings.Split(ev.Args, separator)
				for _, p := range parts {
					// Clean up trailing nulls if it was space separated
					cleanP := strings.Trim(p, "\x00 ")
					if cleanP != "" {
						cmdlineArgs = append(cmdlineArgs, cleanP)
					}
				}
			}

			// Sometimes eBPF only captures the binary name due to argument races during failed PATH executions
			if len(cmdlineArgs) == 0 || (len(cmdlineArgs) == 1 && cmdlineArgs[0] == ev.Comm) {
				// Fallback: read /proc/PID/cmdline (may lose args for very fast processes, but saves most long-lived ones)
				if procArgs := readProcCmdline(ev.PID); len(procArgs) > 0 {
					cmdlineArgs = procArgs
				}
			}

			// FILTER: Only proceed if this is an AI process or descendant
			// Note: fork_runner registers PIDs before execsnoop sees them (usually),
			// but for the root AI process, we might need a direct check here too if fork missed it.
			tracker := GetLineageTracker()
			// We check if it's already tracked (descendant) OR if the comm itself is an AI pattern
			// This double check ensures we catch the "root" AI process (e.g. user typing 'cursor')
			isAI := tracker.IsAI(ev.PID)
			if !isAI {
				// Race condition or root process: try to register (checks pattern AND parent)
				isAI = tracker.RegisterProcess(ev.PID, ev.PPID, ev.Comm)
			}

			// If comm didn't match, check the full cmdline — catches AI tools running
			// under generic runtimes like "node /usr/lib/claude/cli.js" or "python -m aider"
			if !isAI {
				cmdlineStr := strings.Join(cmdlineArgs, " ")
				if cmdlineStr != "" && tracker.CheckPattern(cmdlineStr) {
					// Cmdline matched an AI pattern — register this PID
					tracker.MarkAI(ev.PID)
					isAI = true
					r.logger.Info("AI process detected via cmdline",
						"pid", ev.PID, "comm", ev.Comm, "cmdline", cmdlineStr)
				}
			}

			// If comm and cmdline didn't match, check Docker container name/image.
			// This catches AI tools like OpenClaw running inside containers where
			// the kernel comm is "python" but the container name is "liberty-claws".
			if !isAI {
				containerID := DetectContainerID(ev.PID)
				if containerID != "" && r.dockerResolver.CheckContainerPatterns(containerID, tracker) {
					tracker.MarkAI(ev.PID)
					isAI = true
				}
			}

			if !isAI {
				continue
			}

			// Resolve full executable path from /proc/[pid]/exe
			exePath := fmt.Sprintf("/proc/%d/exe", ev.PID)
			fullPath, err := os.Readlink(exePath)
			if err != nil {
				fullPath = ev.Comm // fallback if process already exited
			}

			// Detect container ID and session ID
			containerID := DetectContainerID(ev.PID)
			sessionID := detectSessionID(ev.PID)

			r.logger.Info("exec captured",
				"pid", ev.PID, "comm", ev.Comm, "exe", fullPath,
				"args_from_ebpf", ev.Args != "", "cmdline", cmdlineArgs)

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
				Role:        CheckRole(ev.Comm),
				AISessionID: tracker.GetSessionID(ev.PID),
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
				"is_ai":        true,
				"role":         CheckRole(ev.Comm),
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

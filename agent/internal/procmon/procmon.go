//go:build linux

package procmon

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/model"
	"github.com/correlic/correlic-agent/internal/transport"
)

// Runner watches for new process executions and emits process_exec telemetry events.
// Linux-only for v1 (using /proc polling).
//
// Note: polling can miss short-lived processes; this runner prioritizes "interesting" processes
// (curl/wget, and shells running -c command strings that include curl/wget pipelines) so they
// are less likely to be dropped when a tick is noisy.
type Runner struct {
	Interval time.Duration
	Emit     collect.EventSink
	Scanner  *Scanner

	// soft limit to avoid storms; extra events will be dropped per tick
	MaxPerTick int

	// EmitInitialSnapshot, when true, emits all processes present at startup as process_exec
	// events. Use when the agent runs inside a container so that processes that started
	// before the agent are still counted (otherwise Exec events stay 0 until something new execs).
	EmitInitialSnapshot bool

	Transport           transport.Transport
	AgentID             string
	ApprovalGateEnabled bool
}

// NewRunner creates a new Runner with the given interval and emit function.
func NewRunner(interval time.Duration, emit collect.EventSink) *Runner {
	return &Runner{
		Interval:   interval,
		Emit:       emit,
		Scanner:    NewScanner("/proc"),
		MaxPerTick: 200,
	}
}

// NewRunnerWithApprovals creates a Runner with approval gate checks enabled.
func NewRunnerWithApprovals(interval time.Duration, emit collect.EventSink, t transport.Transport, agentID string, approvalGateEnabled bool) *Runner {
	r := NewRunner(interval, emit)
	r.Transport = t
	r.AgentID = agentID
	r.ApprovalGateEnabled = approvalGateEnabled
	return r
}

// Start starts the procmon runner.
func (r *Runner) Start(ctx context.Context) {
	if runtime.GOOS != "linux" {
		slog.Info("procmon disabled (unsupported OS)", "os", runtime.GOOS)
		return
	}
	if r.Emit == nil || r.Scanner == nil {
		slog.Warn("procmon disabled (missing dependencies)")
		return
	}
	if r.Interval <= 0 {
		r.Interval = 10 * time.Second
	}
	if r.MaxPerTick <= 0 {
		r.MaxPerTick = 200
	}

	// Prime state. Optionally emit existing processes so container restarts show execs.
	prev, err := r.Scanner.Snapshot()
	if err != nil {
		slog.Warn("procmon initial snapshot failed", "error", err)
		prev = make(map[int]procKey)
	}
	if r.EmitInitialSnapshot && len(prev) > 0 {
		cap := r.MaxPerTick
		if cap <= 0 {
			cap = 200
		}
		if cap > 500 {
			cap = 500
		}
		emitted := 0
		for pid := range prev {
			if emitted >= cap {
				break
			}
			info, err := r.Scanner.ReadProcess(pid)
			if err != nil {
				continue
			}
			payload := map[string]any{
				"pid":     info.PID,
				"ppid":    info.PPID,
				"uid":     info.UID,
				"exe":     info.Exe,
				"comm":    info.Comm,
				"pcomm":   "", // parent comm not read here to avoid extra /proc reads
				"argv":    info.Argv,
				"argv0":   info.Argv0,
				"trunc":   info.Truncated,
				"startid": info.StartTimeTicks,
			}
			if r.Emit("process_exec", payload) {
				emitted++
			}
		}
		if emitted > 0 {
			slog.Info("procmon emitted initial snapshot as process_exec", "count", emitted, "total_in_snapshot", len(prev))
		}
	}

	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			curr, err := r.Scanner.Snapshot()
			if err != nil {
				slog.Warn("procmon snapshot failed", "error", err)
				continue
			}

			// Read all changed processes first, then emit important ones before normal ones.
			var important []ProcInfo
			var normal []ProcInfo
			for pid, key := range curr {
				if pk, ok := prev[pid]; ok && pk == key {
					continue
				}
				info, err := r.Scanner.ReadProcess(pid)
				if err != nil {
					continue
				}
				if isImportantProc(info) {
					important = append(important, info)
				} else {
					normal = append(normal, info)
				}
			}

			emitted := 0
			emitOne := func(info ProcInfo) {
				approval, blocked := r.checkApproval(ctx, info)
				payload := map[string]any{
					"pid":     info.PID,
					"ppid":    info.PPID,
					"uid":     info.UID,
					"exe":     info.Exe,
					"comm":    info.Comm,
					"argv":    info.Argv,
					"argv0":   info.Argv0,
					"trunc":   info.Truncated,
					"startid": info.StartTimeTicks,
				}
				if approval != nil {
					if approval.ApprovalID != "" {
						payload["approval_id"] = approval.ApprovalID
					} else if len(approval.PendingIDs) > 0 {
						payload["approval_id"] = approval.PendingIDs[0]
					}
					if approval.Status != "" {
						payload["approval_status"] = approval.Status
					} else if approval.Restricted {
						payload["approval_status"] = "pending"
					}
					payload["approval_restricted"] = approval.Restricted
				}
				ok := r.Emit("process_exec", payload)
				if ok {
					emitted += 1
				}

				if blocked {
					r.killProcess(info)
				}

				// Derive higher-level git telemetry from process_exec (best-effort).
				// This enables endpoint identity graph + git-guard detections in the backend.
				if gp, ok := gitEventPayloadFromProc(info); ok {
					if approval != nil {
						if approval.ApprovalID != "" {
							gp["approval_id"] = approval.ApprovalID
						} else if len(approval.PendingIDs) > 0 {
							gp["approval_id"] = approval.PendingIDs[0]
						}
						if approval.Status != "" {
							gp["approval_status"] = approval.Status
						} else if approval.Restricted {
							gp["approval_status"] = "pending"
						}
					}
					_ = r.Emit("git_event", gp)
				}
			}

			for _, info := range important {
				if emitted >= r.MaxPerTick {
					break
				}
				emitOne(info)
			}
			for _, info := range normal {
				if emitted >= r.MaxPerTick {
					break
				}
				emitOne(info)
			}

			dropped := (len(important) + len(normal)) - emitted
			if dropped > 0 {
				slog.Warn(
					"procmon tick event cap reached; dropping",
					"max_per_tick", r.MaxPerTick,
					"dropped", dropped,
					"important_candidates", len(important),
					"total_candidates", len(important)+len(normal),
				)
			}

			prev = curr
		}
	}
}

func (r *Runner) checkApproval(ctx context.Context, info ProcInfo) (*model.ApprovalCheckResponse, bool) {
	if !r.ApprovalGateEnabled || r.Transport == nil || r.AgentID == "" {
		return nil, false
	}
	kind, subject, ok := approvalKindFromProc(info)
	if !ok {
		return nil, false
	}
	resp, err := r.Transport.CheckApproval(ctx, r.AgentID, kind, subject)
	if err != nil {
		slog.Debug("approval check failed", "error", err, "kind", kind)
		return nil, false
	}
	return resp, resp.Restricted
}

func (r *Runner) killProcess(info ProcInfo) {
	p, err := os.FindProcess(info.PID)
	if err != nil {
		slog.Warn("approval gate kill failed", "pid", info.PID, "error", err)
		return
	}
	if err := p.Kill(); err != nil {
		slog.Warn("approval gate kill failed", "pid", info.PID, "error", err)
		return
	}
	slog.Info("approval gate blocked process", "pid", info.PID, "comm", info.Comm)
}

func isImportantProc(info ProcInfo) bool {
	comm := strings.ToLower(info.Comm)
	argv0 := strings.ToLower(info.Argv0)
	joined := strings.ToLower(strings.Join(info.Argv, " "))

	// git operations are high-signal for the developer-focused roadmap (repo clone/remote/push).
	if filepath.Base(argv0) == "git" || comm == "git" || strings.HasPrefix(joined, "git ") {
		return true
	}

	// direct fetchers
	if strings.Contains(argv0, "curl") || strings.Contains(comm, "curl") || strings.HasPrefix(joined, "curl ") {
		return true
	}
	if strings.Contains(argv0, "wget") || strings.Contains(comm, "wget") || strings.HasPrefix(joined, "wget ") {
		return true
	}

	// shell wrappers (especially useful for polling): look for -c command strings containing curl/wget + pipe-to-shell
	isShell := argv0 == "sh" || strings.HasSuffix(argv0, "/sh") || comm == "sh" ||
		argv0 == "bash" || strings.HasSuffix(argv0, "/bash") || strings.Contains(comm, "bash") || strings.Contains(comm, "dash")
	if isShell && strings.Contains(joined, " -c ") {
		if strings.Contains(joined, "curl ") || strings.Contains(joined, "wget ") {
			// prefer actual pipe-to-shell patterns
			if strings.Contains(joined, "|") && (strings.Contains(joined, "| sh") || strings.Contains(joined, "| bash") || strings.Contains(joined, "|bash")) {
				return true
			}
			// also important: bash -c $(curl ...) bootstrap
			if strings.Contains(joined, "$(curl") || strings.Contains(joined, "$( wget") || strings.Contains(joined, "$(wget") {
				return true
			}
		}
	}

	return false
}

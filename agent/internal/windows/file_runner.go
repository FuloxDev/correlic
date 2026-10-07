//go:build windows

package windows

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/enforcer"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/pathfilter"
	"github.com/correlic/correlic-agent/internal/procinfo"
)

// FileRunner consumes FileCollector events and emits canonical file_open events.
type FileRunner struct {
	collector  *FileCollector
	emit       collect.EventSink
	logger     *slog.Logger
	hostID     string
	dispatcher dispatch.Dispatcher
	etwTracker *ETWFileTracker // optional; records ETW-reported paths for USN dedup
	enforcer   *enforcer.Enforcer
}

// SetEnforcer attaches the soft-block enforcer to the file runner.
func (r *FileRunner) SetEnforcer(e *enforcer.Enforcer) {
	r.enforcer = e
}

// SetETWTracker attaches a tracker so USN reconciler knows which files ETW reported.
func (r *FileRunner) SetETWTracker(t *ETWFileTracker) {
	r.etwTracker = t
}

// NewFileRunner creates an ETW-based file runner.
func NewFileRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) *FileRunner {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}
	return &FileRunner{
		collector:  NewFileCollector(),
		emit:       emit,
		logger:     logger,
		hostID:     hostID,
		dispatcher: disp,
	}
}

// Collector returns the underlying FileCollector for ETW session registration.
func (r *FileRunner) Collector() *FileCollector {
	return r.collector
}

// Start processes file events until ctx is cancelled.
func (r *FileRunner) Start(ctx context.Context) {
	r.logger.Info("windows file runner started (ETW Kernel-File)")
	tracker := lineage.GetLineageTracker()

	var total, ignored, nonAI, emitted uint64
	for {
		select {
		case <-ctx.Done():
			r.logger.Info("windows file runner stopping")
			return
		case ev, ok := <-r.collector.Events():
			if !ok {
				return
			}
			total++

			// Noise filter: skip high-volume/low-value paths.
			if pathfilter.ShouldIgnorePath(ev.FilePath) {
				ignored++
				continue
			}

			// Only report file access by tracked AI processes.
			// Fallback: if PID isn't tracked yet, try to register it via
			// PPID lookup — same pattern as NetworkRunner. This handles the
			// race where ETW file events arrive before the process exec event
			// registers the PID, or after the process has exited (grace period
			// in the lineage tracker covers the latter case).
			if !tracker.IsAI(ev.PID) {
				ppid := procinfo.LookupPPID(ev.PID)
				cmdline := procinfo.ReadProcCmdline(ev.PID)
				comm := ""
				if len(cmdline) > 0 {
					comm = cmdline[0]
				}
				if !tracker.RegisterProcess(ev.PID, ppid, comm) {
					nonAI++
					continue
				}
			}
			emitted++

			category := pathfilter.CategorizeCredentialPath(ev.FilePath)

			if r.enforcer != nil && r.enforcer.IsEnabled() {
				fileForMatch := filepath.ToSlash(ev.FilePath)
				if blocked, rule := r.enforcer.ShouldBlock("file_open", fileForMatch); blocked {
					start := time.Now()
					success, killErr := r.enforcer.Kill(ev.PID, rule.KillTree)
					latency := time.Since(start)
					r.logger.Warn("BLOCKED file access",
						"pid", ev.PID, "path", fileForMatch, "rule_id", rule.ID,
						"success", success, "latency", latency)
					if r.emit != nil {
						r.emit("block_event", map[string]any{
							"rule_id":     rule.ID,
							"signal_type": "file_open",
							"pid":         int(ev.PID),
							"path":        fileForMatch,
							"success":     success,
							"error_msg":   errStr(killErr),
							"latency_us":  latency.Microseconds(),
						})
					}
					// Don't return — still dispatch the event for visibility
				}
			}

			if r.emit != nil {
				r.emit("file_open", map[string]any{
					"pid":      ev.PID,
					"path":     ev.FilePath,
					"category": category,
					"source":   "etw_kernel_file",
					"is_ai":    true,
				})
			}

			if r.dispatcher != nil {
				ts := time.Now()
				// Convert forward-slash path back to OS path for stat.
				osPath := ev.FilePath // already forward-slash; os.Stat accepts both on Windows
				info, err := os.Stat(osPath)
				if err != nil {
					// File doesn't exist — path resolution probe (e.g. Git Bash
					// MSYS2 paths /c/Users/... resolved as C:\c\Users\...) or
					// race condition (file deleted between ETW event and stat).
					// These generate noise with no security value; skip them.
					continue
				}
				if info.IsDir() {
					continue // skip directory events
				}
				fileSize := info.Size()
				canonEvt := event.Event{
					SchemaVersion: 1,
					Type:          "file_open",
					Timestamp:     ts,
					HostID:        r.hostID,
					Source:        "etw_kernel_file",
					Actor:         &event.Actor{PID: int(ev.PID)},
					Target: &event.Target{
						FilePath: ev.FilePath,
						FileSize: fileSize,
					},
					Context: map[string]any{
						"category":    category,
						"file_exists": true,
					},
				}
				if aiSess := tracker.GetSessionID(ev.PID); aiSess != "" {
					canonEvt.Context["ai_session_id"] = aiSess
				}
				if aiType := tracker.GetAIType(ev.PID); aiType != "" {
					canonEvt.Context["ai_type"] = aiType
				}
				canonEvt.ID = event.GenerateID(
					r.hostID, ts.UnixNano(),
					canonEvt.Source, canonEvt.Type,
					canonEvt.Actor.PID, ev.FilePath,
				)
				r.dispatcher.Enqueue(canonEvt)
				// Record for USN dedup so reconciler doesn't re-emit.
				if r.etwTracker != nil {
					r.etwTracker.Record(ev.FilePath)
				}
			}
		}
	}
}

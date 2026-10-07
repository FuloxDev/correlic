//go:build darwin && esf

package esf

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/pathfilter"
	"github.com/correlic/correlic-agent/internal/procinfo"
)

// FileRunner converts ESF NOTIFY_OPEN events into canonical file_open events.
// Unlike the FSEvents polling collector (Phase 1), ESF provides:
//   - Real PID for every file access (fixes the PID=0 limitation)
//   - Real-time notification (<1ms latency vs 2s polling)
//   - All file opens, not just mtime changes
type FileRunner struct {
	collector *Collector
	emit      collect.EventSink
	logger    *slog.Logger
	hostID    string
	disp      dispatch.Dispatcher
}

// NewFileRunner creates an ESF-based file access runner.
func NewFileRunner(collector *Collector, emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) *FileRunner {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}
	return &FileRunner{
		collector: collector,
		emit:      emit,
		logger:    logger,
		hostID:    hostID,
		disp:      disp,
	}
}

// Start processes file open events from the ESF collector.
func (r *FileRunner) Start(ctx context.Context) {
	r.logger.Info("esf file runner started")
	tracker := lineage.GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("esf file runner stopping")
			return

		case ev, ok := <-r.collector.OpenEvents():
			if !ok {
				return
			}

			// Noise filter.
			if pathfilter.ShouldIgnorePath(ev.FilePath) {
				continue
			}

			// Lineage filter — only track AI process file access.
			if !tracker.IsAI(ev.PID) {
				ppid := procinfo.LookupPPID(ev.PID)
				if !tracker.RegisterProcess(ev.PID, ppid, ev.Comm) {
					continue
				}
			}

			category := pathfilter.CategorizeCredentialPath(ev.FilePath)

			// Flat telemetry.
			if r.emit != nil {
				r.emit("file_open", map[string]any{
					"pid":        ev.PID,
					"ppid":       ev.PPID,
					"comm":       ev.Comm,
					"path":       ev.FilePath,
					"open_flags": ev.OpenFlags,
					"category":   category,
					"source":     "esf",
					"is_ai":      true,
				})
			}

			// Canonical event — PID is now populated (fixes Phase 1 PID=0 issue).
			if r.disp != nil {
				ts := time.Now()
				sessionID := procinfo.DetectSessionID(ev.PID)

				var fileSize int64 = -1
				if info, err := os.Stat(ev.FilePath); err == nil {
					fileSize = info.Size()
				}

				canonEvt := event.Event{
					SchemaVersion: 1,
					Type:          "file_open",
					Timestamp:     ts,
					HostID:        r.hostID,
					Source:        "esf",
					Actor: &event.Actor{
						PID:       int(ev.PID),
						PPID:      int(ev.PPID),
						Comm:      ev.Comm,
						SessionID: strconv.FormatUint(uint64(sessionID), 10),
					},
					Target: &event.Target{
						FilePath: ev.FilePath,
						FileSize: fileSize,
					},
					Context: map[string]any{
						"category":   category,
						"open_flags": ev.OpenFlags,
					},
				}
				canonEvt.ID = event.GenerateID(r.hostID, ts.UnixNano(), "esf", "file_open", int(ev.PID), ev.FilePath)
				r.disp.Enqueue(canonEvt)
			}
		}
	}
}

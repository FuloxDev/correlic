package esevents

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

// FileRunner converts Endpoint Security open events into canonical file_open
// events. Unlike the FSEvents polling collector, Endpoint Security provides:
//   - The real PID for every file access (the polling path reports PID 0)
//   - Real-time notification instead of a 2 s poll
//   - All file opens, not only mtime changes
type FileRunner struct {
	src    EventSource
	source string
	emit   collect.EventSink
	logger *slog.Logger
	hostID string
	disp   dispatch.Dispatcher
}

// NewFileRunner creates a file access runner over src. source names the
// collector ("esf" or "eslogger") in the emitted events.
func NewFileRunner(src EventSource, source string, emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) *FileRunner {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}
	if source == "" {
		source = "esf"
	}
	return &FileRunner{
		src:    src,
		source: source,
		emit:   emit,
		logger: logger,
		hostID: hostID,
		disp:   disp,
	}
}

// Start processes file open events until ctx is cancelled or the source closes.
func (r *FileRunner) Start(ctx context.Context) {
	r.logger.Info("file runner started", "source", r.source)
	tracker := lineage.GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("file runner stopping", "source", r.source)
			return

		case ev, ok := <-r.src.Events():
			if !ok {
				return
			}

			// Noise filter.
			if pathfilter.ShouldIgnorePath(ev.FilePath) {
				continue
			}

			// Lineage filter: only track AI process file access. The event
			// carries the parent PID; ps(1) is only consulted when it does
			// not, so the (high-volume) open stream never forks per event.
			if !tracker.IsAI(ev.PID) {
				ppid := ev.PPID
				if ppid == 0 {
					ppid = lookupPPID(ev.PID)
				}
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
					"source":     r.source,
					"is_ai":      true,
				})
			}

			// Canonical event with the real PID.
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
					Source:        r.source,
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
				tracker.Annotate(canonEvt.Context, ev.PID)
				canonEvt.ID = event.GenerateID(r.hostID, ts.UnixNano(), r.source, "file_open", int(ev.PID), ev.FilePath)
				r.disp.Enqueue(canonEvt)
			}
		}
	}
}

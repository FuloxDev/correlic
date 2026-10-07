//go:build darwin

package darwin

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/pathfilter"
)

// FileRunner monitors file access in sensitive directories and dispatches canonical events.
type FileRunner struct {
	collector  *FSEventsCollector
	emit       collect.EventSink
	logger     *slog.Logger
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// NewFileRunner creates a new FSEvents-based file runner.
func NewFileRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher, watchPaths []string, interval time.Duration) *FileRunner {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}

	collector := NewFSEventsCollector(
		logger.With("component", "fsevents"),
		watchPaths,
		interval,
	)

	return &FileRunner{
		collector:  collector,
		emit:       emit,
		logger:     logger,
		HostID:     hostID,
		Dispatcher: disp,
	}
}

// Start implements the collect.Collector interface.
func (r *FileRunner) Start(ctx context.Context) {
	go r.collector.Start(ctx)

	r.logger.Info("darwin file runner started (fsevents polling)")

	tracker := lineage.GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("darwin file runner stopping")
			return
		case fileEvt, ok := <-r.collector.Events():
			if !ok {
				return
			}

			// Noise filter.
			if pathfilter.ShouldIgnorePath(fileEvt.Path) {
				continue
			}

			// On macOS polling, we don't know which PID accessed the file.
			// We attribute it to AI if any AI process is currently tracked.
			// Phase 2 (ESF) gives per-event PID.
			if !tracker.HasAnyAI() {
				continue
			}

			category := pathfilter.CategorizeCredentialPath(fileEvt.Path)

			// Flat telemetry.
			payload := map[string]any{
				"path":     fileEvt.Path,
				"category": category,
				"source":   "fsevents",
				"is_ai":    true,
			}
			if r.emit != nil {
				r.emit("file_open", payload)
			}

			// Canonical event.
			if r.Dispatcher != nil {
				ts := time.Now()

				var fileSize int64 = -1
				if info, err := os.Stat(fileEvt.Path); err == nil {
					if info.IsDir() {
						continue // skip directory events
					}
					fileSize = info.Size()
				}

				canonEvt := event.Event{
					SchemaVersion: 1,
					Type:          "file_open",
					Timestamp:     ts,
					HostID:        r.HostID,
					Source:        "fsevents",
					Actor: &event.Actor{
						PID:       0, // Unknown from polling; ESF will populate this.
						SessionID: "0", // Unknown — polling can't attribute to a specific session.
					},
					Target: &event.Target{
						FilePath: fileEvt.Path,
						FileSize: fileSize,
					},
					Context: map[string]any{
						"category": category,
					},
				}
				canonEvt.ID = event.GenerateID(
					r.HostID,
					ts.UnixNano(),
					canonEvt.Source,
					canonEvt.Type,
					canonEvt.Actor.PID,
					fileEvt.Path,
				)
				r.Dispatcher.Enqueue(canonEvt)
			}
		}
	}
}

//go:build windows

package windows

import (
	"context"
	"log/slog"
	"time"

	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/pathfilter"
)

// USNReconciler cross-references USN Journal events with ETW to catch
// file events that ETW dropped. Only emits when an AI process is active
// and ETW didn't already report the file.
type USNReconciler struct {
	reader     *USNReader
	tracker    *ETWFileTracker
	dispatcher dispatch.Dispatcher
	hostID     string
	logger     *slog.Logger
}

// NewUSNReconciler creates a reconciler that bridges USN and ETW file events.
func NewUSNReconciler(
	reader *USNReader,
	tracker *ETWFileTracker,
	disp dispatch.Dispatcher,
	hostID string,
	logger *slog.Logger,
) *USNReconciler {
	if logger == nil {
		logger = slog.Default()
	}
	return &USNReconciler{
		reader:     reader,
		tracker:    tracker,
		dispatcher: disp,
		hostID:     hostID,
		logger:     logger,
	}
}

// Run starts the reconciliation loop. Blocks until ctx is cancelled.
func (r *USNReconciler) Run(ctx context.Context) {
	usnCh := make(chan USNEvent, 4096)
	go r.reader.Run(ctx, usnCh)

	// Periodic cleanup of ETW tracker to prevent unbounded growth.
	cleanupTicker := time.NewTicker(10 * time.Second)
	defer cleanupTicker.Stop()

	lt := lineage.GetLineageTracker()
	var catchupEmitted, skippedNoAI, skippedETW, skippedPath uint64

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("USN reconciler stopping",
				"catchup_emitted", catchupEmitted,
				"skipped_no_ai", skippedNoAI,
				"skipped_etw_seen", skippedETW,
				"skipped_path_filter", skippedPath,
			)
			return

		case ev, ok := <-usnCh:
			if !ok {
				return
			}

			// Only care if an AI process is currently active.
			if !lt.HasAnyAI() {
				skippedNoAI++
				continue
			}

			// Skip if ETW already reported this file recently.
			if r.tracker.WasSeen(ev.FilePath) {
				skippedETW++
				continue
			}

			// Apply the same path noise filter as the ETW file runner.
			if pathfilter.ShouldIgnorePath(ev.FilePath) {
				skippedPath++
				continue
			}

			// Emit a catch-up file_open event.
			catchupEmitted++
			category := pathfilter.CategorizeCredentialPath(ev.FilePath)

			canonEvt := event.Event{
				SchemaVersion: 1,
				Type:          "file_open",
				Timestamp:     ev.Timestamp,
				HostID:        r.hostID,
				Source:        "usn_catchup",
				Actor:         &event.Actor{PID: 0}, // PID unknown from USN
				Target: &event.Target{
					FilePath: ev.FilePath,
					FileSize: 0, // unknown from USN
				},
				Context: map[string]any{
					"category":   category,
					"usn_reason": ev.Reason,
					"source":     "usn_catchup",
				},
			}
			canonEvt.ID = event.GenerateID(
				r.hostID, ev.Timestamp.UnixNano(),
				canonEvt.Source, canonEvt.Type,
				0, ev.FilePath,
			)
			r.dispatcher.Enqueue(canonEvt)

		case <-cleanupTicker.C:
			r.tracker.Cleanup()
		}
	}
}

//go:build linux

package ebpf

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/enforcer"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/pathfilter"
)

// FileRunner wraps the FileCollector to implement the collect.Collector interface.
// AI-focused: dispatches to Neo4j only for AI agent file access.
type FileRunner struct {
	collector  *FileCollector
	emit       collect.EventSink
	logger     *slog.Logger
	HostID     string
	Dispatcher dispatch.Dispatcher
	enforcer   *enforcer.Enforcer
}

// NewFileRunner creates a new file open monitoring runner.
// AI-focused: only AI-related file events are dispatched to Neo4j graph.
func NewFileRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) (*FileRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}

	collector, err := NewFileCollector(logger)
	if err != nil {
		return nil, err
	}

	return &FileRunner{
		collector:  collector,
		emit:       emit,
		logger:     logger,
		HostID:     hostID,
		Dispatcher: disp,
	}, nil
}

// SetEnforcer attaches the soft-block enforcer to the file runner.
func (r *FileRunner) SetEnforcer(e *enforcer.Enforcer) {
	r.enforcer = e
}

// Start implements the collect.Collector interface.
func (r *FileRunner) Start(ctx context.Context) {
	// Start the underlying collector
	go r.collector.Start(ctx)

	r.logger.Info("eBPF file runner started, forwarding credential access events")

	tracker := GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("eBPF file runner stopping")
			r.collector.Close()
			return
		case fileEvt := <-r.collector.Events():
			// FILTER: Noise reduction checks first (fastest)
			if pathfilter.ShouldIgnorePath(fileEvt.Filename) {
				continue
			}

			// FILTER: Only proceed if this is an AI process or descendant
			if !tracker.IsAI(fileEvt.PID) {
				// Race condition check: try to register via inheritance or pattern
				if !tracker.RegisterProcess(fileEvt.PID, fileEvt.PPID, fileEvt.Comm) {
					continue
				}
			}

			// Stat the file once to get its size for confidence scoring and to
			// skip directory opens. -1 signals "unknown" on any error (EPERM, race).
			var fileSize int64 = -1
			if info, err := os.Stat(fileEvt.Filename); err == nil {
				if info.IsDir() {
					continue // skip directory events
				}
				fileSize = info.Size()
			}

			category := pathfilter.CategorizeCredentialPath(fileEvt.Filename)

			// Soft-block check — kill process if the path matches a block rule.
			blocked := applyBlockRule(r.enforcer, r.emit, r.logger, "file_open", fileEvt.PID, fileEvt.Filename,
				map[string]any{"path": fileEvt.Filename})

			// Convert FileOpenEvent to telemetry format
			payload := map[string]any{
				"pid":        fileEvt.PID,
				"ppid":       fileEvt.PPID,
				"uid":        fileEvt.UID,
				"gid":        fileEvt.GID,
				"path":       fileEvt.Filename,
				"comm":       fileEvt.Comm,
				"flags":      fileEvt.Flags,
				"source":     "ebpf",
				"category":   category,
				"open_flags": int(fileEvt.Flags),
			}
			tracker.Annotate(payload, fileEvt.PID)
			if blocked {
				payload["action"] = "blocked"
			}

			ok := r.emit("file_open", payload)
			if !ok {
				r.logger.Debug("file event dropped by sink")
			}

			// Dispatch to Neo4j (Graph) - Always for AI processes now
			if r.Dispatcher != nil {
				ts := time.Now()
				canonicalEvent := event.Event{
					SchemaVersion: 1,
					Type:          "file_open",
					Timestamp:     ts,
					HostID:        r.HostID,
					Source:        "ebpf",
					Actor: &event.Actor{
						PID:       int(fileEvt.PID),
						PPID:      int(fileEvt.PPID),
						Comm:      fileEvt.Comm,
						SessionID: strconv.FormatUint(uint64(detectSessionID(fileEvt.PID)), 10),
					},
					Target: &event.Target{
						FilePath: fileEvt.Filename,
						FileSize: fileSize,
					},
					Context: map[string]any{
						"category":   category,
						"open_flags": int(fileEvt.Flags),
					},
				}
				tracker.Annotate(canonicalEvent.Context, fileEvt.PID)
				if blocked {
					canonicalEvent.Context["action"] = "blocked"
				}
				canonicalEvent.ID = event.GenerateID(
					r.HostID,
					ts.UnixNano(),
					canonicalEvent.Source,
					canonicalEvent.Type,
					canonicalEvent.Actor.PID,
					fileEvt.Filename,
				)
				r.Dispatcher.Enqueue(canonicalEvent)
			}
		}
	}
}

// Close releases eBPF resources.
func (r *FileRunner) Close() error {
	if r.collector != nil {
		return r.collector.Close()
	}
	return nil
}

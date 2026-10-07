//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
)

// ForkRunner wraps the ForkCollector to emit process tree events.
// AI-focused: dispatches to Neo4j only for AI agent process trees.
type ForkRunner struct {
	collector  *ForkCollector
	emit       collect.EventSink
	logger     *slog.Logger
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// NewForkRunner creates a new process tree tracking runner.
// AI-focused: only AI-related fork events are dispatched to Neo4j graph.
func NewForkRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) (*ForkRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}

	collector, err := NewForkCollector(logger)
	if err != nil {
		return nil, err
	}

	return &ForkRunner{
		collector:  collector,
		emit:       emit,
		logger:     logger,
		HostID:     hostID,
		Dispatcher: disp,
	}, nil
}

// Start implements the collect.Collector interface.
func (r *ForkRunner) Start(ctx context.Context) {
	// Start the underlying collector
	go r.collector.Start(ctx)

	// Start periodic tree summary
	go r.emitTreeSummary(ctx)

	r.logger.Info("eBPF fork runner started, tracking process tree")

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("eBPF fork runner stopping")
			r.collector.Close()
			return
		case forkEvt := <-r.collector.Events():
			// Skip events with parent_pid=0 - these are incomplete/corrupted events
			// from sys_enter_clone or exit tracepoints that shouldn't be emitted
			if forkEvt.ParentPID == 0 {
				r.logger.Debug("skipping fork event with parent_pid=0",
					"child_pid", forkEvt.ChildPID,
					"clone_flags", fmt.Sprintf("0x%X", forkEvt.CloneFlags))
				continue
			}

			// Skip exit events - they're handled by the dedicated exit collector
			if forkEvt.IsExit() {
				continue
			}

			// Determine event type
			eventType := "fork"
			if forkEvt.IsThread() {
				eventType = "thread"
				// No longer skipping threads. We need them to maintain the lineage
				// for child processes spawned by these threads.
			}

			// Register with LineageTracker
			tracker := GetLineageTracker()
			// For threads/forks, the child initially shares the parent's comm
			// or has its own set via prctl (captured in ChildComm)
			isAI := tracker.RegisterProcess(forkEvt.ChildPID, forkEvt.ParentPID, forkEvt.ChildComm)

			// FILTER: Only proceed if this is an AI process or descendant
			if !isAI {
				continue
			}

			// Detect container and session for enrichment
			containerID := DetectContainerID(forkEvt.ChildPID)
			sessionID := detectSessionID(forkEvt.ChildPID)

			// Convert ForkEvent to telemetry format
			payload := map[string]any{
				"event":        eventType,
				"parent_pid":   forkEvt.ParentPID,
				"parent_tgid":  forkEvt.ParentTGID,
				"child_pid":    forkEvt.ChildPID,
				"child_tgid":   forkEvt.ChildTGID,
				"uid":          forkEvt.UID,
				"parent_comm":  forkEvt.ParentComm,
				"child_comm":   forkEvt.ChildComm,
				"is_fork":      forkEvt.IsFork(),
				"container_id": containerID,         // Container context
				"session_id":   sessionID,           // Session tracking
				"timestamp_ns": forkEvt.TimestampNs, // Precise timestamp
				"source":       "ebpf",
				"is_ai":        true, // Explicit flag
			}

			ok := r.emit("process_tree", payload)
			if !ok {
				r.logger.Debug("process tree event dropped by sink")
			}

			// Dispatch to Neo4j (Graph) - Always for AI processes now
			if r.Dispatcher != nil {
				ts := time.Now()

				// For threads/helper processes that don't exec, we emit a 'process_exec'
				// event representing the start of this thread/process.
				// This ensures it becomes a node in the graph that children can link to.

				// Use "process_exec" for graph compatibility so it looks like a process node.
				graphEventType := "process_exec"

				// Actor is the CHILD (the thread/process being created)
				canonicalEvent := event.Event{
					SchemaVersion: 1,
					Type:          graphEventType,
					Timestamp:     ts,
					HostID:        r.HostID,
					Source:        "ebpf",
					Actor: &event.Actor{
						PID:       int(forkEvt.ChildPID),
						PPID:      int(forkEvt.ParentPID),
						Comm:      forkEvt.ChildComm,
						SessionID: strconv.FormatUint(uint64(sessionID), 10),
					},
					Context: map[string]any{
						"is_thread":      forkEvt.IsThread(),
						"child_tgid":     forkEvt.ChildTGID,
						"parent_comm":    forkEvt.ParentComm,
						"container_id":   containerID,
						"synthetic_exec": true, // Flag to identify and filter these from UI activity stream
					},
				}

				// Generate a deterministic ID
				if aiSess := tracker.GetSessionID(forkEvt.ChildPID); aiSess != "" {
					canonicalEvent.Context["ai_session_id"] = aiSess
				}
				canonicalEvent.ID = event.GenerateID(
					r.HostID,
					ts.UnixNano(),
					canonicalEvent.Source,
					canonicalEvent.Type,
					canonicalEvent.Actor.PID,
					forkEvt.ChildComm,
				)
				r.Dispatcher.Enqueue(canonicalEvent)
			}
		}
	}
}

// emitTreeSummary sends a periodic summary of the process tree.
func (r *ForkRunner) emitTreeSummary(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tree := r.collector.GetTree()
			if len(tree) == 0 {
				continue
			}

			// Build summary: only active processes
			active := make([]map[string]any, 0)
			for _, node := range tree {
				if node.EndTime == nil { // Still running
					active = append(active, map[string]any{
						"pid":        node.PID,
						"ppid":       node.PPID,
						"comm":       node.Comm,
						"uid":        node.UID,
						"start_time": node.StartTime.Unix(),
						"children":   node.Children,
					})
				}
			}

			if len(active) == 0 {
				continue
			}

			payload := map[string]any{
				"event":        "tree_summary",
				"active_count": len(active),
				"total_seen":   len(tree),
				"processes":    active,
				"source":       "ebpf",
			}

			r.emit("process_tree", payload)
		}
	}
}

// Close releases eBPF resources.
func (r *ForkRunner) Close() error {
	if r.collector != nil {
		return r.collector.Close()
	}
	return nil
}

// GetTree returns the current process tree for visualization.
func (r *ForkRunner) GetTree() map[uint32]*ProcessNode {
	return r.collector.GetTree()
}

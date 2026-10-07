package correlation

import (
	"context"
	"fmt"
	"log"

	"github.com/correlic/correlic-backend/internal/event"
)

// ProcessTreePersister is the interface for real-time process tree persistence (Tier 1).
// Implementations upsert process_exec nodes and link them to their parent immediately.
type ProcessTreePersister interface {
	// UpsertProcessAndLink creates the event node and links it to its parent process.
	UpsertProcessAndLink(ctx context.Context, evt *event.Event) error
	// PropagateAILabels walks PROCESS_PARENT edges and labels children of AI agents.
	PropagateAILabels(ctx context.Context, hostID string) (int, error)
}

// ProcessTreeWriter handles Tier 1 correlation: real-time process tree structure.
// Every process_exec event is immediately written to Neo4j with its parent link.
// This ensures the process tree is always correct regardless of batch boundaries.
type ProcessTreeWriter struct {
	persister ProcessTreePersister
}

// NewProcessTreeWriter creates a new process tree writer.
func NewProcessTreeWriter(persister ProcessTreePersister) *ProcessTreeWriter {
	return &ProcessTreeWriter{persister: persister}
}

// isProcessTreeEvent returns true if the event type is part of process tree structure.
func isProcessTreeEvent(eventType string) bool {
	switch eventType {
	case "process_exec", "process_exit", "process_fork":
		return true
	default:
		return false
	}
}

// IngestProcess handles a single process lifecycle event.
// For process_exec: creates the node and links to parent in Neo4j.
// For process_exit: currently a no-op for tree structure (exit edges are handled by Tier 2).
// This method is safe for concurrent use.
func (w *ProcessTreeWriter) IngestProcess(ctx context.Context, evt *event.Event) error {
	if evt == nil || evt.Process == nil {
		return nil
	}

	switch evt.Type {
	case "process_exec":
		return w.ingestExec(ctx, evt)
	case "process_exit":
		// process_exit doesn't affect tree structure (parent-child).
		// The lifecycle edge (exec → exit) is still created by Tier 2 batched correlation.
		return nil
	default:
		return nil
	}
}

// ingestExec handles a process_exec event: upsert node + link to parent + propagate AI labels.
func (w *ProcessTreeWriter) ingestExec(ctx context.Context, evt *event.Event) error {
	// Upsert the node and create PROCESS_PARENT edge
	if err := w.persister.UpsertProcessAndLink(ctx, evt); err != nil {
		return fmt.Errorf("process tree write failed for PID %d: %w", evt.Process.PID, err)
	}

	// Propagate AI labels through the tree.
	// This is cheap: it only labels unlabeled descendants of already-known AI agents.
	if evt.HostID != "" {
		if count, err := w.persister.PropagateAILabels(ctx, evt.HostID); err != nil {
			log.Printf("WARN: AI label propagation failed for host %s: %v", evt.HostID, err)
		} else if count > 0 {
			log.Printf("Propagated AI labels to %d processes on host %s", count, evt.HostID)
		}
	}

	return nil
}

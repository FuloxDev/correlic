package correlation

import (
	"context"
	"errors"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/storage/eventstore"
)

var ErrAnchorNotFound = errors.New("anchor event not found")

// Builder builds a time-windowed context around an anchor event.
type Builder struct {
	Store      eventstore.EventStore
	GraphStore GraphPersister // Optional: persist correlation graphs to Neo4j
}

// GraphPersister persists correlation graphs (e.g., to Neo4j).
// If nil, graph persistence is skipped (correlation still works in-memory).
type GraphPersister interface {
	PersistGraph(ctx context.Context, events []event.Event, graph *EventGraph) error
	// PropagateAILabels walks PROCESS_PARENT edges and labels children of AI agents.
	// Returns the number of nodes labeled. Called after PersistGraph.
	PropagateAILabels(ctx context.Context, hostID string) (int, error)
}

// Build produces a CorrelatedContext for the given anchor event ID and time window.
// The anchor event is included in the returned events; ordering is by timestamp ascending.
func (b *Builder) Build(ctx context.Context, eventID string, window time.Duration) (CorrelatedContext, error) {
	anchor, err := b.Store.GetByID(ctx, eventID)
	if err != nil {
		return CorrelatedContext{}, err
	}
	if anchor == nil {
		return CorrelatedContext{}, ErrAnchorNotFound
	}
	return b.BuildWindow(ctx, *anchor, window)
}

// BuildWindow produces a CorrelatedContext around an anchor event and time window.
func (b *Builder) BuildWindow(
	ctx context.Context,
	anchor event.Event,
	window time.Duration,
) (CorrelatedContext, error) {
	start := anchor.Timestamp.Add(-window)
	end := anchor.Timestamp.Add(window)

	events, err := b.Store.GetRange(ctx, anchor.HostID, start, end)
	if err != nil {
		return CorrelatedContext{}, err
	}

	OrderEvents(events)
	graph := BuildGraph(events)

	// Persist graph to Neo4j (optional, non-blocking)
	if b.GraphStore != nil {
		if err := b.GraphStore.PersistGraph(ctx, events, graph); err != nil {
			// Log error but don't fail the request (Neo4j is secondary storage)
			// TODO: Add proper logging when logger is available
			_ = err
		}
	}

	return CorrelatedContext{
		Anchor:      anchor,
		WindowStart: start,
		WindowEnd:   end,
		Events:      events,
		Graph:       graph,
	}, nil
}

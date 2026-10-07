package neo4j

import (
	"context"

	"github.com/correlic/correlic-backend/internal/correlation"
	"github.com/correlic/correlic-backend/internal/event"
)

// GraphPersister implements correlation.GraphPersister for Neo4j.
type GraphPersister struct {
	store *GraphStore
}

// NewGraphPersister creates a new Neo4j graph persister.
func NewGraphPersister(store *GraphStore) *GraphPersister {
	return &GraphPersister{store: store}
}

// PersistGraph persists a correlation graph to Neo4j.
func (p *GraphPersister) PersistGraph(ctx context.Context, events []event.Event, graph *correlation.EventGraph) error {
	if graph == nil {
		return nil
	}

	// Convert events to pointers
	var eventPtrs []*event.Event
	for i := range events {
		eventPtrs = append(eventPtrs, &events[i])
	}

	// Convert correlation edges to Neo4j edges
	var neo4jEdges []Edge
	for _, edge := range graph.Edges {
		neo4jEdges = append(neo4jEdges, Edge{
			From: edge.From,
			To:   edge.To,
			Type: edge.Type,
		})
	}

	// Persist to Neo4j
	if err := p.store.CreateGraph(ctx, eventPtrs, neo4jEdges); err != nil {
		return err
	}

	// Note: LinkOrphans is no longer called here.
	// Tier 1 (ProcessTreeWriter) handles process tree linking in real-time,
	// creating PROCESS_PARENT edges immediately during event ingestion.
	// The batched path (Tier 2) only handles activity edges (file, network, temporal).

	// Propagate AI labels through process tree for all hosts in this batch
	hostIDs := make(map[string]bool)
	for _, evt := range events {
		if evt.HostID != "" {
			hostIDs[evt.HostID] = true
		}
	}
	for hostID := range hostIDs {
		if count, err := p.PropagateAILabels(ctx, hostID); err == nil && count > 0 {
			// Labeled some processes - this is informational
			_ = count
		}
	}

	return nil
}

// PropagateAILabels walks PROCESS_PARENT edges and labels children of AI agents.
func (p *GraphPersister) PropagateAILabels(ctx context.Context, hostID string) (int, error) {
	return p.store.PropagateAILabels(ctx, hostID)
}

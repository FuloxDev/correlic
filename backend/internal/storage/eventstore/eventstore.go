package eventstore

import (
	"context"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

// EventStore appends and queries canonical events by time range. Append-only; no mutation.
//
// The *ForOrg variants stamp / filter by tenant. Callers that know the org (ingest,
// authenticated API handlers) must use them; the unscoped methods remain for
// internal workers that operate on a host already resolved to an org.
type EventStore interface {
	Append(ctx context.Context, evt event.Event) error
	// AppendIdempotent inserts the event; if id already exists, does nothing (for live ingestion).
	AppendIdempotent(ctx context.Context, evt event.Event) error
	// AppendIdempotentForOrg is AppendIdempotent with the owning org recorded on the row.
	AppendIdempotentForOrg(ctx context.Context, orgID string, evt event.Event) error

	GetByID(ctx context.Context, id string) (*event.Event, error)
	// GetByIDForOrg returns the event only if it belongs to orgID (or has no org recorded,
	// for rows written before org stamping existed). An empty orgID disables the filter.
	GetByIDForOrg(ctx context.Context, orgID string, id string) (*event.Event, error)

	GetRange(
		ctx context.Context,
		hostID string,
		from time.Time,
		to time.Time,
	) ([]event.Event, error)
	// GetRangeForOrg is GetRange restricted to orgID (empty orgID disables the filter).
	GetRangeForOrg(
		ctx context.Context,
		orgID string,
		hostID string,
		from time.Time,
		to time.Time,
	) ([]event.Event, error)
}

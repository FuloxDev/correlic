package eventstore

import (
	"context"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

// EventStore appends and queries canonical events by time range. Append-only; no mutation.
type EventStore interface {
	Append(ctx context.Context, evt event.Event) error
	// AppendIdempotent inserts the event; if id already exists, does nothing (for live ingestion).
	AppendIdempotent(ctx context.Context, evt event.Event) error

	GetByID(ctx context.Context, id string) (*event.Event, error)

	GetRange(
		ctx context.Context,
		hostID string,
		from time.Time,
		to time.Time,
	) ([]event.Event, error)
}

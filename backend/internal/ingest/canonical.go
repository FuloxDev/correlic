package ingest

import (
	"context"

	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/storage/eventstore"
)

// IngestEvent appends one canonical event to the store. No validation beyond store.
func IngestEvent(ctx context.Context, store eventstore.EventStore, evt event.Event) error {
	return store.Append(ctx, evt)
}

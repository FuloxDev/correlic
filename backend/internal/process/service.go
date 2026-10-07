package process

import (
	"context"
	"time"

	"github.com/correlic/correlic-backend/internal/storage/eventstore"
)

// GetProcessLifecycles returns lifecycles that started within the time window for the host.
// Fetches events via store.GetRange, then builds lifecycles in memory. Read-only; no joins.
func GetProcessLifecycles(
	ctx context.Context,
	store eventstore.EventStore,
	hostID string,
	since, until time.Time,
) ([]*Lifecycle, error) {
	events, err := store.GetRange(ctx, hostID, since, until)
	if err != nil {
		return nil, err
	}
	return BuildLifecyclesFromEvents(events), nil
}

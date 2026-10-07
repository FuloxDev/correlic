package correlation

import (
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

// CorrelatedContext is the time-windowed context around an anchor event.
// Events are ordered by timestamp; Graph adds process_parent and temporal edges (in-memory, deterministic).
type CorrelatedContext struct {
	Anchor event.Event

	WindowStart time.Time
	WindowEnd   time.Time

	Events []event.Event
	Graph  *EventGraph
}

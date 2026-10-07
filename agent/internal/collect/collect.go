package collect

import "context"

// EventSink is the stable boundary between collectors and the rest of the agent.
// Collectors emit normalized event types + JSON-serializable payloads; the batcher/transport handle delivery.
type EventSink func(eventType string, payload any) bool

// Collector is a long-running telemetry source.
// Implementations should respect ctx cancellation and avoid panics.
type Collector interface {
	Start(ctx context.Context)
}

package event

import "time"

// Event is the canonical event model. It must match the agent's event.Event 1:1 for symmetry.
// No business logic; pure data only.
type Event struct {
	SchemaVersion int `json:"schema_version"`

	ID        string    `json:"id"`
	HostID    string    `json:"host_id"`
	Timestamp time.Time `json:"timestamp"`

	Source string `json:"source"`
	Type   string `json:"type"`

	Process *ActorStruct   `json:"actor,omitempty"` // process context; JSON "actor"
	Target  *TargetStruct  `json:"target,omitempty"`
	Context map[string]any `json:"context,omitempty"`

	// Style is a presentation hint for timeline UX only (e.g. "muted"). Response-only: do not store.
	// Set only at render time in the API. Persisting Style would be a regression.
	Style string `json:"style,omitempty"`

	// Lifecycle is process lifecycle summary for timeline UX (process_exec only). Response-only: do not store.
	Lifecycle *LifecycleInfo `json:"lifecycle,omitempty"`
}

// LifecycleInfo is a response-only summary attached to process_exec events in timeline.
type LifecycleInfo struct {
	DurationMs *int64 `json:"duration_ms,omitempty"`
	Exited     bool   `json:"exited"`
}

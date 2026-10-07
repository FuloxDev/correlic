package model

import (
	"encoding/json"
	"time"
)

// TelemetryEvent is a single structured event emitted by an agent.
type TelemetryEvent struct {
	// ID is assigned by the backend storage on ingest.
	// It is omitted on ingest requests from agents.
	ID string `json:"id,omitempty"`

	AgentID   string          `json:"agent_id"`
	EventType string          `json:"event_type"`
	Timestamp time.Time       `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`

	// ReceivedAt is assigned by the backend storage on ingest.
	// It is omitted on ingest requests from agents.
	ReceivedAt time.Time `json:"received_at,omitempty"`
}

// TelemetryBatch is a batch of events sent to the telemetry plane.
type TelemetryBatch struct {
	Events []TelemetryEvent `json:"events"`
}

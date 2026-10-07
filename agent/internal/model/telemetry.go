package model

import (
	"encoding/json"
	"time"
)

// TelemetryEvent is a single structured event emitted by the agent.
type TelemetryEvent struct {
	AgentID   string          `json:"agent_id"`
	EventType string          `json:"event_type"`
	Timestamp time.Time       `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
}

// TelemetryBatch is a batch of events sent to the telemetry plane.
type TelemetryBatch struct {
	Events []TelemetryEvent `json:"events"`
}


package model

import (
	"encoding/json"
	"time"
)

type AlertStatus string

const (
	AlertOpen   AlertStatus = "open"
	AlertAck    AlertStatus = "ack"
	AlertClosed AlertStatus = "closed"
)

type Alert struct {
	ID       string          `json:"id"`
	AgentID  string          `json:"agent_id"`
	RuleID   string          `json:"rule_id"`
	Severity string          `json:"severity"`
	Title    string          `json:"title"`
	EventTS  time.Time       `json:"event_ts"`
	Payload  json.RawMessage `json:"payload"`
	// TriggerEventIDs are telemetry event IDs (UUIDs) that triggered / contributed to this alert.
	TriggerEventIDs []string    `json:"trigger_event_ids,omitempty"`
	Status          AlertStatus `json:"status"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
	Note            string      `json:"note,omitempty"`
	AckedAt         *time.Time  `json:"acked_at,omitempty"`
	ClosedAt        *time.Time  `json:"closed_at,omitempty"`
}

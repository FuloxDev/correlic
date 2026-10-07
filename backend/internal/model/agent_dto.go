package model

import "time"

type AgentDTO struct {
	AgentID     string        `json:"agent_id"`
	UserID      *string       `json:"user_id,omitempty"` // Optional: user who owns this agent
	Hostname    string        `json:"hostname"`
	OS          string        `json:"os"`
	Profile     string        `json:"profile"`
	Version     string        `json:"version"`
	State       string        `json:"state"`
	Liveness    AgentLiveness `json:"liveness"`
	FirstSeenAt time.Time     `json:"first_seen_at"`
	LastSeenAt  time.Time     `json:"last_seen_at"`
}

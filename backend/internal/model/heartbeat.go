package model

import "time"

type HeartbeatPayload struct {
	AgentID   string    `json:"agent_id"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	Profile   string    `json:"profile"`
	Version   string    `json:"version"`
	State     string    `json:"state"`
	Timestamp time.Time `json:"timestamp"`
}

package model

import "time"

type Heartbeat struct {
	AgentID   string     `json:"agent_id"`
	Hostname  string     `json:"hostname"`
	OS        string     `json:"os"`
	Version   string     `json:"version"`
	Profile   string     `json:"profile"`
	State     AgentState `json:"state"`
	Timestamp time.Time  `json:"timestamp"`
}

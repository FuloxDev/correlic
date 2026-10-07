package model

import "time"

type Agent struct {
	AgentID     string
	UserID      string // Optional: links agent to a specific user
	Hostname    string
	OS          string
	Profile     string
	Version     string
	State       string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

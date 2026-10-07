package storage

import "time"

type AuditEvent struct {
	ID         string         `json:"id"`
	OrgID      string         `json:"org_id"`
	ActorType  string         `json:"actor_type"`
	ActorID    string         `json:"actor_id"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Meta       map[string]any `json:"meta"`
	CreatedAt  time.Time      `json:"created_at"`
}

type AuditStore interface {
	InsertEvent(e *AuditEvent) error
}

package storage

import (
	"encoding/json"
	"time"
)

type AgentIdentityRecord struct {
	Kind          string          `json:"kind"`
	Value         string          `json:"value"`
	FirstSeenAt   time.Time       `json:"first_seen_at"`
	LastSeenAt    time.Time       `json:"last_seen_at"`
	SeenCount     int64           `json:"seen_count"`
	LastEventID   string          `json:"last_event_id,omitempty"`
	LastEventType string          `json:"last_event_type,omitempty"`
	LastMeta      json.RawMessage `json:"last_meta,omitempty"`
}

// AgentIdentityStore persists the per-agent identity graph for an org.
//
// Security boundary: all methods require orgID.
type AgentIdentityStore interface {
	// UpsertSeen records that the given values for (org, agent, kind) were observed at seenAt.
	// Returns the subset of values that were newly inserted (first time seen).
	UpsertSeen(orgID, agentID, kind string, values []string, seenAt time.Time, sourceEventType string, sourceEventID string, meta any) (newValues []string, err error)

	// ListByAgent returns identity records for a given agent, ordered by most recently seen.
	// If kind is empty, returns all kinds.
	ListByAgent(orgID, agentID, kind string, limit int) ([]AgentIdentityRecord, error)
}

package model

import (
	"encoding/json"
	"time"
)

// Approval mirrors correlic-backend's org_approvals API response (subset).
type Approval struct {
	ID        string          `json:"id"`
	OrgID     string          `json:"org_id"`
	AgentID   string          `json:"agent_id"`
	Kind      string          `json:"kind"`
	Status    string          `json:"status"`
	Subject   json.RawMessage `json:"subject"`
	Reason    string          `json:"reason"`
	AlertID   string          `json:"alert_id,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	DecidedAt *time.Time      `json:"decided_at,omitempty"`
}

// ApprovalCheckResponse mirrors /approvals/check response.
type ApprovalCheckResponse struct {
	Allowed      bool     `json:"allowed"`
	Restricted   bool     `json:"restricted"`
	PendingCount int      `json:"pending_count,omitempty"`
	PendingIDs   []string `json:"pending_ids,omitempty"`
	ApprovalID   string   `json:"approval_id,omitempty"`
	Status       string   `json:"status,omitempty"`
}


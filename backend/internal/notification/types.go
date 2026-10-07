package notification

import "time"

// Endpoint represents a configured notification channel (webhook or Slack).
type Endpoint struct {
	ID          string         `json:"id"`
	OrgID       string         `json:"org_id"`
	Name        string         `json:"name"`
	ChannelType string         `json:"channel_type"` // "webhook" or "slack"
	Config      map[string]any `json:"config"`       // {url, secret, headers} for webhook; {webhook_url} for slack
	MinSeverity string         `json:"min_severity"` // "low", "medium", "high", "critical"
	Enabled     bool           `json:"enabled"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// Notification represents an in-app notification entry.
type Notification struct {
	ID            string         `json:"id"`
	OrgID         string         `json:"org_id"`
	Category      string         `json:"category"` // "finding", "incident", "system"
	Severity      string         `json:"severity"`
	Title         string         `json:"title"`
	Summary       string         `json:"summary"`
	ReferenceType string         `json:"reference_type,omitempty"` // "finding" or "incident"
	ReferenceID   string         `json:"reference_id,omitempty"`
	HostID        string         `json:"host_id,omitempty"`
	Context       map[string]any `json:"context,omitempty"`
	Read          bool           `json:"read"`
	Dismissed     bool           `json:"dismissed"`
	CreatedAt     time.Time      `json:"created_at"`
}

// Delivery represents a queued external notification delivery.
type Delivery struct {
	ID            string         `json:"id"`
	OrgID         string         `json:"org_id"`
	EndpointID    string         `json:"endpoint_id"`
	ReferenceType string         `json:"reference_type"`
	ReferenceID   string         `json:"reference_id"`
	Payload       map[string]any `json:"payload"`
	Status        string         `json:"status"` // "pending", "delivered", "failed", "dead"
	Attempts      int            `json:"attempts"`
	MaxAttempts   int            `json:"max_attempts"`
	LastError     string         `json:"last_error"`
	NextAttemptAt time.Time      `json:"next_attempt_at"`
	DeliveredAt   *time.Time     `json:"delivered_at,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// SeverityRank maps severity strings to numeric ranks for comparison.
var SeverityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

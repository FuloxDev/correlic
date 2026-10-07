package detection

import (
	"context"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

// Detection is the interface every detection rule must implement.
// Rules are grouped into packs (ai, dev, system) and evaluated per-event.
type Detection interface {
	// Meta returns metadata about this detection (name, severity, pack, etc.).
	Meta() DetectionMeta
	// Scope returns which event types trigger this detection and its look-back window.
	Scope() DetectionScope
	// Evaluate runs the detection logic against a single event with graph context.
	Evaluate(ctx *EvalContext) []Finding
}

// DetectionMeta describes a detection rule.
type DetectionMeta struct {
	ID              string   `json:"id"`               // e.g. "ai.credential_access"
	Pack            string   `json:"pack"`             // "ai" | "dev" | "system"
	Name            string   `json:"name"`             // human-readable name
	Severity        string   `json:"severity"`         // "critical" | "high" | "medium" | "low"
	Description     string   `json:"description"`      // what this detection catches
	Tags            []string `json:"tags"`             // e.g. ["ai", "credentials", "exfiltration"]
	MITRETechniques []string `json:"mitre_techniques"` // e.g. ["T1552", "T1552.004"]
}

// DetectionScope declares when a detection should be evaluated.
type DetectionScope struct {
	EventTypes []string `json:"event_types"` // triggers on these event types
	WindowSecs int      `json:"window_secs"` // look-back window for context queries
}

// SafeDomainChecker is the interface for checking if a domain is allowlisted.
type SafeDomainChecker interface {
	IsSafe(domain string) bool
}

// ExceptionChecker is the interface for checking if a finding matches a per-rule exception.
type ExceptionChecker interface {
	Matches(orgID string, f Finding) bool
}

// RuleSettingsReader provides per-org rule threshold settings to detection rules.
// Rules call GetFloat/GetInt with a default fallback — nil means always use defaults.
type RuleSettingsReader interface {
	GetFloat(orgID, ruleID, key string, def float64) float64
	GetInt(orgID, ruleID, key string, def int) int
}

// BaselineChecker lets detection rules query whether a specific file path
// falls within an already-baselined directory. Nil-safe — pass nil to disable.
type BaselineChecker interface {
	IsFileBaselined(orgID, hostID, aiType, filePath string) bool
}

// EvalContext provides the event being evaluated and graph access for context queries.
type EvalContext struct {
	Ctx               context.Context
	Event             *event.Event
	HostID            string
	OrgID             string            // needed for per-org rule settings lookup
	GraphQuery        GraphQuerier
	SafeDomainChecker SafeDomainChecker
	RuleSettings      RuleSettingsReader // nil = use rule defaults
	DNSCache          *DNSCache          // nil-safe; correlates net_connect IPs with recent DNS queries
	Baselines         BaselineChecker    // nil = no baseline filtering
}

// Finding represents a detection match — a raw signal that something suspicious happened.
// Findings have a lifecycle: pending → allowed/dismissed/investigating.
type Finding struct {
	ID            string         `json:"id"`
	DetectionID   string         `json:"detection_id"`
	HostID        string         `json:"host_id"`
	Severity      string         `json:"severity"`
	Confidence    float64        `json:"confidence"`
	Title         string         `json:"title"`
	Summary       string         `json:"summary"`
	AnchorEventID string         `json:"anchor_event_id"`
	RelatedEvents []string       `json:"related_events,omitempty"`
	Context       map[string]any `json:"context,omitempty"`

	// Lifecycle
	Status     string     `json:"status"` // "pending" | "allowed" | "dismissed" | "investigating"
	Resolution string     `json:"resolution,omitempty"`
	ResolvedBy string     `json:"resolved_by,omitempty"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`

	// Behavioral suppression
	Suppressed    bool   `json:"suppressed"`
	BaselineMatch string `json:"baseline_match,omitempty"`

	Timestamp time.Time `json:"timestamp"`
}

// GraphQuerier is the interface detection rules use to query Neo4j for context.
// This keeps detection rules decoupled from the storage layer.
type GraphQuerier interface {
	// GetRecentEvents returns events for a PID within a time window.
	GetRecentEvents(ctx context.Context, hostID string, pid int, since time.Time, eventTypes []string) ([]event.Event, error)
	// GetRecentEventsMultiPID returns events for a set of PIDs within a time window.
	GetRecentEventsMultiPID(ctx context.Context, hostID string, pids []int, since time.Time, eventTypes []string) ([]event.Event, error)
	// GetRecentEventsBySession returns events for a session within a time window.
	GetRecentEventsBySession(ctx context.Context, hostID string, sessionID string, since time.Time, eventTypes []string) ([]event.Event, error)
	// GetProcessAncestors returns the ancestor chain for a process.
	GetProcessAncestors(ctx context.Context, hostID string, pid int, maxDepth int) ([]event.Event, error)
	// IsAIProcess checks if a PID belongs to an AI agent process tree.
	// Returns (isAI, aiType, error).
	IsAIProcess(ctx context.Context, hostID string, pid int) (bool, string, error)
}

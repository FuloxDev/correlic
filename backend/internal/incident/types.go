package incident

import (
	"strings"
	"time"
)

// SeverityRank maps severity strings to numeric ranks for comparison.
var SeverityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}

// SeverityFromRank returns the severity string for a numeric rank.
func SeverityFromRank(rank int) string {
	for name, r := range SeverityRank {
		if r == rank {
			return name
		}
	}
	return "low"
}

// Incident is a correlated security event — a collection of related findings
// with temporal bounds, aggregate severity, and pre-computed context summary.
type Incident struct {
	ID              string         `json:"id"`
	OrgID           string         `json:"org_id"`
	HostID          string         `json:"host_id"`
	Category        string         `json:"category"`
	Severity        string         `json:"severity"`
	Confidence      float64        `json:"confidence"`
	Title           string         `json:"title"`
	Summary         string         `json:"summary,omitempty"`
	MITRETechniques []string       `json:"mitre_techniques,omitempty"`
	FindingIDs      []string       `json:"finding_ids"`
	ChainFindingID  string         `json:"chain_finding_id,omitempty"`
	StartedAt       time.Time      `json:"started_at"`
	EndedAt         time.Time      `json:"ended_at"`
	ContextSummary  map[string]any `json:"context_summary,omitempty"`
	Status          string         `json:"status"`
	Resolution      *string        `json:"resolution,omitempty"`
	ResolvedBy      *string        `json:"resolved_by,omitempty"`
	ResolvedAt      *time.Time     `json:"resolved_at,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// IncidentDetail is the full incident view assembled on-demand.
// Includes resolved findings from PostgreSQL and event-level context from Neo4j.
// This is the AI-consumable package for Phase 5.
type IncidentDetail struct {
	Incident
	Findings       []FindingSummary `json:"findings"`
	Timeline       []TimelineEntry  `json:"timeline"`
	ProcessTree    *ProcessNode     `json:"process_tree,omitempty"`
	EventGraph     *EventGraph      `json:"event_graph,omitempty"`
	ProcessDetails []ProcessDetail  `json:"process_details,omitempty"`
}

// ProcessDetail provides per-process context for the AI dossier.
// Aggregates what each process did: files, network, DNS.
type ProcessDetail struct {
	PID        int64     `json:"pid"`
	PPID       int64     `json:"ppid"`
	Exe        string    `json:"exe"`
	Cmdline    string    `json:"cmdline"`
	User       string    `json:"user"`
	StartedAt  time.Time `json:"started_at"`
	Files      []string  `json:"files,omitempty"`
	NetConns   []string  `json:"net_conns,omitempty"`
	DNSQueries []string  `json:"dns_queries,omitempty"`
}

// FindingSummary is a lightweight finding view embedded in incidents.
type FindingSummary struct {
	ID          string         `json:"id"`
	DetectionID string         `json:"detection_id"`
	Severity    string         `json:"severity"`
	Confidence  float64        `json:"confidence"`
	Title       string         `json:"title"`
	Summary     string         `json:"summary"`
	Context     map[string]any `json:"context,omitempty"`
	Timestamp   time.Time      `json:"timestamp"`
	Status      string         `json:"status"`
}

// TimelineEntry is a single point on the incident timeline.
type TimelineEntry struct {
	Timestamp  time.Time      `json:"timestamp"`
	Type       string         `json:"type"` // "finding", "event", "chain"
	EventType  string         `json:"event_type,omitempty"`
	Title      string         `json:"title"`
	Detail     string         `json:"detail,omitempty"`
	Severity   string         `json:"severity,omitempty"`
	EventID    string         `json:"event_id,omitempty"`
	FindingID  string         `json:"finding_id,omitempty"`
	PID        int            `json:"pid,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// ProcessNode is a process tree node for the incident view.
type ProcessNode struct {
	PID        int            `json:"pid"`
	PPID       int            `json:"ppid"`
	Comm       string         `json:"comm"`
	ExePath    string         `json:"exe_path,omitempty"`
	User       string         `json:"user,omitempty"`
	AIType     string         `json:"ai_type,omitempty"`
	StartedAt  *time.Time     `json:"started_at,omitempty"`
	FindingIDs []string       `json:"finding_ids,omitempty"`
	Children   []*ProcessNode `json:"children,omitempty"`
}

// EventGraph is a simplified graph for visualization.
type EventGraph struct {
	Nodes []EventNode `json:"nodes"`
	Edges []EventEdge `json:"edges"`
}

// EventNode is a single node in the event graph.
type EventNode struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	PID       int       `json:"pid,omitempty"`
	Label     string    `json:"label"`
	IsFinding bool      `json:"is_finding,omitempty"`
}

// EventEdge is a directed edge between two event nodes.
type EventEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

// IncidentCounts holds aggregated incident counts for the dashboard.
type IncidentCounts struct {
	Total         int `json:"total"`
	Open          int `json:"open"`
	Investigating int `json:"investigating"`
	Resolved      int `json:"resolved"`
	Dismissed     int `json:"dismissed"`
	AutoResolved  int `json:"auto_resolved"`
}

// ListOptions holds query parameters for listing incidents.
type ListOptions struct {
	Status   string
	Severity string
	HostID   string
	Category string
	Since    time.Time
	Limit    int
	Offset   int
}

// AttackCategoryMap maps detection IDs to their grouping category.
var AttackCategoryMap = map[string]string{
	"ai.credential_access":    "credential_theft",
	"ai.unauthorized_exec":    "execution",
	"ai.command_activity":     "execution",
	"ai.privilege_escalation": "privilege_escalation",
	"ai.container_escape":     "privilege_escalation",
	"ai.persistence":          "persistence",
	"ai.data_exfiltration":    "exfiltration",
	"ai.unexpected_network":   "exfiltration",
	"ai.suspicious_dns":       "reconnaissance",
	"ai.discovery":            "reconnaissance",
	"ai.code_tampering":       "tampering",
	"ai.file_activity":        "tampering",
	"ai.excessive_writes":     "tampering",
}

// CategoryLabels provides human-readable labels for each category.
var CategoryLabels = map[string]string{
	"credential_theft":     "Credential Theft",
	"execution":            "Suspicious Execution",
	"privilege_escalation": "Privilege Escalation",
	"persistence":          "Persistence",
	"exfiltration":         "Data Exfiltration",
	"reconnaissance":       "Reconnaissance",
	"tampering":            "Code Tampering",
	"other":                "Other",
}

// InformationalDetections are low-severity detections that should attach to
// existing incidents but never create seed incidents on their own.
var InformationalDetections = map[string]bool{
	"ai.command_activity": true,
	"ai.file_activity":    true,
}

// chainCategoryMap maps chain pattern IDs to their attack category.
var chainCategoryMap = map[string]string{
	"credential_theft":         "credential_theft",
	"reverse_shell_setup":      "execution",
	"lateral_movement":         "execution",
	"full_compromise":          "credential_theft",
	"persistence_backdoor":     "persistence",
	"supply_chain_attack":      "tampering",
	"data_staging":             "exfiltration",
	"credential_persistence":   "credential_theft",
	"privesc_credential_exfil": "privilege_escalation",
	"recon_to_escalation":      "reconnaissance",
	"container_breakout":       "privilege_escalation",
}

// categoryTitle returns a campaign-level incident title derived from the attack
// category and (optional) AI agent type. Used so incidents are titled after the
// attack pattern rather than the specific command that seeded them.
func categoryTitle(category, aiType string) string {
	actor := "AI agent"
	if aiType != "" {
		actor = aiType
	}
	switch category {
	case "credential_theft":
		return actor + " credential access campaign"
	case "privilege_escalation":
		return actor + " privilege escalation campaign"
	case "execution":
		return actor + " suspicious execution campaign"
	case "persistence":
		return actor + " persistence campaign"
	case "exfiltration":
		return actor + " data exfiltration campaign"
	case "network":
		return actor + " unexpected network activity"
	case "dns":
		return actor + " suspicious DNS activity"
	case "tampering":
		return actor + " code/supply-chain tampering"
	case "reconnaissance":
		return actor + " reconnaissance activity"
	default:
		return actor + " suspicious activity"
	}
}

// CategoryForDetection returns the attack category for a detection ID.
func CategoryForDetection(detectionID string) string {
	if cat, ok := AttackCategoryMap[detectionID]; ok {
		return cat
	}
	if strings.HasPrefix(detectionID, "chain.") {
		patternID := strings.TrimPrefix(detectionID, "chain.")
		if cat, ok := chainCategoryMap[patternID]; ok {
			return cat
		}
	}
	return "other"
}

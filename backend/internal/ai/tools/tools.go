package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/correlic/correlic-backend/internal/ai/intelligence"
	"github.com/correlic/correlic-backend/internal/query"
	"github.com/correlic/correlic-backend/internal/storage/neo4j"
)

// Params is the explicit input for all tools. Host scope (HostID) is always provided by the caller.
// AI is not allowed to change or broaden host scope.
// For diff_* tools, BaseSince/BaseUntil and CompareSince/CompareUntil define the two windows.
type Params struct {
	OrgID        string    `json:"org_id"`
	HostID       string    `json:"host_id"`
	Since        time.Time `json:"since"`
	Until        time.Time `json:"until"`
	Pattern      string    `json:"pattern,omitempty"` // used by list_processes_by_executable and find_related_events
	PID          int64     `json:"pid,omitempty"`     // used by graph tools (process tree, attack chain, session activity)
	BaseSince    time.Time `json:"base_since,omitempty"`
	BaseUntil    time.Time `json:"base_until,omitempty"`
	CompareSince time.Time `json:"compare_since,omitempty"`
	CompareUntil time.Time `json:"compare_until,omitempty"`
}

// DiffData is the result shape for diff_* tools (Added/Removed slices). Used by summarizer and AskResponse.
type DiffData struct {
	Added      interface{} `json:"added"`
	Removed    interface{} `json:"removed"`
	LenAdded   int         `json:"-"`
	LenRemoved int         `json:"-"`
}

// Result wraps tool output with a truncation flag. Handlers return *Result when the query hit MaxResults.
type Result struct {
	Data      any
	Truncated bool
}

// Tool defines a callable with explicit name, description, and handler. No new query logic; wraps query service.
// The handler accepts an optional GraphStore (nil when Neo4j is unavailable).
type Tool struct {
	Name        string
	Description string
	Handler     func(ctx context.Context, q *query.Service, g *neo4j.GraphStore, p Params) (any, error)
}

// NewRegistry creates the tool registry. AI may only call these; no direct DB or correlation access.
// The GraphStore may be nil — graph-based tools will return an error in that case.
// The intelligence store may be nil — intelligence tools will return errors in that case.
func NewRegistry(q *query.Service, g *neo4j.GraphStore, intStore *intelligence.Store) map[string]*Tool {
	return map[string]*Tool{
		"list_containers": {
			Name:        "list_containers",
			Description: "List container_start events in a time range for a host",
			Handler:     listContainers,
		},
		"list_open_ports": {
			Name:        "list_open_ports",
			Description: "List net_listen (open port) events in a time range for a host",
			Handler:     listOpenPorts,
		},
		"list_external_connections": {
			Name:        "list_external_connections",
			Description: "List net_connect (outbound) events in a time range for a host",
			Handler:     listExternalConnections,
		},
		"list_processes_by_executable": {
			Name:        "list_processes_by_executable",
			Description: "List process_exec events whose executable path contains a pattern",
			Handler:     listProcessesByExecutable,
		},
		"diff_processes": {
			Name:        "diff_processes",
			Description: "What processes (by executable) changed between two time windows",
			Handler:     diffProcesses,
		},
		"diff_connections": {
			Name:        "diff_connections",
			Description: "What external connections changed between two time windows",
			Handler:     diffConnections,
		},
		"diff_ports": {
			Name:        "diff_ports",
			Description: "What open ports changed between two time windows",
			Handler:     diffPorts,
		},
		// Graph-based tools (require Neo4j)
		"get_process_tree": {
			Name:        "get_process_tree",
			Description: "Get parent/child process chain for a PID (5 levels up, 10 down)",
			Handler: func(ctx context.Context, q *query.Service, g *neo4j.GraphStore, p Params) (any, error) {
				if g == nil {
					return nil, fmt.Errorf("graph store unavailable")
				}
				return g.GetProcessTree(ctx, p.PID, p.HostID)
			},
		},
		"get_attack_chain": {
			Name:        "get_attack_chain",
			Description: "BFS from an event or PID to find up to 100 connected events",
			Handler: func(ctx context.Context, q *query.Service, g *neo4j.GraphStore, p Params) (any, error) {
				if g == nil {
					return nil, fmt.Errorf("graph store unavailable")
				}
				return g.QueryAttackChain(ctx, neo4j.AttackChainQuery{
					StartPID:   p.PID,
					HostID:     p.HostID,
					MaxDepth:   10,
					TimeWindow: p.Until.Sub(p.Since),
				})
			},
		},
		"find_related_events": {
			Name:        "find_related_events",
			Description: "Find events that touched a specific file path or IP address",
			Handler: func(ctx context.Context, q *query.Service, g *neo4j.GraphStore, p Params) (any, error) {
				if g == nil {
					return nil, fmt.Errorf("graph store unavailable")
				}
				return g.FindRelatedEvents(ctx, p.Pattern, "", p.HostID, 30)
			},
		},
		"get_session_activity": {
			Name:        "get_session_activity",
			Description: "Get all events in a login session",
			Handler: func(ctx context.Context, q *query.Service, g *neo4j.GraphStore, p Params) (any, error) {
				if g == nil {
					return nil, fmt.Errorf("graph store unavailable")
				}
				return g.GetSessionActivity(ctx, p.PID, p.HostID) // PID reused for session_id
			},
		},
		"get_lateral_movement": {
			Name:        "get_lateral_movement",
			Description: "Find processes that made network connections then spawned children",
			Handler: func(ctx context.Context, q *query.Service, g *neo4j.GraphStore, p Params) (any, error) {
				if g == nil {
					return nil, fmt.Errorf("graph store unavailable")
				}
				return g.GetLateralMovement(ctx, p.HostID, p.Since)
			},
		},
		// Query-based tools
		"list_execs": {
			Name:        "list_execs",
			Description: "List all process_exec events in a time range",
			Handler: func(ctx context.Context, q *query.Service, g *neo4j.GraphStore, p Params) (any, error) {
				rows, truncated, err := q.ListExecs(ctx, p.HostID, p.Since, p.Until)
				if err != nil {
					return nil, err
				}
				return &Result{Data: rows, Truncated: truncated}, nil
			},
		},
		"list_inbound_connections": {
			Name:        "list_inbound_connections",
			Description: "List inbound network connections in a time range",
			Handler: func(ctx context.Context, q *query.Service, g *neo4j.GraphStore, p Params) (any, error) {
				rows, truncated, err := q.ListInboundConnections(ctx, p.HostID, p.Since, p.Until)
				if err != nil {
					return nil, err
				}
				return &Result{Data: rows, Truncated: truncated}, nil
			},
		},
		// Intelligence tools (require intelligence.Store)
		"get_system_profile": {
			Name:        "get_system_profile",
			Description: "Get the system profile for the current host — shows installed AI agents, normal network destinations, baseline summary, and working directories. Use this to understand what is 'normal' for this system.",
			Handler: func(ctx context.Context, _ *query.Service, _ *neo4j.GraphStore, p Params) (any, error) {
				if intStore == nil {
					return nil, fmt.Errorf("intelligence store unavailable")
				}
				profile, err := intStore.GetProfile(ctx, p.OrgID, p.HostID)
				if err != nil || profile == nil {
					return json.RawMessage(`{"error": "no system profile available yet"}`), nil
				}
				return profile, nil
			},
		},
		"get_recent_activity": {
			Name:        "get_recent_activity",
			Description: "Get a summary of recent activity on the host. Returns event counts, unique binaries, network destinations, findings, and temporal patterns. Use 'granularity' to choose detail level: '1m' for the last minute, '1h' for the last hour, '24h' for the last day.",
			Handler: func(ctx context.Context, _ *query.Service, _ *neo4j.GraphStore, p Params) (any, error) {
				if intStore == nil {
					return nil, fmt.Errorf("intelligence store unavailable")
				}
				granularity := p.Pattern // reuse Pattern field for granularity
				if granularity == "" {
					granularity = "1h"
				}
				count := 1
				if p.PID > 0 && p.PID <= 10 {
					count = int(p.PID) // reuse PID field for count
				}
				since := time.Now().Add(-24 * time.Hour)
				windows, err := intStore.GetContextWindows(ctx, p.OrgID, p.HostID, granularity, since, count)
				if err != nil || len(windows) == 0 {
					return json.RawMessage(`{"error": "no recent activity data available"}`), nil
				}
				return windows, nil
			},
		},
		"get_learned_patterns": {
			Name:        "get_learned_patterns",
			Description: "Get patterns the AI has learned from user actions (dismiss, allow, investigate, block). Shows verdict (always_benign, likely_benign, suspicious, always_malicious), confidence score, and evidence counts. Use this to check if a finding type has been seen before and what the user typically does with it.",
			Handler: func(ctx context.Context, _ *query.Service, _ *neo4j.GraphStore, p Params) (any, error) {
				if intStore == nil {
					return nil, fmt.Errorf("intelligence store unavailable")
				}
				patterns, err := intStore.ListPatterns(ctx, p.OrgID)
				if err != nil || len(patterns) == 0 {
					return json.RawMessage(`{"patterns": [], "message": "no patterns learned yet — the system learns from user actions on findings"}`), nil
				}
				return map[string]any{"patterns": patterns, "count": len(patterns)}, nil
			},
		},
		"get_false_positive_rate": {
			Name:        "get_false_positive_rate",
			Description: "Get the false positive rate for each detection rule based on user actions. A high rate (>0.8) means most findings from that rule are noise. A low rate (<0.2) means the rule is high-value. Use this to calibrate how much to trust a specific detection rule.",
			Handler: func(ctx context.Context, _ *query.Service, _ *neo4j.GraphStore, p Params) (any, error) {
				if intStore == nil {
					return nil, fmt.Errorf("intelligence store unavailable")
				}
				since := time.Now().Add(-30 * 24 * time.Hour)
				if !p.Since.IsZero() {
					since = p.Since
				}
				rates, err := intStore.GetFalsePositiveRates(ctx, p.OrgID, since)
				if err != nil || len(rates) == 0 {
					return json.RawMessage(`{"rates": {}, "message": "not enough data yet (need 5+ findings per rule)"}`), nil
				}
				return rates, nil
			},
		},
	}
}

// IntelligenceToolNames returns the names of tools that use intelligence-specific parameters.
// These tools use Pattern for granularity, PID for count, and Since for time range
// rather than the standard query parameters.
var IntelligenceToolNames = map[string]bool{
	"get_system_profile":    true,
	"get_recent_activity":   true,
	"get_learned_patterns":  true,
	"get_false_positive_rate": true,
}

// ParseIntelligenceArgs parses raw JSON arguments for intelligence tools into Params.
// Intelligence tools reuse Params fields: Pattern for granularity, PID for count.
func ParseIntelligenceArgs(toolName string, rawJSON []byte, orgID, hostID string) Params {
	p := Params{OrgID: orgID, HostID: hostID}

	var args map[string]any
	if err := json.Unmarshal(rawJSON, &args); err != nil {
		return p
	}

	switch toolName {
	case "get_recent_activity":
		if g, ok := args["granularity"].(string); ok {
			p.Pattern = g // reuse Pattern for granularity
		}
		if c, ok := args["count"]; ok {
			switch v := c.(type) {
			case float64:
				p.PID = int64(v) // reuse PID for count
			case string:
				if n, err := strconv.Atoi(v); err == nil {
					p.PID = int64(n)
				}
			}
		}
	case "get_false_positive_rate":
		if s, ok := args["since"].(string); ok {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				p.Since = t
			}
		}
	}

	return p
}

func diffProcesses(ctx context.Context, q *query.Service, _ *neo4j.GraphStore, p Params) (any, error) {
	res, err := q.DiffProcessesByExecutable(ctx, p.HostID, p.BaseSince, p.BaseUntil, p.CompareSince, p.CompareUntil)
	if err != nil {
		return nil, err
	}
	return &Result{Data: DiffData{Added: res.Added, Removed: res.Removed, LenAdded: len(res.Added), LenRemoved: len(res.Removed)}}, nil
}

func diffConnections(ctx context.Context, q *query.Service, _ *neo4j.GraphStore, p Params) (any, error) {
	res, err := q.DiffExternalConnections(ctx, p.HostID, p.BaseSince, p.BaseUntil, p.CompareSince, p.CompareUntil)
	if err != nil {
		return nil, err
	}
	return &Result{Data: DiffData{Added: res.Added, Removed: res.Removed, LenAdded: len(res.Added), LenRemoved: len(res.Removed)}}, nil
}

func diffPorts(ctx context.Context, q *query.Service, _ *neo4j.GraphStore, p Params) (any, error) {
	res, err := q.DiffOpenPorts(ctx, p.HostID, p.BaseSince, p.BaseUntil, p.CompareSince, p.CompareUntil)
	if err != nil {
		return nil, err
	}
	return &Result{Data: DiffData{Added: res.Added, Removed: res.Removed, LenAdded: len(res.Added), LenRemoved: len(res.Removed)}}, nil
}

func listContainers(ctx context.Context, q *query.Service, _ *neo4j.GraphStore, p Params) (any, error) {
	rows, truncated, err := q.ListContainerStarts(ctx, p.HostID, p.Since, p.Until)
	if err != nil {
		return nil, err
	}
	return &Result{Data: rows, Truncated: truncated}, nil
}

func listOpenPorts(ctx context.Context, q *query.Service, _ *neo4j.GraphStore, p Params) (any, error) {
	rows, truncated, err := q.ListOpenPorts(ctx, p.HostID, p.Since, p.Until)
	if err != nil {
		return nil, err
	}
	return &Result{Data: rows, Truncated: truncated}, nil
}

func listExternalConnections(ctx context.Context, q *query.Service, _ *neo4j.GraphStore, p Params) (any, error) {
	rows, truncated, err := q.ListExternalConnections(ctx, p.HostID, p.Since, p.Until)
	if err != nil {
		return nil, err
	}
	return &Result{Data: rows, Truncated: truncated}, nil
}

func listProcessesByExecutable(ctx context.Context, q *query.Service, _ *neo4j.GraphStore, p Params) (any, error) {
	rows, truncated, err := q.ListProcessesByExecutable(ctx, p.HostID, p.Since, p.Until, p.Pattern)
	if err != nil {
		return nil, err
	}
	return &Result{Data: rows, Truncated: truncated}, nil
}

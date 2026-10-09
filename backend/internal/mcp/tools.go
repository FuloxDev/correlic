package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ToolSet is the Correlic tool catalogue backed by the REST API.
//
// Read tools are always available. correlic.finding.resolve is only listed
// (and only callable) when AllowWrites is set: the MCP server is started
// with --allow-writes by an operator who wants the model to triage findings.
type ToolSet struct {
	client      *CorrelicClient
	allowWrites bool
	now         func() time.Time
	timeout     time.Duration
}

// NewToolSet builds the catalogue over client.
func NewToolSet(client *CorrelicClient, allowWrites bool) *ToolSet {
	return &ToolSet{client: client, allowWrites: allowWrites, now: time.Now, timeout: 20 * time.Second}
}

// AllowWrites reports whether the write tools are enabled.
func (t *ToolSet) AllowWrites() bool { return t.allowWrites }

// Tool names.
const (
	ToolAIProof         = "correlic.ai.proof"
	ToolNetworkSummary  = "correlic.network.summary"
	ToolPortsSummary    = "correlic.ports.summary"
	ToolTelemetrySearch = "correlic.telemetry.search"
	ToolFindingsList    = "correlic.findings.list"
	ToolIncidentsList   = "correlic.incidents.list"
	ToolIncidentGet     = "correlic.incident.get"
	ToolAgentsActivity  = "correlic.agents.activity"
	ToolAgentsList      = "correlic.agents.list"
	ToolFindingResolve  = "correlic.finding.resolve"
)

var (
	severityValues = []string{"low", "medium", "high", "critical"}
	findingStatus  = []string{"pending", "allowed", "dismissed", "investigating", "blocked"}
	incidentStatus = []string{"open", "investigating", "resolved", "dismissed", "auto_resolved"}
	resolveStatus  = []string{"allowed", "dismissed", "investigating"}
)

const (
	defaultListLimit = 50
	maxListLimit     = 500
	// severityFetchLimit is how many rows are fetched when a severity filter
	// is applied client-side (the findings API has no severity parameter).
	severityFetchLimit = 2000
	maxTimelineEntries = 200
)

func prop(typ, desc string) map[string]any {
	return map[string]any{"type": typ, "description": desc}
}

func enumProp(desc string, values []string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": values}
}

func intProp(desc string, min, max int) map[string]any {
	return map[string]any{"type": "integer", "description": desc, "minimum": min, "maximum": max}
}

const sinceDesc = "Start of the window: an RFC 3339 timestamp (2026-10-09T10:00:00Z) or a duration back from now such as 30m, 6h, 7d."

// Tools returns the catalogue for tools/list.
func (t *ToolSet) Tools() []Tool {
	tools := []Tool{
		{
			Name:        ToolAIProof,
			Description: "Generate an AI Proof report: evidence-backed summary of what AI agents did on monitored hosts in a time window (processes, files, network, with event ids). Requires since and until.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"since":          prop("string", "RFC 3339 timestamp, start of the window"),
					"until":          prop("string", "RFC 3339 timestamp, end of the window"),
					"agent_id":       prop("string", "Restrict to one agent (host) id"),
					"include_non_ai": prop("boolean", "Include activity of non-AI processes too (default false)"),
				},
				"required": []string{"since", "until"},
			},
		},
		{
			Name:        ToolNetworkSummary,
			Description: "Network summary for a time window: DNS lookups and outbound connections aggregated by destination, with AI attribution.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"since":    prop("string", "RFC 3339 timestamp"),
					"until":    prop("string", "RFC 3339 timestamp"),
					"agent_id": prop("string", "Restrict to one agent (host) id"),
				},
			},
		},
		{
			Name:        ToolPortsSummary,
			Description: "Listening ports summary for a time window: open services and their exposure across hosts.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"since":    prop("string", "RFC 3339 timestamp"),
					"until":    prop("string", "RFC 3339 timestamp"),
					"agent_id": prop("string", "Restrict to one agent (host) id"),
				},
			},
		},
		{
			Name:        ToolTelemetrySearch,
			Description: "Search raw telemetry events (process_exec, file_open, net_connect, dns_query, ...) with filters. Returns the newest matching events; use limit/offset to page.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"event_type": prop("string", "Event type, e.g. process_exec, file_open, net_connect, dns_query"),
					"agent_id":   prop("string", "Restrict to one agent (host) id"),
					"since":      prop("string", "RFC 3339 timestamp"),
					"until":      prop("string", "RFC 3339 timestamp"),
					"pid":        intProp("Restrict to one process id", 1, 4194304),
					"limit":      intProp("Maximum events to return (default 100)", 1, 1000),
					"offset":     intProp("Events to skip, for paging", 0, 1000000),
					"ai_only":    prop("boolean", "Only events attributed to AI agent processes"),
				},
			},
		},
		{
			Name:        ToolFindingsList,
			Description: "List detection findings (one per matched rule, e.g. ai.credential_access). Filter by severity, status, host and time; newest first. Each finding has id, detection_id, severity, confidence, status, title, summary, host_id, incident_id and a context object (ai_type, file_path, command, pid, mitre_techniques). Default window: last 24 hours.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"severity": enumProp("Only findings of this severity", severityValues),
					"status":   enumProp("Only findings in this status (pending = not yet triaged)", findingStatus),
					"host":     prop("string", "Only findings from this host id (host_id)"),
					"since":    prop("string", sinceDesc+" Default 24h."),
					"limit":    intProp("Maximum findings to return (default 50, max 500)", 1, maxListLimit),
				},
			},
		},
		{
			Name:        ToolIncidentsList,
			Description: "List incidents: clusters of related findings on one host with a severity, category, MITRE techniques and status. Filter by severity, status, host, category and time; newest first. Default window: last 7 days. Use correlic.incident.get for the timeline of one incident.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"severity": enumProp("Only incidents of this severity", severityValues),
					"status":   enumProp("Only incidents in this status", incidentStatus),
					"host":     prop("string", "Only incidents on this host id"),
					"category": prop("string", "Only incidents of this attack category (e.g. credential_access, exfiltration, persistence)"),
					"since":    prop("string", sinceDesc+" Default 7d."),
					"limit":    intProp("Maximum incidents to return (default 50, max 500)", 1, maxListLimit),
				},
			},
		},
		{
			Name:        ToolIncidentGet,
			Description: "Full detail of one incident: the incident record, its findings, a chronological timeline of the events behind them, per-process details and (with full=true) the process tree and event graph.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":           prop("string", "Incident id (from correlic.incidents.list or a finding's incident_id)"),
					"max_timeline": intProp("Maximum timeline entries to include (default 100, max 200)", 1, maxTimelineEntries),
					"full":         prop("boolean", "Include the process tree and event graph (large). Default false."),
				},
				"required": []string{"id"},
			},
		},
		{
			Name:        ToolAgentsActivity,
			Description: "What did my AI agents do recently: a human-readable, significance-scored activity feed per AI session (commands run, files touched, connections made) for the last N minutes. Significance 1 = noise, 5 = high-risk action.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"minutes":          intProp("Window length in minutes (default 30, max 10080 = 7 days)", 1, 10080),
					"min_significance": intProp("Hide activity below this significance (1-5, default 2)", 1, 5),
				},
			},
		},
		{
			Name:        ToolAgentsList,
			Description: "List the monitored hosts (agents) with hostname, OS, profile, version, state and last-seen time. Use agent_id/host ids from here in the other tools.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"state": prop("string", "Only agents in this state (e.g. active, stale)"),
				},
			},
		},
	}
	if t.allowWrites {
		tools = append(tools, Tool{
			Name:        ToolFindingResolve,
			Description: "Resolve a finding: mark it allowed (expected behaviour, optionally for a limited time), dismissed (not relevant) or investigating. Resolving every finding of an incident resolves the incident. Only available when the server runs with --allow-writes.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":         prop("string", "Finding id"),
					"status":     enumProp("New status", resolveStatus),
					"resolution": prop("string", "Free-text reason recorded with the resolution"),
					"expires_in": prop("string", "For status=allowed: how long the allowance lasts (7d, 30d, 90d). Omit for permanent."),
				},
				"required": []string{"id", "status"},
			},
		})
	}
	return tools
}

// Call executes a tool. Validation and API failures are returned as errors,
// which the server reports as MCP tool errors (isError: true).
func (t *ToolSet) Call(name string, args map[string]any) (ToolResult, error) {
	if args == nil {
		args = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()

	switch name {
	case ToolAIProof:
		since, err := RequireString(args, "since")
		if err != nil {
			return ToolResult{}, err
		}
		until, err := RequireString(args, "until")
		if err != nil {
			return ToolResult{}, err
		}
		q := url.Values{}
		q.Set("since", since)
		q.Set("until", until)
		setOptString(q, args, "agent_id", "agent_id")
		if OptionalBool(args, "include_non_ai") {
			q.Set("include_non_ai", "true")
		}
		return t.get(ctx, "/ai/proof", q)

	case ToolNetworkSummary, ToolPortsSummary:
		q := url.Values{}
		setOptString(q, args, "since", "since")
		setOptString(q, args, "until", "until")
		setOptString(q, args, "agent_id", "agent_id")
		path := "/network/summary"
		if name == ToolPortsSummary {
			path = "/ports/summary"
		}
		return t.get(ctx, path, q)

	case ToolTelemetrySearch:
		q := url.Values{}
		setOptString(q, args, "event_type", "event_type")
		setOptString(q, args, "agent_id", "agent_id")
		setOptString(q, args, "since", "since")
		setOptString(q, args, "until", "until")
		if v, ok := OptionalInt(args, "pid"); ok && v > 0 {
			q.Set("pid", strconv.Itoa(v))
		}
		if v, ok := OptionalInt(args, "limit"); ok && v > 0 {
			q.Set("limit", strconv.Itoa(v))
		}
		if v, ok := OptionalInt(args, "offset"); ok && v >= 0 {
			q.Set("offset", strconv.Itoa(v))
		}
		if OptionalBool(args, "ai_only") {
			q.Set("ai_only", "true")
		}
		return t.get(ctx, "/telemetry", q)

	case ToolFindingsList:
		return t.findingsList(ctx, args)

	case ToolIncidentsList:
		return t.incidentsList(ctx, args)

	case ToolIncidentGet:
		return t.incidentGet(ctx, args)

	case ToolAgentsActivity:
		q := url.Values{}
		if v, ok := OptionalInt(args, "minutes"); ok {
			if v < 1 || v > 10080 {
				return ToolResult{}, errors.New("invalid argument minutes: must be between 1 and 10080")
			}
			q.Set("interval", strconv.Itoa(v))
		}
		if v, ok := OptionalInt(args, "min_significance"); ok {
			if v < 1 || v > 5 {
				return ToolResult{}, errors.New("invalid argument min_significance: must be between 1 and 5")
			}
			q.Set("min_significance", strconv.Itoa(v))
		}
		return t.get(ctx, "/agents/activity", q)

	case ToolAgentsList:
		return t.agentsList(ctx, args)

	case ToolFindingResolve:
		return t.findingResolve(ctx, args)

	default:
		return ToolResult{}, fmt.Errorf("unknown tool: %s", name)
	}
}

func (t *ToolSet) findingsList(ctx context.Context, args map[string]any) (ToolResult, error) {
	severity, err := optionalEnum(args, "severity", severityValues)
	if err != nil {
		return ToolResult{}, err
	}
	status, err := optionalEnum(args, "status", findingStatus)
	if err != nil {
		return ToolResult{}, err
	}
	limit, err := optionalLimit(args, defaultListLimit, maxListLimit)
	if err != nil {
		return ToolResult{}, err
	}
	since, err := t.optionalSince(args)
	if err != nil {
		return ToolResult{}, err
	}

	q := url.Values{}
	if status != "" {
		q.Set("status", status)
	}
	setOptString(q, args, "host", "host_id")
	if since != "" {
		q.Set("since", since)
	}
	fetch := limit
	if severity != "" {
		// The findings API has no severity filter; fetch more and filter here.
		fetch = severityFetchLimit
	}
	q.Set("limit", strconv.Itoa(fetch))

	body, err := t.client.DoGET(ctx, "/api/v1/findings", q)
	if err != nil {
		return ToolResult{}, err
	}
	var resp struct {
		Findings     []map[string]any `json:"findings"`
		Total        int              `json:"total"`
		TotalPending int              `json:"total_pending"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ToolResult{}, fmt.Errorf("decode findings: %w", err)
	}
	out := make([]map[string]any, 0, len(resp.Findings))
	for _, f := range resp.Findings {
		if severity != "" && !strings.EqualFold(stringOf(f["severity"]), severity) {
			continue
		}
		out = append(out, f)
		if len(out) >= limit {
			break
		}
	}
	return jsonResult(map[string]any{
		"findings":      out,
		"count":         len(out),
		"total":         resp.Total,
		"total_pending": resp.TotalPending,
		"filters":       map[string]any{"severity": severity, "status": status, "host": OptionalString(args, "host"), "since": since, "limit": limit},
	})
}

func (t *ToolSet) incidentsList(ctx context.Context, args map[string]any) (ToolResult, error) {
	severity, err := optionalEnum(args, "severity", severityValues)
	if err != nil {
		return ToolResult{}, err
	}
	status, err := optionalEnum(args, "status", incidentStatus)
	if err != nil {
		return ToolResult{}, err
	}
	limit, err := optionalLimit(args, defaultListLimit, maxListLimit)
	if err != nil {
		return ToolResult{}, err
	}
	since, err := t.optionalSince(args)
	if err != nil {
		return ToolResult{}, err
	}
	q := url.Values{}
	if severity != "" {
		q.Set("severity", severity)
	}
	if status != "" {
		q.Set("status", status)
	}
	setOptString(q, args, "host", "host_id")
	setOptString(q, args, "category", "category")
	if since != "" {
		q.Set("since", since)
	}
	q.Set("limit", strconv.Itoa(limit))
	return t.get(ctx, "/api/v1/incidents", q)
}

func (t *ToolSet) incidentGet(ctx context.Context, args map[string]any) (ToolResult, error) {
	id, err := RequireString(args, "id")
	if err != nil {
		return ToolResult{}, err
	}
	maxTimeline := 100
	if v, ok := OptionalInt(args, "max_timeline"); ok {
		if v < 1 || v > maxTimelineEntries {
			return ToolResult{}, fmt.Errorf("invalid argument max_timeline: must be between 1 and %d", maxTimelineEntries)
		}
		maxTimeline = v
	}
	full := OptionalBool(args, "full")

	body, err := t.client.DoGET(ctx, "/api/v1/incidents/"+url.PathEscape(id), nil)
	if err != nil {
		return ToolResult{}, err
	}
	var resp struct {
		Incident map[string]any `json:"incident"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Incident == nil {
		return ToolResult{}, fmt.Errorf("decode incident: unexpected response")
	}
	inc := resp.Incident
	if timeline, ok := inc["timeline"].([]any); ok && len(timeline) > maxTimeline {
		inc["timeline"] = timeline[:maxTimeline]
		inc["timeline_truncated"] = true
		inc["timeline_total"] = len(timeline)
	}
	if !full {
		delete(inc, "process_tree")
		delete(inc, "event_graph")
	}
	return jsonResult(map[string]any{"incident": inc})
}

func (t *ToolSet) agentsList(ctx context.Context, args map[string]any) (ToolResult, error) {
	body, err := t.client.DoGET(ctx, "/agents", nil)
	if err != nil {
		return ToolResult{}, err
	}
	var agents []map[string]any
	if err := json.Unmarshal(body, &agents); err != nil {
		return ToolResult{}, fmt.Errorf("decode agents: %w", err)
	}
	if agents == nil {
		agents = []map[string]any{}
	}
	if state := OptionalString(args, "state"); state != "" {
		filtered := agents[:0]
		for _, a := range agents {
			if strings.EqualFold(stringOf(a["state"]), state) {
				filtered = append(filtered, a)
			}
		}
		agents = filtered
	}
	return jsonResult(map[string]any{"agents": agents, "count": len(agents)})
}

func (t *ToolSet) findingResolve(ctx context.Context, args map[string]any) (ToolResult, error) {
	if !t.allowWrites {
		return ToolResult{}, errors.New("writes are disabled: start correlic-mcp with --allow-writes to resolve findings")
	}
	id, err := RequireString(args, "id")
	if err != nil {
		return ToolResult{}, err
	}
	status, err := RequireString(args, "status")
	if err != nil {
		return ToolResult{}, err
	}
	if !contains(resolveStatus, status) {
		return ToolResult{}, fmt.Errorf("invalid argument status: must be one of %s", strings.Join(resolveStatus, ", "))
	}
	body := map[string]any{"status": status}
	if v := OptionalString(args, "resolution"); v != "" {
		body["resolution"] = v
	}
	if v := OptionalString(args, "expires_in"); v != "" {
		if status != "allowed" {
			return ToolResult{}, errors.New("invalid argument expires_in: only valid with status=allowed")
		}
		body["expires_in"] = v
	}
	out, err := t.client.Do(ctx, "PATCH", "/api/v1/findings/"+url.PathEscape(id), nil, body)
	if err != nil {
		return ToolResult{}, err
	}
	return jsonResult(map[string]any{"ok": true, "id": id, "status": status, "response": json.RawMessage(compactJSON(out))})
}

// --- helpers ---

func (t *ToolSet) get(ctx context.Context, path string, q url.Values) (ToolResult, error) {
	body, err := t.client.DoGET(ctx, path, q)
	if err != nil {
		return ToolResult{}, err
	}
	return textResult(body), nil
}

// optionalSince parses "since" as RFC 3339 or as a duration back from now
// (30m, 6h, 7d) and returns it as RFC 3339, or "" when absent.
func (t *ToolSet) optionalSince(args map[string]any) (string, error) {
	raw := strings.TrimSpace(OptionalString(args, "since"))
	if raw == "" {
		return "", nil
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts.UTC().Format(time.RFC3339), nil
	}
	if d, ok := parseDuration(raw); ok {
		return t.now().Add(-d).UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("invalid argument since: %q is neither an RFC 3339 timestamp nor a duration like 30m, 6h or 7d", raw)
}

// parseDuration accepts Go durations plus a trailing d (days) or w (weeks).
func parseDuration(s string) (time.Duration, bool) {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d, true
	}
	if len(s) > 1 {
		n, err := strconv.Atoi(s[:len(s)-1])
		if err == nil && n > 0 {
			switch s[len(s)-1] {
			case 'd':
				return time.Duration(n) * 24 * time.Hour, true
			case 'w':
				return time.Duration(n) * 7 * 24 * time.Hour, true
			}
		}
	}
	return 0, false
}

func optionalEnum(args map[string]any, key string, allowed []string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(OptionalString(args, key)))
	if v == "" {
		return "", nil
	}
	if !contains(allowed, v) {
		return "", fmt.Errorf("invalid argument %s: must be one of %s", key, strings.Join(allowed, ", "))
	}
	return v, nil
}

func optionalLimit(args map[string]any, def, max int) (int, error) {
	v, ok := OptionalInt(args, "limit")
	if !ok {
		return def, nil
	}
	if v < 1 || v > max {
		return 0, fmt.Errorf("invalid argument limit: must be between 1 and %d", max)
	}
	return v, nil
}

func setOptString(q url.Values, args map[string]any, argKey, queryKey string) {
	if v := strings.TrimSpace(OptionalString(args, argKey)); v != "" {
		q.Set(queryKey, v)
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

// textResult wraps an API body as one text content block. The stdio
// transport is newline-delimited, so the JSON is compacted (string values
// keep their escaped \n).
func textResult(body []byte) ToolResult {
	return ToolResult{Content: []ToolContent{{Type: "text", Text: compactJSON(body)}}}
}

func jsonResult(v any) (ToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return ToolResult{}, fmt.Errorf("encode result: %w", err)
	}
	return textResult(b), nil
}

func compactJSON(body []byte) string {
	s := strings.ReplaceAll(string(body), "\n", "")
	return strings.ReplaceAll(s, "\r", "")
}

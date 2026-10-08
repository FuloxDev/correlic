package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
)

// AgentBlockRule is one enabled block rule as served by GET /agent/block-rules
// on the telemetry plane. It mirrors the backend's storage.BlockRule fields
// the agent-side matcher needs (internal/enforcer converts it).
type AgentBlockRule struct {
	ID         int    `json:"id"`
	SignalType string `json:"signal_type"` // process_exec | net_connect | file_open
	Pattern    string `json:"pattern"`
	KillTree   bool   `json:"kill_tree"`
	Source     string `json:"source"`
}

// BlockRulesResult is the outcome of GetBlockRules. NotModified is true when
// the backend answered 304 for the If-None-Match version the caller passed;
// Rules is then nil and Version echoes the caller's version.
type BlockRulesResult struct {
	Version     string
	Rules       []AgentBlockRule
	NotModified bool
}

// GetBlockRules fetches the org's enabled block rules from
// telemetry_url/agent/block-rules. ifNoneMatch is the version hash of the
// rules the caller already holds (empty to always fetch).
func (t *HTTPTransport) GetBlockRules(ctx context.Context, ifNoneMatch string) (*BlockRulesResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.telemetryURL+"/agent/block-rules", nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(t.apiKey) != "" {
		req.Header.Set("Authorization", t.apiKey)
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return &BlockRulesResult{Version: ifNoneMatch, NotModified: true}, nil
	}
	if resp.StatusCode >= 300 {
		return nil, parseBackendError(resp, "block_rules")
	}
	var body struct {
		Version string           `json:"version"`
		Rules   []AgentBlockRule `json:"rules"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return nil, err
	}
	return &BlockRulesResult{Version: body.Version, Rules: body.Rules}, nil
}

// BlockEventReport is one block action reported to POST /agent/block-events.
// Field names match the backend's storage.BlockEvent; org_id is stamped by
// the backend from the caller's credentials.
type BlockEventReport struct {
	ID         string    `json:"id"`
	HostID     string    `json:"host_id"`
	AgentID    string    `json:"agent_id"`
	RuleID     int       `json:"rule_id"`
	SignalType string    `json:"signal_type"`
	PID        int       `json:"pid"`
	ExePath    string    `json:"exe_path"`
	Cmdline    string    `json:"cmdline"`
	Target     string    `json:"target"`
	AIType     string    `json:"ai_type"`
	Success    bool      `json:"success"`
	ErrorMsg   string    `json:"error_msg"`
	LatencyUS  int       `json:"latency_us"`
	BlockedAt  time.Time `json:"blocked_at"`
}

// ReportBlockEvents POSTs block actions to telemetry_url/agent/block-events.
func (t *HTTPTransport) ReportBlockEvents(ctx context.Context, events []BlockEventReport) error {
	if len(events) == 0 {
		return nil
	}
	payload := map[string]any{"events": events}
	return t.sendJSON(ctx, t.telemetryURL, "/agent/block-events", payload, "block_events")
}

// IngestResult is the 202 body of POST /ingest/events.
type IngestResult struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
	Sampled  int `json:"sampled"`
}

// SendCanonicalEventsWithResult POSTs one canonical event to
// telemetry_url/ingest/events and returns the backend's counts (used by
// `correlic-hook test`).
func (t *HTTPTransport) SendCanonicalEventsWithResult(ctx context.Context, evt event.Event) (*IngestResult, error) {
	var out IngestResult
	if err := t.postJSON(ctx, t.telemetryURL, "/ingest/events", evt, &out, "ingest/events"); err != nil {
		return nil, err
	}
	return &out, nil
}

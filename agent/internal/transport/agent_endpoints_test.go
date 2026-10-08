package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetBlockRules(t *testing.T) {
	var gotAuth, gotETag string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/block-rules" || r.Method != http.MethodGet {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotETag = r.Header.Get("If-None-Match")
		if gotETag == "sha256:v1" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"sha256:v1","rules":[{"id":7,"signal_type":"process_exec","pattern":"nc","kill_tree":true,"source":"user"}]}`))
	}))
	defer srv.Close()

	tr := NewHTTPTransportWithTelemetryURL("agent-key", srv.URL, srv.URL)
	res, err := tr.GetBlockRules(context.Background(), "")
	if err != nil {
		t.Fatalf("GetBlockRules: %v", err)
	}
	if gotAuth != "agent-key" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if res.NotModified || res.Version != "sha256:v1" || len(res.Rules) != 1 {
		t.Fatalf("result = %+v", res)
	}
	if r := res.Rules[0]; r.ID != 7 || r.SignalType != "process_exec" || r.Pattern != "nc" || !r.KillTree {
		t.Errorf("rule = %+v", r)
	}

	res, err = tr.GetBlockRules(context.Background(), "sha256:v1")
	if err != nil {
		t.Fatalf("GetBlockRules (etag): %v", err)
	}
	if !res.NotModified || res.Version != "sha256:v1" || res.Rules != nil {
		t.Errorf("not-modified result = %+v", res)
	}
}

func TestGetBlockRules_AuthErrorIsBackendError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad key","code":"unauthorized"}`))
	}))
	defer srv.Close()
	tr := NewHTTPTransportWithTelemetryURL("k", srv.URL, srv.URL)
	_, err := tr.GetBlockRules(context.Background(), "")
	if !IsAuthError(err) {
		t.Fatalf("expected auth error, got %v", err)
	}
}

func TestReportBlockEvents(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/agent/block-events" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":1}`))
	}))
	defer srv.Close()

	tr := NewHTTPTransportWithTelemetryURL("k", srv.URL, srv.URL)
	err := tr.ReportBlockEvents(context.Background(), []BlockEventReport{{
		ID: "be-1", HostID: "h", RuleID: 7, SignalType: "process_exec", PID: 42,
		ExePath: "nc", Cmdline: "nc -l 4444", Target: "nc", AIType: "claude-code",
		Success: true, BlockedAt: time.Unix(1700000000, 0).UTC(),
	}})
	if err != nil {
		t.Fatalf("ReportBlockEvents: %v", err)
	}
	events, _ := body["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("events = %v", body)
	}
	ev := events[0].(map[string]any)
	if ev["rule_id"] != float64(7) || ev["signal_type"] != "process_exec" || ev["host_id"] != "h" || ev["success"] != true {
		t.Errorf("event = %v", ev)
	}
	if tr.ReportBlockEvents(context.Background(), nil) != nil {
		t.Error("empty report should be a no-op")
	}
}

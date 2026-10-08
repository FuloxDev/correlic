package hook

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuildEvent_ShellPre(t *testing.T) {
	ts := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	ev := &ToolEvent{
		Tool: ToolClaudeCode, HookEvent: "PreToolUse", Phase: PhasePre, Blockable: true,
		SessionID: "sess-1", ToolName: "Bash", ToolUseID: "toolu_1",
		Command: "cat /etc/shadow", Cwd: "/w", Workspace: "/w", PermissionMode: "default",
	}
	actor := Actor{PID: 4242, User: "alice", ExePath: "/usr/bin/node"}
	evt := BuildEvent(ev, "host-1", actor, ts, Decision{})

	if evt.SchemaVersion != 1 || evt.Source != "hook" || evt.Type != "ai_tool_call" || evt.HostID != "host-1" || !evt.Timestamp.Equal(ts) {
		t.Errorf("envelope = %+v", evt)
	}
	if evt.ID == "" || len(evt.ID) != 64 {
		t.Errorf("id = %q", evt.ID)
	}
	if evt.Actor == nil || evt.Actor.PID != 4242 || evt.Actor.Comm != "claude" || evt.Actor.User != "alice" || evt.Actor.SessionID != "sess-1" || evt.Actor.ExePath != "/usr/bin/node" {
		t.Errorf("actor = %+v", evt.Actor)
	}
	if evt.Target != nil {
		t.Errorf("shell events carry no target, got %+v", evt.Target)
	}
	want := map[string]any{
		"is_ai": true, "ai_type": "claude-code", "ai_session_id": "sess-1", "hook_event": "PreToolUse",
		"phase": "pre", "decision": "allowed", "tool_name": "Bash", "tool_use_id": "toolu_1",
		"cwd": "/w", "workspace": "/w", "permission_mode": "default", "command": "cat /etc/shadow",
	}
	if !reflect.DeepEqual(evt.Context, want) {
		t.Errorf("context = %v\nwant %v", evt.Context, want)
	}

	// Pre and post of the same call get different ids; the same input at the
	// same instant is stable.
	again := BuildEvent(ev, "host-1", actor, ts, Decision{})
	post := *ev
	post.HookEvent, post.Phase = "PostToolUse", PhasePost
	if BuildEvent(&post, "host-1", actor, ts, Decision{}).ID == evt.ID {
		t.Error("pre and post ids must differ")
	}
	if again.ID != evt.ID {
		t.Error("id must be deterministic")
	}
}

func TestBuildEvent_FileURLAndBlocked(t *testing.T) {
	ts := time.Now()
	file := BuildEvent(&ToolEvent{Tool: ToolCursor, HookEvent: "beforeReadFile", Phase: PhasePre, ToolName: "file_read", FilePath: "/w/.env"},
		"h", Actor{PID: 1}, ts, Decision{Blocked: true, RuleID: 9, SignalType: "file_open", Candidate: "/w/.env", Pattern: "*/.env"})
	if file.Target == nil || file.Target.FilePath != "/w/.env" {
		t.Errorf("file target = %+v", file.Target)
	}
	if file.Actor.Comm != "cursor" || file.Context["ai_type"] != "cursor" {
		t.Errorf("cursor actor = %+v ctx=%v", file.Actor, file.Context)
	}
	if file.Context["decision"] != "blocked" || file.Context["block_rule_id"] != 9 || file.Context["block_signal_type"] != "file_open" || file.Context["block_candidate"] != "/w/.env" {
		t.Errorf("blocked context = %v", file.Context)
	}

	fetch := BuildEvent(&ToolEvent{Tool: ToolClaudeCode, HookEvent: "PreToolUse", Phase: PhasePre, ToolName: "WebFetch", URL: "https://evil.example:8443/x?y=1"},
		"h", Actor{PID: 1}, ts, Decision{})
	if fetch.Target == nil || fetch.Target.Domain != "evil.example" || fetch.Context["url"] != "https://evil.example:8443/x?y=1" {
		t.Errorf("fetch = target %+v ctx %v", fetch.Target, fetch.Context)
	}
}

func TestBuildEvent_PostOutcomeAndPrivacy(t *testing.T) {
	ok := false
	ev := &ToolEvent{Tool: ToolClaudeCode, HookEvent: "PostToolUseFailure", Phase: PhasePost, ToolName: "Bash",
		Command: "npm test", Success: &ok, Error: "Exit code 1", DurationMs: 4187, Interrupted: false}
	evt := BuildEvent(ev, "h", Actor{PID: 1}, time.Now(), Decision{})
	if evt.Context["success"] != false || evt.Context["error"] != "Exit code 1" || evt.Context["duration_ms"] != int64(4187) {
		t.Errorf("post context = %v", evt.Context)
	}
	raw, _ := json.Marshal(evt)
	for _, forbidden := range []string{"stdout", "tool_response", "old_string", "new_string", "content", "prompt", "transcript"} {
		if strings.Contains(string(raw), `"`+forbidden+`"`) {
			t.Errorf("event JSON must not contain %q: %s", forbidden, raw)
		}
	}
	pre := BuildEvent(&ToolEvent{Tool: ToolClaudeCode, HookEvent: "PreToolUse", Phase: PhasePre, ToolName: "Bash", Command: "ls", Success: &ok},
		"h", Actor{PID: 1}, time.Now(), Decision{})
	if _, has := pre.Context["success"]; has {
		t.Error("pre events carry no outcome")
	}
}

func TestShellCommandsAndExecutable(t *testing.T) {
	cases := map[string][]string{
		"npm test": {"npm test"},
		"cd /x && make; ls | grep foo || true\nid": {"cd /x", "make", "ls", "grep foo", "true", "id"},
		"  ": nil,
	}
	for in, want := range cases {
		if got := ShellCommands(in); !reflect.DeepEqual(got, want) {
			t.Errorf("ShellCommands(%q) = %q, want %q", in, got, want)
		}
	}
	exe := map[string]string{
		"nc -l 4444":                        "nc",
		"sudo /usr/bin/ncat 1.2.3.4 22":     "/usr/bin/ncat",
		"FOO=1 BAR=2 env python3 x.py":      "python3",
		`"C:\Tools\nc.exe" -e cmd`:          `C:\Tools\nc.exe`,
		"time nice -n 5 ./build.sh":         "./build.sh",
		"sudo -u postgres psql -c x":        "psql",
		"env -i -u HOME python3":            "python3",
		"":                                  "",
		"-x":                                "",
		"a=b=c echo hi":                     "echo",
		"http://not-an-assignment=1 curl x": "http://not-an-assignment=1",
	}
	for in, want := range exe {
		if got := Executable(in); got != want {
			t.Errorf("Executable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPathTokens(t *testing.T) {
	got := PathTokens(`cat ~/.ssh/id_rsa /etc/shadow ./local.txt "quoted/p" --flag=/skip -o https://x/y KEY=~/.aws/credentials plain`, "/home/u")
	want := []string{"/home/u/.ssh/id_rsa", "/etc/shadow", "./local.txt", "quoted/p", "/home/u/.aws/credentials"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PathTokens = %q, want %q", got, want)
	}
	if PathTokens("ls", "") != nil {
		t.Error("no path tokens expected")
	}
}

func TestCurrentActor(t *testing.T) {
	a := CurrentActor()
	if a.PID <= 0 {
		t.Errorf("pid = %d", a.PID)
	}
	if a.User == "" {
		t.Error("user should be resolved")
	}
}

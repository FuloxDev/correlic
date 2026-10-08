package query

import (
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

func activityEvent(id, host, typ string, ts time.Time, actor event.ActorStruct, target *event.TargetStruct, ctx map[string]any) event.Event {
	return event.Event{ID: id, HostID: host, Type: typ, Timestamp: ts, Process: &actor, Target: target, Context: ctx}
}

func TestBuildActivityStream_GroupsPerSession(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	since := now.Add(-30 * time.Minute)
	sessA := map[string]any{"ai_session_id": "sess-a", "is_ai": true, "ai_type": "claude"}
	sessB := map[string]any{"ai_session_id": "sess-b", "is_ai": true, "ai_type": "cursor"}

	events := []event.Event{
		// newest first, as the query returns them
		activityEvent("a4", "h1", "net_connect", now.Add(-1*time.Minute), event.ActorStruct{PID: 12, Comm: "curl"}, &event.TargetStruct{IP: "1.2.3.4", Port: 4444}, sessA),
		activityEvent("a3", "h1", "file_open", now.Add(-2*time.Minute), event.ActorStruct{PID: 11, Comm: "cat"}, &event.TargetStruct{FilePath: "/root/.ssh/id_rsa"}, sessA),
		activityEvent("a2", "h1", "process_exec", now.Add(-3*time.Minute), event.ActorStruct{PID: 11, Comm: "bash", Cmdline: []string{"bash", "-c", "x"}}, nil, map[string]any{"ai_session_id": "sess-a", "is_ai": true, "ai_type": "claude", "synthetic_exec": true}),
		activityEvent("a1", "h1", "file_open", now.Add(-4*time.Minute), event.ActorStruct{PID: 10, Comm: "claude"}, &event.TargetStruct{FilePath: "/proc/self/status"}, sessA),
		activityEvent("b1", "h2", "process_exec", now.Add(-10*time.Minute), event.ActorStruct{PID: 50, Comm: "git", Cmdline: []string{"git", "push"}}, nil, sessB),
	}
	roots := map[string][]sessionRoot{
		"sess-a": {{StartedAt: now.Add(-2 * time.Hour), PID: 10, Comm: "claude", ExePath: "/usr/bin/claude"}},
	}

	resp := buildActivityStream(events, roots, since, now, 2)
	if len(resp.Agents) != 2 {
		t.Fatalf("agents = %d, want 2", len(resp.Agents))
	}
	// Ordered newest session first: sess-b has no recorded root so it starts at
	// its earliest in-window event (-10m); sess-a started two hours ago.
	b, a := resp.Agents[0], resp.Agents[1]
	if b.AIType != "cursor" || a.AIType != "claude" {
		t.Fatalf("order = %s,%s; want cursor,claude", b.AIType, a.AIType)
	}

	if a.AgentName != "claude" || a.AgentPID != 10 || a.ExePath != "/usr/bin/claude" || a.HostID != "h1" {
		t.Errorf("session a identity = %+v", a)
	}
	if !a.StartedAt.Equal(now.Add(-2*time.Hour)) || a.Duration != "2h" {
		t.Errorf("session a started=%s duration=%s", a.StartedAt, a.Duration)
	}
	if a.ChildCount != 2 { // pids 10 (root), 11, 12
		t.Errorf("session a child_count = %d, want 2", a.ChildCount)
	}
	// /proc read is significance 1 (filtered at min 2); synthetic exec hidden.
	if len(a.Actions) != 2 {
		t.Fatalf("session a actions = %d, want 2: %+v", len(a.Actions), a.Actions)
	}
	if a.Actions[0].EventID != "a3" || a.Actions[1].EventID != "a4" {
		t.Errorf("actions not oldest-first: %s, %s", a.Actions[0].EventID, a.Actions[1].EventID)
	}
	if a.Actions[0].Significance != 5 || a.Actions[0].Category != "file" || a.Actions[0].ProcessComm != "cat" {
		t.Errorf("ssh key read action = %+v", a.Actions[0])
	}
	if a.Stats.FilesRead != 1 || a.Stats.Connections != 1 || a.Stats.TotalEvents != 2 {
		t.Errorf("session a stats = %+v", a.Stats)
	}

	// Session b: no recorded root, so the earliest in-window exec is the root.
	if b.AgentName != "git" || b.AgentPID != 50 || b.ChildCount != 0 {
		t.Errorf("session b identity = %+v", b)
	}
	if !b.StartedAt.Equal(now.Add(-10 * time.Minute)) {
		t.Errorf("session b started = %s", b.StartedAt)
	}
	if len(b.Actions) != 1 || b.Actions[0].Category != "command" || b.Stats.CommandsRun != 1 {
		t.Errorf("session b actions = %+v", b.Actions)
	}
	if !resp.WindowStart.Equal(since) || !resp.WindowEnd.Equal(now) {
		t.Errorf("window = %s..%s", resp.WindowStart, resp.WindowEnd)
	}
}

func TestBuildActivityStream_IsAIWithoutSessionFallsBackToHostAndType(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	tagged := map[string]any{"is_ai": true}
	events := []event.Event{
		activityEvent("e2", "h1", "file_write", now.Add(-time.Minute), event.ActorStruct{PID: 7, Comm: "python"}, &event.TargetStruct{FilePath: "/srv/app/main.py"}, tagged),
		activityEvent("e1", "h1", "file_open", now.Add(-2*time.Minute), event.ActorStruct{PID: 7, Comm: "python"}, &event.TargetStruct{FilePath: "/srv/app/main.py"}, tagged),
		activityEvent("x1", "h9", "file_open", now.Add(-2*time.Minute), event.ActorStruct{PID: 7, Comm: "python"}, &event.TargetStruct{FilePath: "/srv/app/main.py"}, tagged),
	}
	resp := buildActivityStream(events, nil, now.Add(-time.Hour), now, 1)
	if len(resp.Agents) != 2 {
		t.Fatalf("agents = %d, want one per host", len(resp.Agents))
	}
	for _, ag := range resp.Agents {
		if ag.AIType != defaultActivityAIType || ag.AgentName != "python" || ag.AgentPID != 0 {
			t.Errorf("fallback identity = %+v", ag)
		}
	}
	var h1 AgentSummary
	for _, ag := range resp.Agents {
		if ag.HostID == "h1" {
			h1 = ag
		}
	}
	if h1.Stats.FilesModified != 1 || h1.Stats.FilesRead != 1 || len(h1.Actions) != 2 {
		t.Errorf("h1 stats = %+v actions = %d", h1.Stats, len(h1.Actions))
	}
}

func TestBuildActivityStream_EmptyIsAnEmptyList(t *testing.T) {
	now := time.Now()
	resp := buildActivityStream(nil, nil, now.Add(-time.Hour), now, 2)
	if resp.Agents == nil || len(resp.Agents) != 0 {
		t.Fatalf("agents = %#v, want empty non-nil slice", resp.Agents)
	}
}

func TestBuildActivityStream_AllActionsFilteredStillListsSession(t *testing.T) {
	now := time.Now()
	ctx := map[string]any{"ai_session_id": "s", "ai_type": "claude"}
	events := []event.Event{
		activityEvent("e1", "h1", "file_open", now.Add(-time.Minute), event.ActorStruct{PID: 3, Comm: "claude"}, &event.TargetStruct{FilePath: "/proc/3/stat"}, ctx),
	}
	resp := buildActivityStream(events, nil, now.Add(-time.Hour), now, 5)
	if len(resp.Agents) != 1 || len(resp.Agents[0].Actions) != 0 || resp.Agents[0].Actions == nil {
		t.Fatalf("agents = %+v", resp.Agents)
	}
}

func TestPickRoot_PrefersProcessNamedLikeTheAIType(t *testing.T) {
	t0 := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	cands := []sessionRoot{
		{StartedAt: t0, PID: 20, Comm: "bash", ExePath: "/usr/bin/bash", Argv0: "/bin/bash"},
		{StartedAt: t0.Add(time.Millisecond), PID: 10, Comm: "node", ExePath: "/usr/bin/node", Argv0: "claude"},
		{StartedAt: t0.Add(2 * time.Millisecond), PID: 30, Comm: "claude", ExePath: "/opt/claude-code/bin/claude"},
	}
	if r := pickRoot(cands, "claude"); r == nil || r.PID != 10 {
		t.Fatalf("pickRoot(claude) = %+v, want argv0 match pid 10", r)
	}
	if r := pickRoot(cands, "cursor"); r == nil || r.PID != 20 {
		t.Fatalf("pickRoot(cursor) = %+v, want earliest pid 20", r)
	}
	if r := pickRoot(cands, "ai-agent"); r == nil || r.PID != 20 {
		t.Fatalf("pickRoot(default type) = %+v, want earliest", r)
	}
	if pickRoot(nil, "claude") != nil {
		t.Fatal("pickRoot(nil) should be nil")
	}
	win := []sessionRoot{
		{StartedAt: t0, PID: 1, Comm: "cmd.exe"},
		{StartedAt: t0, PID: 2, Comm: "Cursor.exe", ExePath: `C:\Users\me\AppData\Local\Programs\cursor\Cursor.exe`},
	}
	if r := pickRoot(win, "cursor"); r == nil || r.PID != 2 {
		t.Fatalf("pickRoot(windows cursor) = %+v, want pid 2", r)
	}
}

func hookEvent(id, host string, ts time.Time, pid int, ctx map[string]any) event.Event {
	base := map[string]any{"is_ai": true, "ai_type": "claude-code", "ai_session_id": "hook-sess", "hook_event": "PreToolUse", "phase": "pre", "decision": "allowed"}
	for k, v := range ctx {
		base[k] = v
	}
	evt := event.Event{ID: id, HostID: host, Type: "ai_tool_call", Timestamp: ts, Process: &event.ActorStruct{PID: pid, Comm: "claude", User: "alice"}, Context: base}
	if fp, ok := base["file_path"].(string); ok {
		evt.Target = &event.TargetStruct{FilePath: fp}
	}
	return evt
}

func TestBuildActivityStream_HookOnlySessionIsNamedAfterTheTool(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	since := now.Add(-30 * time.Minute)
	events := []event.Event{
		// newest first
		hookEvent("k6", "mac", now.Add(-1*time.Minute), 500, map[string]any{"tool_name": "Bash", "command": "cat /etc/shadow", "decision": "blocked", "block_rule_id": 3, "tool_use_id": "t6"}),
		hookEvent("k5", "mac", now.Add(-2*time.Minute), 500, map[string]any{"tool_name": "Bash", "command": "git push", "phase": "post", "hook_event": "PostToolUse", "tool_use_id": "t4", "success": true}),
		hookEvent("k4", "mac", now.Add(-3*time.Minute), 500, map[string]any{"tool_name": "Bash", "command": "git push", "tool_use_id": "t4"}),
		hookEvent("k3", "mac", now.Add(-4*time.Minute), 500, map[string]any{"tool_name": "Edit", "file_path": "/Users/alice/proj/main.go", "tool_use_id": "t3"}),
		hookEvent("k2", "mac", now.Add(-5*time.Minute), 500, map[string]any{"tool_name": "Read", "file_path": "/Users/alice/proj/README.md", "tool_use_id": "t2"}),
		hookEvent("k1", "mac", now.Add(-6*time.Minute), 500, map[string]any{"hook_event": "SessionStart", "phase": "session"}),
	}

	resp := buildActivityStream(events, nil, since, now, 2)
	if len(resp.Agents) != 1 {
		t.Fatalf("agents = %d, want 1", len(resp.Agents))
	}
	a := resp.Agents[0]
	if a.AgentName != "claude-code (hooks)" || a.AIType != "claude-code" || a.HostID != "mac" || a.AgentPID != 500 {
		t.Errorf("identity = %+v", a)
	}
	if !a.StartedAt.Equal(now.Add(-6 * time.Minute)) {
		t.Errorf("started = %s, want the session start event", a.StartedAt)
	}
	// session start is significance 1 (filtered); the post event pairs with its pre; four actions remain.
	if len(a.Actions) != 4 {
		t.Fatalf("actions = %d: %+v", len(a.Actions), a.Actions)
	}
	ids := []string{a.Actions[0].EventID, a.Actions[1].EventID, a.Actions[2].EventID, a.Actions[3].EventID}
	if ids[0] != "k2" || ids[1] != "k3" || ids[2] != "k4" || ids[3] != "k6" {
		t.Errorf("action order = %v", ids)
	}
	read, edit, push, blocked := a.Actions[0], a.Actions[1], a.Actions[2], a.Actions[3]
	if read.Category != "file" || read.Significance != 3 || read.Detail != "Read: /Users/alice/proj/README.md" || read.EventType != "ai_tool_call" {
		t.Errorf("read action = %+v", read)
	}
	if edit.Category != "file" || edit.Significance != 5 || edit.Action != "📝 Edited /Users/alice/proj/main.go" {
		t.Errorf("edit action = %+v", edit)
	}
	if push.Category != "command" || push.Significance != 4 || push.Action != "⚙️ Ran: git push" || push.Detail != "Bash: git push" {
		t.Errorf("push action = %+v", push)
	}
	if blocked.Significance != 5 || blocked.Category != "command" || blocked.Action != "⛔ Blocked: ⚙️ cat /etc/shadow" {
		t.Errorf("blocked action = %+v", blocked)
	}
	if blocked.ProcessPID != 500 || blocked.ProcessComm != "claude" {
		t.Errorf("blocked actor = %+v", blocked)
	}
	if a.Stats.FilesRead != 1 || a.Stats.FilesModified != 1 || a.Stats.CommandsRun != 2 || a.Stats.TotalEvents != 4 {
		t.Errorf("stats = %+v", a.Stats)
	}
	if a.ChildCount != 0 {
		t.Errorf("child_count = %d", a.ChildCount)
	}
}

func TestBuildActivityStream_HookEventsJoinAKernelSession(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	ctx := map[string]any{"ai_session_id": "mixed", "is_ai": true, "ai_type": "claude"}
	events := []event.Event{
		activityEvent("m2", "h1", "process_exec", now.Add(-time.Minute), event.ActorStruct{PID: 11, Comm: "git", Cmdline: []string{"git", "push"}}, nil, ctx),
		hookEvent("m1", "h1", now.Add(-2*time.Minute), 10, map[string]any{"ai_session_id": "mixed", "ai_type": "claude", "tool_name": "WebFetch", "url": "https://pastebin.com/raw/x"}),
	}
	roots := map[string][]sessionRoot{"mixed": {{StartedAt: now.Add(-time.Hour), PID: 10, Comm: "claude", ExePath: "/usr/bin/claude"}}}
	resp := buildActivityStream(events, roots, now.Add(-time.Hour), now, 2)
	if len(resp.Agents) != 1 {
		t.Fatalf("agents = %d, want 1 (hook and kernel events share the session)", len(resp.Agents))
	}
	a := resp.Agents[0]
	if a.AgentName != "claude" || a.AgentPID != 10 {
		t.Errorf("a recorded root keeps its name: %+v", a)
	}
	if len(a.Actions) != 2 || a.Actions[0].Category != "network" || a.Actions[0].Action != "🌐 Fetched https://pastebin.com/raw/x" || a.Actions[0].Significance != 3 {
		t.Errorf("actions = %+v", a.Actions)
	}
	if a.Stats.Connections != 1 || a.Stats.CommandsRun != 1 {
		t.Errorf("stats = %+v", a.Stats)
	}
}

func TestBuildToolCallAction_Fallbacks(t *testing.T) {
	now := time.Now()
	mcp := hookEvent("x1", "h", now, 1, map[string]any{"tool_name": "mcp__github__create_issue"})
	if act, write := buildToolCallAction(&mcp); act.Significance != 2 || act.Category != "command" || write || act.Detail != "mcp__github__create_issue: mcp__github__create_issue" {
		t.Errorf("mcp action = %+v write=%v", act, write)
	}
	end := hookEvent("x2", "h", now, 1, map[string]any{"hook_event": "sessionEnd", "phase": "session"})
	if act, _ := buildToolCallAction(&end); act.Action != "session ended" || act.Significance != 1 {
		t.Errorf("session end = %+v", act)
	}
	bare := hookEvent("x3", "h", now, 1, nil)
	if act, _ := buildToolCallAction(&bare); act.Action != "AI tool call" || act.Significance != 1 {
		t.Errorf("bare = %+v", act)
	}
	cursorEdit := hookEvent("x4", "h", now, 1, map[string]any{"ai_type": "cursor", "tool_name": "file_edit", "file_path": "/w/app.ts", "phase": "post", "hook_event": "afterFileEdit"})
	if act, write := buildToolCallAction(&cursorEdit); !write || act.Significance != 5 {
		t.Errorf("cursor afterFileEdit = %+v write=%v", act, write)
	}
}

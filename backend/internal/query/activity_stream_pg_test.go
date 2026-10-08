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

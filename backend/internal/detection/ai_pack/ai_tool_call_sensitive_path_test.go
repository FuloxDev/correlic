package ai_pack_test

import (
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/detection/ai_pack"
	"github.com/correlic/correlic-backend/internal/event"
)

func toolCallEvent(id string, ctx map[string]any) *event.Event {
	base := map[string]any{
		"is_ai": true, "ai_type": "claude-code", "ai_session_id": "sess-hook",
		"hook_event": "PreToolUse", "phase": "pre", "decision": "allowed", "tool_use_id": "toolu_" + id,
	}
	for k, v := range ctx {
		base[k] = v
	}
	evt := &event.Event{
		SchemaVersion: 1,
		ID:            id,
		HostID:        "mac-1",
		Timestamp:     time.Now(),
		Source:        "hook",
		Type:          "ai_tool_call",
		Process:       &event.ActorStruct{PID: 900, Comm: "claude", User: "alice", Role: "agent"},
		Context:       base,
	}
	if fp, ok := base["file_path"].(string); ok {
		evt.Target = &event.TargetStruct{FilePath: fp}
	}
	return evt
}

func findingByID(findings []detection.Finding, id string) *detection.Finding {
	for i := range findings {
		if findings[i].DetectionID == id {
			return &findings[i]
		}
	}
	return nil
}

const sensitiveRule = "ai.tool_call_sensitive_path"

func TestToolCallSensitivePath_FileRead(t *testing.T) {
	engine := detection.NewEngine()
	engine.RegisterPack(ai_pack.NewAIPack())
	cache := detection.NewAttributionCache(0, 0)

	evt := toolCallEvent("h1", map[string]any{"tool_name": "Read", "file_path": "/Users/alice/.ssh/id_ed25519"})
	findings := evaluateNoGraph(t, engine, cache, evt)
	f := findingByID(findings, sensitiveRule)
	if f == nil {
		t.Fatalf("expected %s, got %+v", sensitiveRule, findings)
	}
	if f.Severity != "high" || f.HostID != "mac-1" || f.AnchorEventID != "h1" {
		t.Errorf("stamping = sev %s host %s anchor %s", f.Severity, f.HostID, f.AnchorEventID)
	}
	if f.Context["ai_type"] != "claude-code" || f.Context["tool_name"] != "Read" || f.Context["file_path"] != "/Users/alice/.ssh/id_ed25519" {
		t.Errorf("context = %v", f.Context)
	}
	if f.Context["matched_pattern"] != ".ssh/" || f.Context["signal_type"] != "file_activity" || f.Context["pattern"] != "/Users/alice/.ssh/id_ed25519" {
		t.Errorf("pattern context = %v", f.Context)
	}
	if f.Confidence != 0.75 {
		t.Errorf("confidence = %v", f.Confidence)
	}
	// Only the hook rule fires: file_open/process_exec rules are not scoped to ai_tool_call.
	for _, other := range findings {
		if other.DetectionID != sensitiveRule {
			t.Errorf("unexpected finding %s on an ai_tool_call event", other.DetectionID)
		}
	}
}

func TestToolCallSensitivePath_CommandTokens(t *testing.T) {
	engine := detection.NewEngine()
	engine.RegisterPack(ai_pack.NewAIPack())
	cache := detection.NewAttributionCache(0, 0)

	cmd := toolCallEvent("h2", map[string]any{"tool_name": "Bash", "command": "cat ~/.aws/credentials | base64", "decision": "blocked"})
	f := findingByID(evaluateNoGraph(t, engine, cache, cmd), sensitiveRule)
	if f == nil {
		t.Fatal("expected a finding for cat ~/.aws/credentials")
	}
	if f.Context["file_path"] != "~/.aws/credentials" || f.Context["signal_type"] != "command" || f.Context["pattern"] != "cat ~/.aws/credentials | base64" {
		t.Errorf("context = %v", f.Context)
	}
	if f.Context["decision"] != "blocked" || f.Confidence != 0.70 {
		t.Errorf("blocked call: decision=%v confidence=%v summary=%q", f.Context["decision"], f.Confidence, f.Summary)
	}

	cursor := toolCallEvent("h3", map[string]any{"ai_type": "cursor", "tool_name": "shell", "command": "sudo cat /etc/shadow"})
	if f := findingByID(evaluateNoGraph(t, engine, cache, cursor), sensitiveRule); f == nil || f.Context["ai_type"] != "cursor" {
		t.Errorf("cursor shell command: %+v", f)
	}

	// Bare words are not paths: `git config` and `--token` must stay quiet.
	for _, benign := range []string{"git config user.name alice", "npm test", "curl -H 'Authorization: token x' https://api.example/", "ls -la src/"} {
		evt := toolCallEvent("b-"+benign[:3], map[string]any{"tool_name": "Bash", "command": benign})
		if f := findingByID(evaluateNoGraph(t, engine, cache, evt), sensitiveRule); f != nil {
			t.Errorf("benign command %q produced %+v", benign, f.Context)
		}
	}
}

func TestToolCallSensitivePath_IgnoresPostEventsAndNonAI(t *testing.T) {
	engine := detection.NewEngine()
	engine.RegisterPack(ai_pack.NewAIPack())
	cache := detection.NewAttributionCache(0, 0)

	post := toolCallEvent("h4", map[string]any{"tool_name": "Read", "file_path": "/etc/shadow", "phase": "post", "hook_event": "PostToolUse"})
	if f := findingByID(evaluateNoGraph(t, engine, cache, post), sensitiveRule); f != nil {
		t.Errorf("post events must not fire again: %+v", f)
	}

	// A fresh cache: the shared one already learned PID 900 as AI from the
	// events above (that carry-forward is the cache's job).
	plain := toolCallEvent("h5", map[string]any{"tool_name": "Read", "file_path": "/etc/shadow"})
	plain.Context = map[string]any{"tool_name": "Read", "file_path": "/etc/shadow", "phase": "pre"}
	if f := findingByID(evaluateNoGraph(t, engine, detection.NewAttributionCache(0, 0), plain), sensitiveRule); f != nil {
		t.Errorf("event without AI tags must not fire: %+v", f)
	}

	benign := toolCallEvent("h6", map[string]any{"tool_name": "Edit", "file_path": "/Users/alice/proj/main.go"})
	if f := findingByID(evaluateNoGraph(t, engine, cache, benign), sensitiveRule); f != nil {
		t.Errorf("ordinary source file must not fire: %+v", f)
	}
}

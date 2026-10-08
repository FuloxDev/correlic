package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, raw)
	}
	return doc
}

func claudeCommands(t *testing.T, doc map[string]any, event string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	hooks := doc["hooks"].(map[string]any)
	entries, _ := hooks[event].([]any)
	for _, raw := range entries {
		entry := raw.(map[string]any)
		matcher, _ := entry["matcher"].(string)
		for _, h := range entry["hooks"].([]any) {
			out[matcher] = append(out[matcher], h.(map[string]any)["command"].(string))
		}
	}
	return out
}

func TestSetup_FreshGlobalFiles(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin", "correlic-hook")
	res, err := Setup(SetupOptions{Binary: bin, Home: home})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if res.ClaudeSettings != filepath.Join(home, ".claude", "settings.json") || res.CursorHooks != filepath.Join(home, ".cursor", "hooks.json") {
		t.Errorf("paths = %+v", res)
	}

	claude := readJSON(t, res.ClaudeSettings)
	pre := claudeCommands(t, claude, "PreToolUse")
	if !reflect.DeepEqual(pre[ClaudeToolMatcher], []string{bin}) || !reflect.DeepEqual(pre[ClaudeMCPMatcher], []string{bin}) {
		t.Errorf("PreToolUse = %v", pre)
	}
	for _, ev := range []string{"PostToolUse", "PostToolUseFailure"} {
		if cmds := claudeCommands(t, claude, ev); len(cmds[ClaudeToolMatcher]) != 1 || len(cmds[ClaudeMCPMatcher]) != 1 {
			t.Errorf("%s = %v", ev, cmds)
		}
	}
	for _, ev := range []string{"SessionStart", "SessionEnd"} {
		if cmds := claudeCommands(t, claude, ev); !reflect.DeepEqual(cmds[""], []string{bin}) {
			t.Errorf("%s = %v (session events take no matcher)", ev, cmds)
		}
	}
	if _, has := claude["hooks"].(map[string]any)["UserPromptSubmit"]; has {
		t.Error("prompts must not be hooked")
	}

	cursor := readJSON(t, res.CursorHooks)
	if v, _ := cursor["version"].(float64); v != 1 {
		t.Errorf("cursor version = %v", cursor["version"])
	}
	hooks := cursor["hooks"].(map[string]any)
	for _, ev := range cursorHookEvents {
		entries, _ := hooks[ev].([]any)
		if len(entries) != 1 || entries[0].(map[string]any)["command"] != bin {
			t.Errorf("cursor %s = %v", ev, entries)
		}
	}
	if _, has := hooks["beforeSubmitPrompt"]; has {
		t.Error("beforeSubmitPrompt must not be hooked")
	}
}

func TestSetup_IsIdempotentAndPreservesExistingHooks(t *testing.T) {
	home := t.TempDir()
	claudePath := filepath.Join(home, ".claude", "settings.json")
	os.MkdirAll(filepath.Dir(claudePath), 0o755)
	existing := `{
  "model": "opus",
  "permissions": {"allow": ["Bash(git *)"], "deny": []},
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/lint-check", "timeout": 10}]},
      {"matcher": "` + ClaudeToolMatcher + `", "hooks": [{"type": "command", "command": "/old/path/correlic-hook"}]}
    ],
    "Stop": [{"hooks": [{"type": "command", "command": "say done"}]}]
  },
  "env": {"BIG": 12345678901234567890}
}`
	os.WriteFile(claudePath, []byte(existing), 0o644)

	cursorPath := filepath.Join(home, ".cursor", "hooks.json")
	os.MkdirAll(filepath.Dir(cursorPath), 0o755)
	os.WriteFile(cursorPath, []byte(`{"version": 1, "hooks": {"beforeShellExecution": [{"command": "./scripts/audit.sh"}], "afterFileEdit": [{"command": "C:\\old\\correlic-hook.exe"}]}}`), 0o644)

	bin := "/new/bin/correlic-hook"
	for i := 0; i < 3; i++ { // running it repeatedly changes nothing after the first run
		if _, err := Setup(SetupOptions{Claude: true, Cursor: true, Binary: bin, Home: home}); err != nil {
			t.Fatalf("Setup #%d: %v", i, err)
		}
	}

	claude := readJSON(t, claudePath)
	if claude["model"] != "opus" {
		t.Errorf("unrelated keys lost: %v", claude)
	}
	if perms := claude["permissions"].(map[string]any); !reflect.DeepEqual(perms["allow"], []any{"Bash(git *)"}) {
		t.Errorf("permissions changed: %v", perms)
	}
	raw, _ := os.ReadFile(claudePath)
	if !strings.Contains(string(raw), "12345678901234567890") {
		t.Errorf("large number not preserved verbatim:\n%s", raw)
	}
	pre := claudeCommands(t, claude, "PreToolUse")
	if !reflect.DeepEqual(pre["Bash"], []string{"/usr/local/bin/lint-check"}) {
		t.Errorf("foreign PreToolUse hook changed: %v", pre)
	}
	if !reflect.DeepEqual(pre[ClaudeToolMatcher], []string{bin}) {
		t.Errorf("existing correlic-hook entry not updated in place: %v", pre[ClaudeToolMatcher])
	}
	if !reflect.DeepEqual(pre[ClaudeMCPMatcher], []string{bin}) {
		t.Errorf("mcp matcher = %v", pre[ClaudeMCPMatcher])
	}
	if stop := claudeCommands(t, claude, "Stop"); !reflect.DeepEqual(stop[""], []string{"say done"}) {
		t.Errorf("Stop hooks changed: %v", stop)
	}
	// The lint-check entry keeps its timeout.
	preEntries := claude["hooks"].(map[string]any)["PreToolUse"].([]any)
	first := preEntries[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if first["timeout"] != float64(10) {
		t.Errorf("timeout lost: %v", first)
	}

	cursor := readJSON(t, cursorPath)
	hooks := cursor["hooks"].(map[string]any)
	shell := hooks["beforeShellExecution"].([]any)
	if len(shell) != 2 || shell[0].(map[string]any)["command"] != "./scripts/audit.sh" || shell[1].(map[string]any)["command"] != bin {
		t.Errorf("beforeShellExecution = %v", shell)
	}
	edit := hooks["afterFileEdit"].([]any)
	if len(edit) != 1 || edit[0].(map[string]any)["command"] != bin {
		t.Errorf("afterFileEdit old correlic-hook entry not replaced: %v", edit)
	}
}

func TestSetup_ProjectAndSingleTool(t *testing.T) {
	project := t.TempDir()
	res, err := Setup(SetupOptions{Cursor: true, Project: project, Binary: "/b/correlic-hook", Home: "/nonexistent-home"})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if res.ClaudeSettings != "" {
		t.Errorf("claude must not be written with --cursor: %q", res.ClaudeSettings)
	}
	if res.CursorHooks != filepath.Join(project, ".cursor", "hooks.json") {
		t.Errorf("cursor path = %q", res.CursorHooks)
	}
	if _, err := os.Stat(filepath.Join(project, ".claude")); !os.IsNotExist(err) {
		t.Error(".claude must not be created")
	}
}

func TestSetup_Errors(t *testing.T) {
	if _, err := Setup(SetupOptions{Home: t.TempDir()}); err == nil {
		t.Error("missing binary must error")
	}
	if _, err := Setup(SetupOptions{Binary: "/b"}); err == nil {
		t.Error("no home and no project must error")
	}
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "settings.json")
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, []byte(`{"hooks": "nope"}`), 0o644)
	if _, err := Setup(SetupOptions{Claude: true, Binary: "/b", Home: home}); err == nil {
		t.Error("a non-object hooks key must not be clobbered")
	}
	os.WriteFile(path, []byte(`not json`), 0o644)
	if _, err := Setup(SetupOptions{Claude: true, Binary: "/b", Home: home}); err == nil {
		t.Error("invalid JSON must not be overwritten")
	}
}

func TestIsHookCommand(t *testing.T) {
	yes := []string{"/usr/bin/correlic-hook", `C:\Correlic\bin\correlic-hook.exe`, `"C:\Program Files\Correlic\correlic-hook.exe" --flag`, "correlic-hook", "/opt/x/CORRELIC-HOOK.EXE"}
	no := []string{"", "/usr/bin/other-hook", "correlic-agent", "echo correlic-hook"}
	for _, c := range yes {
		if !IsHookCommand(c) {
			t.Errorf("IsHookCommand(%q) = false", c)
		}
	}
	for _, c := range no {
		if IsHookCommand(c) {
			t.Errorf("IsHookCommand(%q) = true", c)
		}
	}
}

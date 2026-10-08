package lineage

import (
	"testing"
	"time"
)

func TestLineageTracker(t *testing.T) {
	// Reset singleton and seed test patterns.
	ResetForTesting()
	tracker := GetLineageTracker()
	tracker.UpdatePatterns([]string{"cursor", "copilot", "claude"})

	// Case 1: Non-AI process
	isAI := tracker.RegisterProcess(100, 1, "bash")
	if isAI {
		t.Errorf("bash should not be AI")
	}
	if tracker.IsAI(100) {
		t.Errorf("PID 100 should not be tracked")
	}

	// Case 2: Direct AI match
	isAI = tracker.RegisterProcess(200, 100, "cursor")
	if !isAI {
		t.Errorf("cursor should be AI")
	}
	if !tracker.IsAI(200) {
		t.Errorf("PID 200 should be tracked")
	}
	if got := tracker.GetAIType(200); got != "cursor" {
		t.Errorf("ai_type for cursor root = %q, want cursor", got)
	}

	// Case 3: Inheritance (Child of AI)
	isAI = tracker.RegisterProcess(300, 200, "node") // cursor spawns node
	if !isAI {
		t.Errorf("node spawned by cursor should be AI")
	}
	if !tracker.IsAI(300) {
		t.Errorf("PID 300 should be tracked")
	}
	if tracker.GetSessionID(300) != tracker.GetSessionID(200) {
		t.Errorf("child should inherit parent's session")
	}

	// Case 4: Deep Inheritance (Grandchild of AI)
	isAI = tracker.RegisterProcess(400, 300, "sh") // node spawns sh
	if !isAI {
		t.Errorf("sh spawned by node (spawned by cursor) should be AI")
	}
	if !tracker.IsAI(400) {
		t.Errorf("PID 400 should be tracked")
	}

	// Case 5: Unrelated process
	isAI = tracker.RegisterProcess(500, 1, "vim")
	if isAI {
		t.Errorf("vim spawned by init should not be AI")
	}
	if tracker.IsAI(500) {
		t.Errorf("PID 500 should not be tracked")
	}

	// Case 6: Cleanup. An exited PID stays matchable for the grace period so
	// late-arriving events from short-lived processes are still attributed,
	// then is forgotten.
	tracker.UnregisterProcess(400)
	if !tracker.IsAI(400) {
		t.Errorf("PID 400 should remain matchable during the grace period")
	}
	tracker.mu.Lock()
	tracker.graceAIPIDs[400] = time.Now().Add(-time.Second)
	tracker.mu.Unlock()
	if tracker.IsAI(400) {
		t.Errorf("PID 400 should be unregistered after the grace period")
	}
}

func TestCheckPatternCaseInsensitive(t *testing.T) {
	ResetForTesting()
	tracker := GetLineageTracker()

	// Patterns with mixed case — should be normalized to lowercase by UpdatePatterns
	tracker.UpdatePatterns([]string{"OpenClaw", "CursorAI", "CLAUDE"})

	// All of these should match regardless of input case
	tests := []struct {
		input string
		want  bool
	}{
		{"openclaw", true},        // lowercase input, mixed-case pattern
		{"OpenClaw", true},        // exact case
		{"OPENCLAW", true},        // uppercase input
		{"cursorai", true},        // lowercase
		{"CursorAI", true},        // exact case
		{"claude", true},          // lowercase vs CLAUDE pattern
		{"Claude", true},          // mixed case
		{"vim", false},            // no match
		{"python openclaw", true}, // pattern as a whole token inside a cmdline string
		{"myclaude", false},       // substring only — must not match
	}

	for _, tt := range tests {
		got := tracker.CheckPattern(tt.input)
		if got != tt.want {
			t.Errorf("CheckPattern(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestNormalizePatterns(t *testing.T) {
	kept, ignored := NormalizePatterns([]string{"Claude", " cursor ", "ai", "openai.com", "cc", "claude", ""})
	wantKept := []string{"claude", "cursor"}
	if len(kept) != len(wantKept) {
		t.Fatalf("kept = %v, want %v", kept, wantKept)
	}
	for i := range kept {
		if kept[i] != wantKept[i] {
			t.Errorf("kept[%d] = %q, want %q", i, kept[i], wantKept[i])
		}
	}
	if len(ignored) != 3 {
		t.Errorf("ignored = %v, want 3 entries (ai, openai.com, cc)", ignored)
	}
}

func TestMatchToken(t *testing.T) {
	tests := []struct {
		token   string
		pattern string
		want    bool
	}{
		{"claude", "claude", true},
		{"Claude.exe", "claude", true},
		{"claude-code", "claude", true},
		{"claude_helper", "claude", true},
		{"/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js", "claude", true},
		{`C:\Users\me\AppData\Local\Programs\cursor\Cursor.exe`, "cursor", true},
		{"/opt/claude/bin/x", "claude", true},
		{"--claude", "claude", false},
		{"myclaude", "claude", false},
		{"claudette", "claude", false},
		{"optimized", "zed", false},
		{"diagnostic", "agno", false},
		{"", "claude", false},
		{"claude", "", false},
	}
	for _, tt := range tests {
		if got := MatchToken(tt.token, tt.pattern); got != tt.want {
			t.Errorf("MatchToken(%q, %q) = %v, want %v", tt.token, tt.pattern, got, tt.want)
		}
	}
}

func TestMatchCommand(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		exe      string
		argv     []string
		wantOK   bool
		wantType string
	}{
		{
			name:     "git rebase in a claude/x branch is not AI",
			patterns: []string{"claude"},
			exe:      "/usr/bin/git",
			argv:     []string{"git", "rebase", "--continue"},
			wantOK:   false,
		},
		{
			name:     "claude code under node is AI",
			patterns: []string{"claude", "cursor"},
			exe:      "/usr/bin/node",
			argv:     []string{"node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"},
			wantOK:   true,
			wantType: "claude",
		},
		{
			name:     "cursor --app is AI",
			patterns: []string{"claude", "cursor"},
			exe:      "/opt/cursor/cursor",
			argv:     []string{"cursor", "--app"},
			wantOK:   true,
			wantType: "cursor",
		},
		{
			name:     "cc -o optimized does not match zed",
			patterns: []string{"zed"},
			exe:      "/usr/bin/cc",
			argv:     []string{"cc", "-o", "optimized", "x.c"},
			wantOK:   false,
		},
		{
			name:     "diagnostic does not match agno",
			patterns: []string{"agno"},
			exe:      "/usr/bin/diagnostic",
			argv:     []string{"diagnostic"},
			wantOK:   false,
		},
		{
			name:     "joined command line is never substring matched",
			patterns: []string{"claude"},
			exe:      "/usr/bin/python3",
			argv:     []string{"python3", "-c", "print('myclaudeapp')"},
			wantOK:   false,
		},
		{
			name:     "domain-style patterns are ignored for process matching",
			patterns: []string{"openai.com"},
			exe:      "/usr/bin/curl",
			argv:     []string{"curl", "https://openai.com"},
			wantOK:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ResetForTesting()
			tracker := GetLineageTracker()
			tracker.UpdatePatterns(tt.patterns)
			aiType, ok := tracker.MatchCommand(tt.exe, tt.argv)
			if ok != tt.wantOK {
				t.Fatalf("MatchCommand ok = %v, want %v (type %q)", ok, tt.wantOK, aiType)
			}
			if ok && aiType != tt.wantType {
				t.Errorf("ai_type = %q, want %q", aiType, tt.wantType)
			}
		})
	}
}

func TestRegisterProcessWithCommand_RootViaArgv(t *testing.T) {
	ResetForTesting()
	tracker := GetLineageTracker()
	tracker.UpdatePatterns([]string{"claude"})

	// comm is the generic runtime; the tool name is only in argv.
	ok := tracker.RegisterProcessWithCommand(10, 1, "node", "/usr/bin/node",
		[]string{"node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"})
	if !ok {
		t.Fatal("claude code under node should be AI")
	}
	if got := tracker.GetAIType(10); got != "claude" {
		t.Errorf("ai_type = %q, want claude", got)
	}
	if tracker.GetSessionID(10) == "" {
		t.Error("root should have a session")
	}

	// A child that is a plain git invocation inherits.
	if !tracker.RegisterProcessWithCommand(11, 10, "git", "/usr/bin/git", []string{"git", "rebase", "--continue"}) {
		t.Fatal("child of AI root should be AI")
	}
	if tracker.GetSessionID(11) != tracker.GetSessionID(10) {
		t.Error("child should inherit the root session")
	}
}

func TestChildInheritsSessionEvenWhenItMatchesPattern(t *testing.T) {
	ResetForTesting()
	tracker := GetLineageTracker()
	tracker.UpdatePatterns([]string{"claude", "cursor"})

	if !tracker.RegisterProcess(20, 1, "cursor") {
		t.Fatal("cursor should be AI root")
	}
	rootSess := tracker.GetSessionID(20)

	// cursor spawns claude: must join cursor's session, not open a new one.
	if !tracker.RegisterProcess(21, 20, "claude") {
		t.Fatal("claude under cursor should be AI")
	}
	if got := tracker.GetSessionID(21); got != rootSess {
		t.Errorf("child session = %q, want parent session %q", got, rootSess)
	}
	if got := tracker.GetAIType(21); got != "cursor" {
		t.Errorf("child ai_type = %q, want inherited cursor", got)
	}

	// Same through the explicit marking path (container matches).
	tracker.MarkAIWithType(22, 20, "openclaw")
	if got := tracker.GetSessionID(22); got != rootSess {
		t.Errorf("marked child session = %q, want parent session %q", got, rootSess)
	}

	// And a root marked explicitly gets its own session with the given type.
	tracker.MarkAIWithType(30, 1, "openclaw")
	if got := tracker.GetSessionID(30); got == "" || got == rootSess {
		t.Errorf("explicit root session = %q, want a fresh session", got)
	}
	if got := tracker.GetAIType(30); got != "openclaw" {
		t.Errorf("explicit root ai_type = %q, want openclaw", got)
	}
}

func TestAnnotate(t *testing.T) {
	ResetForTesting()
	tracker := GetLineageTracker()
	tracker.UpdatePatterns([]string{"claude"})
	tracker.RegisterProcess(40, 1, "claude")

	ctx := map[string]any{}
	tracker.Annotate(ctx, 40)
	if ctx["is_ai"] != true {
		t.Errorf("is_ai = %v, want true", ctx["is_ai"])
	}
	if ctx["ai_session_id"] != tracker.GetSessionID(40) {
		t.Errorf("ai_session_id = %v, want %q", ctx["ai_session_id"], tracker.GetSessionID(40))
	}
	if ctx["ai_type"] != "claude" {
		t.Errorf("ai_type = %v, want claude", ctx["ai_type"])
	}

	other := map[string]any{}
	tracker.Annotate(other, 41)
	if len(other) != 0 {
		t.Errorf("non-AI pid must not be annotated, got %v", other)
	}
}

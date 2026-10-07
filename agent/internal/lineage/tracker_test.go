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

	// Case 3: Inheritance (Child of AI)
	isAI = tracker.RegisterProcess(300, 200, "node") // cursor spawns node
	if !isAI {
		t.Errorf("node spawned by cursor should be AI")
	}
	if !tracker.IsAI(300) {
		t.Errorf("PID 300 should be tracked")
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
		{"python openclaw", true}, // pattern inside cmdline string
	}

	for _, tt := range tests {
		got := tracker.CheckPattern(tt.input)
		if got != tt.want {
			t.Errorf("CheckPattern(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

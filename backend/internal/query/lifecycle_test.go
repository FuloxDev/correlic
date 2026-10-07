package query

import (
	"testing"
	"time"
)

func TestBuildProcessLifecycles_ExecAndExit_DurationComputed(t *testing.T) {
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	execs := []ExecRow{
		{ID: "e1", HostID: "h1", Timestamp: base, PID: 100, PPID: 1, ExePath: "/bin/sleep"},
	}
	exits := []ProcessExitRow{
		{ID: "x1", HostID: "h1", Timestamp: base.Add(150 * time.Millisecond), PID: 100, PPID: 1, ExitCode: 0},
	}

	got := BuildProcessLifecycles(execs, exits)
	if len(got) != 1 {
		t.Fatalf("expected 1 lifecycle, got %d", len(got))
	}
	lc := got[0]
	if lc.PID != 100 || lc.PPID != 1 || lc.ExecID != "e1" {
		t.Errorf("lifecycle: pid=100 ppid=1 exec_id=e1, got pid=%d ppid=%d exec_id=%s", lc.PID, lc.PPID, lc.ExecID)
	}
	if !lc.Exited {
		t.Error("expected Exited true")
	}
	if lc.ExitID == nil || *lc.ExitID != "x1" {
		t.Errorf("expected ExitID x1, got %v", lc.ExitID)
	}
	if lc.DurationMs == nil {
		t.Fatal("expected DurationMs to be set")
	}
	if *lc.DurationMs != 150 {
		t.Errorf("expected duration_ms 150, got %d", *lc.DurationMs)
	}
}

func TestBuildProcessLifecycles_MissingExit_DurationNil(t *testing.T) {
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	execs := []ExecRow{
		{ID: "e1", HostID: "h1", Timestamp: base, PID: 100, PPID: 1, ExePath: "/bin/sleep"},
	}
	exits := []ProcessExitRow{} // no exit

	got := BuildProcessLifecycles(execs, exits)
	if len(got) != 1 {
		t.Fatalf("expected 1 lifecycle, got %d", len(got))
	}
	lc := got[0]
	if lc.Exited {
		t.Error("expected Exited false when no exit")
	}
	if lc.ExitID != nil || lc.ExitTime != nil || lc.DurationMs != nil {
		t.Errorf("expected ExitID/ExitTime/DurationMs nil when no exit, got ExitID=%v ExitTime=%v DurationMs=%v",
			lc.ExitID, lc.ExitTime, lc.DurationMs)
	}
}

func TestBuildProcessLifecycles_EmptyExecs_EmptyResult(t *testing.T) {
	exits := []ProcessExitRow{
		{ID: "x1", HostID: "h1", Timestamp: time.Now(), PID: 1, PPID: 0, ExitCode: 0},
	}
	got := BuildProcessLifecycles(nil, exits)
	if len(got) != 0 {
		t.Errorf("expected 0 lifecycles when no execs, got %d", len(got))
	}
}

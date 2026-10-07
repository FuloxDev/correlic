package process

import (
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

func baseEvent(pid, ppid int, typ, id string, ts time.Time) event.Event {
	return event.Event{
		ID: id, HostID: "h1", Timestamp: ts,
		Source: "kernel", Type: typ, SchemaVersion: 1,
		Process: &event.ActorStruct{PID: pid, PPID: ppid, ExePath: "/bin/foo"},
	}
}

func exitEvent(pid, ppid int, id string, ts time.Time, exitCode int) event.Event {
	e := baseEvent(pid, ppid, "process_exit", id, ts)
	e.Context = map[string]any{"exit_code": exitCode}
	return e
}

func TestBuilder_ExecOnly_Running(t *testing.T) {
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	b := NewBuilder()
	b.AddExec(baseEvent(100, 1, "process_exec", "e1", base))
	roots := b.Build()
	if len(roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(roots))
	}
	lc := roots[0]
	if lc.PID != 100 || !lc.Running {
		t.Errorf("expected pid 100 running=true, got pid=%d running=%v", lc.PID, lc.Running)
	}
	if lc.ExitEvent != nil || lc.DurationMs != nil {
		t.Error("expected no exit or duration")
	}
}

func TestBuilder_ExecAndExit_DurationComputed(t *testing.T) {
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	b := NewBuilder()
	b.AddExec(baseEvent(100, 1, "process_exec", "e1", base))
	b.AddExit(exitEvent(100, 1, "x1", base.Add(150*time.Millisecond), 0))
	roots := b.Build()
	if len(roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(roots))
	}
	lc := roots[0]
	if lc.Running {
		t.Error("expected Running false")
	}
	if lc.DurationMs == nil || *lc.DurationMs != 150 {
		t.Errorf("expected duration_ms 150, got %v", lc.DurationMs)
	}
	if lc.ExitCode == nil || *lc.ExitCode != 0 {
		t.Errorf("expected exit_code 0, got %v", lc.ExitCode)
	}
}

func TestBuilder_ExitBeforeExec_StillLinked(t *testing.T) {
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	b := NewBuilder()
	b.AddExit(exitEvent(100, 1, "x1", base.Add(100*time.Millisecond), 0))
	b.AddExec(baseEvent(100, 1, "process_exec", "e1", base))
	roots := b.Build()
	if len(roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(roots))
	}
	lc := roots[0]
	if lc.ExitEvent == nil || lc.Running {
		t.Error("expected exit attached and Running false")
	}
	if lc.DurationMs == nil || *lc.DurationMs != 100 {
		t.Errorf("expected duration_ms 100, got %v", lc.DurationMs)
	}
}

func TestBuilder_DuplicateExec_Ignored(t *testing.T) {
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	b := NewBuilder()
	b.AddExec(baseEvent(100, 1, "process_exec", "e1", base))
	b.AddExec(baseEvent(100, 1, "process_exec", "e2", base.Add(time.Second)))
	roots := b.Build()
	if len(roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(roots))
	}
	if roots[0].ExecEvent.ID != "e1" {
		t.Errorf("expected first exec (e1) kept, got %s", roots[0].ExecEvent.ID)
	}
}

func TestBuilder_ParentChildren_Linkage(t *testing.T) {
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	b := NewBuilder()
	b.AddExec(baseEvent(100, 1, "process_exec", "e1", base))
	b.AddExec(baseEvent(101, 100, "process_exec", "e2", base.Add(time.Second)))
	b.AddExec(baseEvent(102, 100, "process_exec", "e3", base.Add(2*time.Second)))
	roots := b.Build()
	if len(roots) != 1 {
		t.Fatalf("expected 1 root (parent 100; 1 not in set), got %d", len(roots))
	}
	lc := roots[0]
	if lc.PID != 100 {
		t.Errorf("expected root PID 100, got %d", lc.PID)
	}
	if len(lc.Children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(lc.Children))
	}
	pids := map[int]bool{lc.Children[0].PID: true, lc.Children[1].PID: true}
	if !pids[101] || !pids[102] {
		t.Errorf("expected children 101 and 102, got %v", pids)
	}
}

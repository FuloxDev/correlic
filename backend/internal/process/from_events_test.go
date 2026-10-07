package process

import (
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

func TestBuildLifecyclesFromEvents_OneExecOneExit(t *testing.T) {
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	events := []event.Event{
		{
			ID: "e1", HostID: "h1", Timestamp: base, Type: "process_exec", SchemaVersion: 1,
			Process: &event.ActorStruct{PID: 100, PPID: 1, ExePath: "/bin/sleep"},
		},
		{
			ID: "x1", HostID: "h1", Timestamp: base.Add(200 * time.Millisecond), Type: "process_exit", SchemaVersion: 1,
			Process: &event.ActorStruct{PID: 100, PPID: 1},
			Context: map[string]any{"exit_code": 0},
		},
	}
	roots := BuildLifecyclesFromEvents(events)
	if len(roots) != 1 {
		t.Fatalf("expected 1 lifecycle, got %d", len(roots))
	}
	lc := roots[0]
	if lc.Running || lc.DurationMs == nil || *lc.DurationMs != 200 {
		t.Errorf("expected exited with duration 200ms, got running=%v duration=%v", lc.Running, lc.DurationMs)
	}
}

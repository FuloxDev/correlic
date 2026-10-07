package api

import (
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/process"
)

// TestTimelineLifecycleEnrichment asserts that process_exec events get lifecycle (duration_ms, exited) set
// when lifecycle is derived from events (same logic as TimelineHandler).
func TestTimelineLifecycleEnrichment(t *testing.T) {
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
	lifecycles := process.BuildLifecyclesFromEvents(events)
	byPID := process.LifecycleViewByPID(lifecycles)
	for i := range events {
		e := &events[i]
		if e.Type != "process_exec" || e.Process == nil {
			continue
		}
		if v, ok := byPID[e.Process.PID]; ok {
			e.Lifecycle = &event.LifecycleInfo{DurationMs: v.DurationMs, Exited: v.Exited}
		}
	}
	// Find process_exec and assert lifecycle
	var execEvt *event.Event
	for i := range events {
		if events[i].Type == "process_exec" {
			execEvt = &events[i]
			break
		}
	}
	if execEvt == nil {
		t.Fatal("no process_exec in events")
	}
	if execEvt.Lifecycle == nil {
		t.Fatal("expected Lifecycle to be set on process_exec")
	}
	if !execEvt.Lifecycle.Exited {
		t.Error("expected Lifecycle.Exited true")
	}
	if execEvt.Lifecycle.DurationMs == nil || *execEvt.Lifecycle.DurationMs != 200 {
		t.Errorf("expected Lifecycle.DurationMs 200, got %v", execEvt.Lifecycle.DurationMs)
	}
}

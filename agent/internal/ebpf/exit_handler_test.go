//go:build linux

package ebpf

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
)

type captureDispatcher struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *captureDispatcher) Start(ctx context.Context) {}

func (c *captureDispatcher) Enqueue(evt event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, evt)
}

func (c *captureDispatcher) RecordDrop(eventType, reason string) {}

func (c *captureDispatcher) captured() []event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]event.Event(nil), c.events...)
}

func TestExitHandler_Handle_EmitsProcessExitEvent(t *testing.T) {
	disp := &captureDispatcher{}
	h := &ExitHandler{HostID: "host1", Dispatcher: disp}

	raw := ExitEvent{
		PID:       100,
		PPID:      1,
		ExitCode:  0,
		Timestamp: time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC),
		Comm:      "sleep",
	}
	h.Handle(raw)

	events := disp.captured()
	if len(events) != 1 {
		t.Fatalf("expected 1 event enqueued, got %d", len(events))
	}
	evt := events[0]
	if evt.Type != "process_exit" {
		t.Errorf("expected type process_exit, got %q", evt.Type)
	}
	if evt.HostID != "host1" || evt.Source != "kernel" {
		t.Errorf("expected host1/kernel, got %q / %q", evt.HostID, evt.Source)
	}
	if evt.Actor == nil {
		t.Fatal("expected Actor set")
	}
	if evt.Actor.PID != 100 || evt.Actor.PPID != 1 || evt.Actor.ExePath != "" {
		t.Errorf("actor: pid=100 ppid=1 exe=\"\", got pid=%d ppid=%d exe=%q",
			evt.Actor.PID, evt.Actor.PPID, evt.Actor.ExePath)
	}
	if evt.Actor.SessionID == "" {
		t.Errorf("actor: expected session_id to be populated, got empty")
	}
	if evt.Context == nil {
		t.Fatal("expected Context set")
	}
	code, ok := evt.Context["exit_code"].(int)
	if !ok || code != 0 {
		t.Errorf("expected context exit_code 0, got %v (%T)", evt.Context["exit_code"], evt.Context["exit_code"])
	}
	if evt.ID == "" {
		t.Error("expected ID to be set")
	}
}

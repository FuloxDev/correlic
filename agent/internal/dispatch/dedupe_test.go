package dispatch

import (
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
)

func TestWindowDedupe_Allow(t *testing.T) {
	deduper := NewWindowDedupe(100 * time.Millisecond)
	evt := event.Event{
		Type:  "process_exec",
		Actor: &event.Actor{PPID: 1, ExePath: "/bin/foo"},
	}
	if !deduper.Allow(evt) {
		t.Error("first occurrence should be allowed")
	}
	if deduper.Allow(evt) {
		t.Error("duplicate within window should be dropped")
	}
	time.Sleep(150 * time.Millisecond)
	if !deduper.Allow(evt) {
		t.Error("after window should be allowed again")
	}
}

func TestWindowDedupe_NonExecAllowed(t *testing.T) {
	deduper := NewWindowDedupe(10 * time.Millisecond)
	evt := event.Event{Type: "net_accept"}
	if !deduper.Allow(evt) {
		t.Error("non process_exec should always be allowed")
	}
}

func TestWindowDedupe_NoActorAllowed(t *testing.T) {
	deduper := NewWindowDedupe(10 * time.Millisecond)
	evt := event.Event{Type: "process_exec", Actor: nil}
	if !deduper.Allow(evt) {
		t.Error("process_exec with nil Actor should be allowed")
	}
}

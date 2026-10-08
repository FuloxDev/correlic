package esevents

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/lineage"
)

// captureDispatcher records canonical events.
type captureDispatcher struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *captureDispatcher) Start(context.Context) {}

func (c *captureDispatcher) Enqueue(evt event.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, evt)
}

func (c *captureDispatcher) RecordDrop(string, string) {}

func (c *captureDispatcher) snapshot() []event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]event.Event(nil), c.events...)
}

// waitFor blocks until the n-th event (1-based) of the given type was
// enqueued, or fails the test after a deadline.
func (c *captureDispatcher) waitFor(t *testing.T, typ string, n int) event.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		seen := 0
		for _, e := range c.snapshot() {
			if e.Type == typ {
				seen++
				if seen == n {
					return e
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s event #%d; have %+v", typ, n, c.snapshot())
	return event.Event{}
}

func (c *captureDispatcher) count(typ string) int {
	n := 0
	for _, e := range c.snapshot() {
		if e.Type == typ {
			n++
		}
	}
	return n
}

// captureEmit records flat telemetry.
type captureEmit struct {
	mu   sync.Mutex
	recs []emitted
}

type emitted struct {
	typ     string
	payload map[string]any
}

func (c *captureEmit) sink() collect.EventSink {
	return func(eventType string, payload any) bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		m, _ := payload.(map[string]any)
		c.recs = append(c.recs, emitted{typ: eventType, payload: m})
		return true
	}
}

func (c *captureEmit) snapshot() []emitted {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]emitted(nil), c.recs...)
}

// newTracker resets the lineage singleton and installs one AI pattern.
func newTracker(t *testing.T) *lineage.LineageTracker {
	t.Helper()
	lineage.ResetForTesting()
	tr := lineage.GetLineageTracker()
	tr.UpdatePatterns([]string{"claude"})
	return tr
}

func startExecRunner(t *testing.T, src chan Event, disp *captureDispatcher, emit *captureEmit) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := NewExecRunner(ChanSource(src), "eslogger", emit.sink(), nil, "host-1", disp)
	go r.Start(ctx)
}

func claudeExec(pid, ppid uint32) Event {
	return Event{
		Type:      EventExec,
		Timestamp: time.Now(),
		PID:       pid,
		PPID:      ppid,
		UID:       501,
		Comm:      "claude",
		ExePath:   "/usr/local/bin/claude",
		Args:      []string{"claude", "-p", "fix the tests"},
	}
}

func TestExecRunner_DispatchesAIExec(t *testing.T) {
	tracker := newTracker(t)
	disp := &captureDispatcher{}
	emit := &captureEmit{}
	src := make(chan Event, 16)
	startExecRunner(t, src, disp, emit)

	src <- claudeExec(4242, 3310)

	got := disp.waitFor(t, "process_exec", 1)
	if got.Actor == nil || got.Actor.PID != 4242 || got.Actor.PPID != 3310 {
		t.Fatalf("actor = %+v", got.Actor)
	}
	if got.Actor.ExePath != "/usr/local/bin/claude" || len(got.Actor.Cmdline) != 3 {
		t.Errorf("exe/cmdline not carried: %+v", got.Actor)
	}
	if got.Context["is_ai"] != true || got.Context["ai_session_id"] == "" || got.Context["ai_type"] != "claude" {
		t.Errorf("AI context missing: %v", got.Context)
	}
	if !tracker.IsAI(4242) {
		t.Error("exec should register the PID with the lineage tracker")
	}

	recs := emit.snapshot()
	if len(recs) != 1 || recs[0].typ != "process_exec" {
		t.Fatalf("telemetry = %+v", recs)
	}
	if recs[0].payload["source"] != "eslogger" || recs[0].payload["pid"] != uint32(4242) {
		t.Errorf("telemetry payload = %v", recs[0].payload)
	}
}

func TestExecRunner_IgnoresNonAIAndTracksChildren(t *testing.T) {
	newTracker(t)
	disp := &captureDispatcher{}
	emit := &captureEmit{}
	src := make(chan Event, 16)
	startExecRunner(t, src, disp, emit)

	// A plain shell command by an unrelated process is filtered out.
	src <- Event{Type: EventExec, PID: 77, PPID: 1, Comm: "ls", ExePath: "/bin/ls", Args: []string{"ls"}}
	// An AI root, then a child that inherits the session through PPID.
	src <- claudeExec(100, 1)
	src <- Event{Type: EventExec, PID: 101, PPID: 100, Comm: "python3", ExePath: "/usr/bin/python3", Args: []string{"python3", "-c", "1"}}

	root := disp.waitFor(t, "process_exec", 1)
	child := disp.waitFor(t, "process_exec", 2)
	if root.Actor.PID != 100 || child.Actor.PID != 101 {
		t.Fatalf("unexpected order/pids: %d %d", root.Actor.PID, child.Actor.PID)
	}
	if child.Context["ai_session_id"] != root.Context["ai_session_id"] {
		t.Errorf("child session %v != root session %v", child.Context["ai_session_id"], root.Context["ai_session_id"])
	}
	if disp.count("process_exec") != 2 {
		t.Errorf("non-AI exec leaked: %d events", disp.count("process_exec"))
	}
	for _, r := range emit.snapshot() {
		if r.payload["comm"] == "ls" {
			t.Errorf("non-AI exec emitted as telemetry: %v", r.payload)
		}
	}
}

func TestExecRunner_ExitEvent(t *testing.T) {
	tracker := newTracker(t)
	disp := &captureDispatcher{}
	emit := &captureEmit{}
	src := make(chan Event, 16)
	startExecRunner(t, src, disp, emit)

	// Exit of an unknown PID is ignored.
	src <- Event{Type: EventExit, PID: 9, PPID: 1, Comm: "cron", ExitCode: 0}
	src <- claudeExec(200, 1)
	disp.waitFor(t, "process_exec", 1)
	src <- Event{Type: EventExit, PID: 200, PPID: 1, Comm: "claude", ExitCode: 3}

	got := disp.waitFor(t, "process_exit", 1)
	if got.Source != "eslogger" || got.Actor.PID != 200 || got.Actor.PPID != 1 || got.Actor.Comm != "claude" {
		t.Errorf("exit event = %+v actor=%+v", got, got.Actor)
	}
	if got.Context["exit_code"] != int32(3) || got.Context["is_ai"] != true {
		t.Errorf("exit context = %v", got.Context)
	}
	if disp.count("process_exit") != 1 {
		t.Errorf("exit of an untracked PID was dispatched")
	}
	// Unregistered, but still matchable during the grace period.
	if sess := tracker.GetSessionID(200); sess == "" {
		t.Error("session should survive in the grace map after exit")
	}
}

func TestExecRunner_ForkJoinsParentSession(t *testing.T) {
	tracker := newTracker(t)
	r := NewExecRunner(ChanSource(make(chan Event)), "eslogger", nil, nil, "host-1", nil)

	// Child of a non-AI parent: nothing happens.
	r.handleFork(Event{Type: EventFork, PID: 51, PPID: 50, Comm: "bash"}, tracker)
	if tracker.IsAI(51) {
		t.Fatal("child of a non-AI parent must not be tracked")
	}

	if !tracker.RegisterProcess(300, 1, "claude") {
		t.Fatal("setup: claude root not registered")
	}
	r.handleFork(Event{Type: EventFork, PID: 301, PPID: 300, Comm: "claude"}, tracker)
	if !tracker.IsAI(301) {
		t.Fatal("forked child of an AI parent must join the lineage")
	}
	if tracker.GetSessionID(301) != tracker.GetSessionID(300) {
		t.Errorf("child session %q != parent session %q", tracker.GetSessionID(301), tracker.GetSessionID(300))
	}
	// PID 0 is never registered.
	r.handleFork(Event{Type: EventFork, PID: 0, PPID: 300}, tracker)
	if tracker.IsAI(0) {
		t.Error("PID 0 must not be registered")
	}
}

func TestFileRunner_AttributesAIOpens(t *testing.T) {
	tracker := newTracker(t)
	disp := &captureDispatcher{}
	emit := &captureEmit{}
	src := make(chan Event, 16)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := NewFileRunner(ChanSource(src), "eslogger", emit.sink(), nil, "host-1", disp)
	go r.Start(ctx)

	if !tracker.RegisterProcess(500, 1, "claude") {
		t.Fatal("setup: claude not registered")
	}
	// Non-AI process: filtered.
	src <- Event{Type: EventOpen, PID: 600, PPID: 1, Comm: "Finder", FilePath: "/Users/dev/.aws/credentials", OpenFlags: 1}
	// Noise path from an AI process: filtered by pathfilter.
	src <- Event{Type: EventOpen, PID: 500, PPID: 1, Comm: "claude", FilePath: "/tmp/scratch.txt", OpenFlags: 1}
	// Credential read by the AI process: dispatched.
	src <- Event{Type: EventOpen, PID: 500, PPID: 1, Comm: "claude", FilePath: "/Users/dev/.ssh/id_ed25519", OpenFlags: 1}
	// Child of the AI process, seen for the first time on an open: inherits.
	src <- Event{Type: EventOpen, PID: 501, PPID: 500, Comm: "cat", FilePath: "/Users/dev/.kube/config", OpenFlags: 1}

	first := disp.waitFor(t, "file_open", 1)
	second := disp.waitFor(t, "file_open", 2)
	if first.Actor.PID != 500 || first.Target.FilePath != "/Users/dev/.ssh/id_ed25519" {
		t.Errorf("first file_open = %+v target=%+v", first.Actor, first.Target)
	}
	if first.Context["category"] != "ssh_key" || first.Context["open_flags"] != int32(1) || first.Context["is_ai"] != true {
		t.Errorf("first context = %v", first.Context)
	}
	if first.Target.FileSize != -1 {
		t.Errorf("missing file should report size -1, got %d", first.Target.FileSize)
	}
	if second.Actor.PID != 501 || second.Context["ai_session_id"] != first.Context["ai_session_id"] {
		t.Errorf("child open not attributed to the parent's session: %+v %v", second.Actor, second.Context)
	}
	if disp.count("file_open") != 2 {
		t.Errorf("expected 2 file_open events, got %d", disp.count("file_open"))
	}
	recs := emit.snapshot()
	if len(recs) != 2 || recs[0].typ != "file_open" || recs[0].payload["source"] != "eslogger" || recs[0].payload["category"] != "ssh_key" {
		t.Errorf("telemetry = %+v", recs)
	}
}

func TestDNSRunner_DispatchesLookups(t *testing.T) {
	tracker := newTracker(t)
	disp := &captureDispatcher{}
	emit := &captureEmit{}
	src := make(chan Event, 16)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := NewDNSRunner(ChanSource(src), "esf", emit.sink(), nil, "host-1", disp)
	go r.Start(ctx)

	tracker.RegisterProcess(700, 1, "claude")
	src <- Event{Type: EventLookup, PID: 700, PPID: 1, Comm: "claude"} // no domain: ignored
	src <- Event{Type: EventLookup, PID: 701, PPID: 2, Comm: "curl", Domain: "example.com"}
	src <- Event{Type: EventLookup, PID: 700, PPID: 1, Comm: "claude", Domain: "api.anthropic.com"}

	got := disp.waitFor(t, "net_dns", 1)
	if got.Source != "esf" || got.Target.Domain != "api.anthropic.com" || got.Context["category"] != "other" {
		t.Errorf("net_dns = %+v target=%+v ctx=%v", got, got.Target, got.Context)
	}
	if disp.count("net_dns") != 1 {
		t.Errorf("non-AI lookup leaked")
	}
}

func TestFanout_RoutesByTypeAndCloses(t *testing.T) {
	src := make(chan Event, 8)
	f := NewFanout(ChanSource(src), nil)
	done := make(chan struct{})
	go func() {
		f.Start(context.Background())
		close(done)
	}()

	src <- Event{Type: EventExec, PID: 1}
	src <- Event{Type: EventOpen, PID: 2}
	src <- Event{Type: EventLookup, PID: 3}
	src <- Event{Type: EventExit, PID: 4}
	src <- Event{Type: EventFork, PID: 5}
	src <- Event{Type: EventUnknown, PID: 6}
	close(src)

	<-done
	var procPIDs []uint32
	for ev := range f.Process().Events() {
		procPIDs = append(procPIDs, ev.PID)
	}
	if len(procPIDs) != 3 || procPIDs[0] != 1 || procPIDs[1] != 4 || procPIDs[2] != 5 {
		t.Errorf("process events = %v", procPIDs)
	}
	if ev, ok := <-f.Open().Events(); !ok || ev.PID != 2 {
		t.Errorf("open event = %+v ok=%v", ev, ok)
	}
	if ev, ok := <-f.Lookup().Events(); !ok || ev.PID != 3 {
		t.Errorf("lookup event = %+v ok=%v", ev, ok)
	}
	if _, ok := <-f.Open().Events(); ok {
		t.Error("open channel should be closed after the source closed")
	}
	if f.Dropped() != 0 {
		t.Errorf("dropped = %d", f.Dropped())
	}
}

func TestFanout_DropsWhenRunnerIsBehind(t *testing.T) {
	f := NewFanout(ChanSource(make(chan Event)), nil)
	n := cap(f.open) + 5
	for i := 0; i < n; i++ {
		f.route(Event{Type: EventOpen, PID: uint32(i)})
	}
	if got := f.Dropped(); got != 5 {
		t.Errorf("dropped = %d, want 5", got)
	}
	if len(f.open) != cap(f.open) {
		t.Errorf("open channel should be full: %d/%d", len(f.open), cap(f.open))
	}
}

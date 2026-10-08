//go:build !windows

package eslogger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/darwin/esevents"
)

// The collector tests drive a fake eslogger: a shell script that prints
// fixture lines and then behaves as the test needs (stays up, exits at once,
// dies after a while). They need /bin/sh and kill(2), hence the build tag.

func skipWithoutSh(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
}

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// writeScript writes an executable /bin/sh script and returns its path.
func writeScript(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "eslogger")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// useBinary points the package at a fake eslogger for one test.
func useBinary(t *testing.T, path string) {
	t.Helper()
	old := Binary
	Binary = path
	t.Cleanup(func() { Binary = old })
}

// newTestCollector returns a collector with short timings.
func newTestCollector(t *testing.T, names ...string) *Collector {
	t.Helper()
	c := New(nil, names)
	c.StartupGrace = 300 * time.Millisecond
	c.TermGrace = 500 * time.Millisecond
	c.RestartBackoff = 20 * time.Millisecond
	c.MaxBackoff = 100 * time.Millisecond
	c.MaxRestartsPerMinute = 3
	c.ChannelSize = 64
	return c
}

// recv reads one event or fails after a deadline.
func recv(t *testing.T, ch <-chan esevents.Event, within time.Duration) (esevents.Event, bool) {
	t.Helper()
	select {
	case ev, ok := <-ch:
		return ev, ok
	case <-time.After(within):
		t.Fatalf("no event within %s", within)
		return esevents.Event{}, false
	}
}

// waitDone fails unless Wait returns within the deadline.
func waitDone(t *testing.T, c *Collector, within time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		c.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(within):
		t.Fatal("collector did not stop in time")
	}
}

// waitUntil polls cond until it is true or the deadline passes.
func waitUntil(t *testing.T, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestCollector_StreamsEventsAndStopsOnCancel(t *testing.T) {
	skipWithoutSh(t)
	dir := t.TempDir()
	script := writeScript(t, dir, fmt.Sprintf(`echo "$$" > %q
echo "$*" > %q
cat %q %q %q %q
exec sleep 60`,
		filepath.Join(dir, "pid"), filepath.Join(dir, "args"),
		fixturePath(t, "exec.jsonl"), fixturePath(t, "open.jsonl"),
		fixturePath(t, "exit.jsonl"), fixturePath(t, "fork.jsonl")))
	useBinary(t, script)

	c := newTestCollector(t, "exec", "exit", "fork", "open")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var types []esevents.EventType
	for i := 0; i < 4; i++ {
		ev, ok := recv(t, c.Events(), 3*time.Second)
		if !ok {
			t.Fatal("channel closed early")
		}
		types = append(types, ev.Type)
		if ev.PID == 0 || ev.Comm != "claude" {
			t.Errorf("event %d = %+v", i, ev)
		}
	}
	want := []esevents.EventType{esevents.EventExec, esevents.EventOpen, esevents.EventExit, esevents.EventFork}
	for i := range want {
		if types[i] != want[i] {
			t.Errorf("event %d type = %v, want %v", i, types[i], want[i])
		}
	}
	if args, _ := os.ReadFile(filepath.Join(dir, "args")); strings.TrimSpace(string(args)) != "exec exit fork open" {
		t.Errorf("eslogger args = %q", strings.TrimSpace(string(args)))
	}
	if c.Parsed() != 4 || c.Dropped() != 0 || c.ParseErrors() != 0 {
		t.Errorf("counters parsed=%d dropped=%d errors=%d", c.Parsed(), c.Dropped(), c.ParseErrors())
	}

	cancel()
	waitDone(t, c, 5*time.Second)
	if _, ok := <-c.Events(); ok {
		t.Error("events channel should be closed after stop")
	}
	pidText, _ := os.ReadFile(filepath.Join(dir, "pid"))
	var pid int
	fmt.Sscan(strings.TrimSpace(string(pidText)), &pid)
	if pid <= 0 {
		t.Fatalf("fake eslogger did not record its pid: %q", pidText)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Errorf("fake eslogger (pid %d) still alive after cancel: kill(0) = %v", pid, err)
	}
}

func TestCollector_StartupFailureNotPermitted(t *testing.T) {
	skipWithoutSh(t)
	script := writeScript(t, t.TempDir(), `echo "ERROR: Failed to create ES client: ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED" 1>&2
exit 1`)
	useBinary(t, script)

	c := newTestCollector(t)
	err := c.Start(context.Background())
	if !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("Start = %v, want ErrNotPermitted", err)
	}
	if !strings.Contains(err.Error(), "exit status 1") || !strings.Contains(err.Error(), "NOT_PERMITTED") {
		t.Errorf("error lacks exit status or stderr: %v", err)
	}
	waitDone(t, c, time.Second)
	if _, ok := <-c.Events(); ok {
		t.Error("events channel should be closed after a startup failure")
	}
}

func TestCollector_StartupFailureNotRoot(t *testing.T) {
	skipWithoutSh(t)
	script := writeScript(t, t.TempDir(), `echo "eslogger: ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED" 1>&2
exit 1`)
	useBinary(t, script)

	c := newTestCollector(t)
	if err := c.Start(context.Background()); !errors.Is(err, ErrNotRoot) {
		t.Fatalf("Start = %v, want ErrNotRoot", err)
	}
	waitDone(t, c, time.Second)
}

func TestCollector_StartupFailureUnrecognized(t *testing.T) {
	skipWithoutSh(t)
	script := writeScript(t, t.TempDir(), `exit 3`)
	useBinary(t, script)

	c := newTestCollector(t)
	err := c.Start(context.Background())
	if !errors.Is(err, ErrStartup) {
		t.Fatalf("Start = %v, want ErrStartup", err)
	}
	if !strings.Contains(err.Error(), "exit status 3") || !strings.Contains(err.Error(), "no stderr") {
		t.Errorf("error = %v", err)
	}
	// Exiting 0 right away is a startup failure too: eslogger never returns on its own.
	script = writeScript(t, t.TempDir(), `exit 0`)
	useBinary(t, script)
	c = newTestCollector(t)
	if err := c.Start(context.Background()); !errors.Is(err, ErrStartup) {
		t.Fatalf("Start after exit 0 = %v, want ErrStartup", err)
	}
}

func TestCollector_BinaryMissing(t *testing.T) {
	useBinary(t, filepath.Join(t.TempDir(), "eslogger"))
	c := newTestCollector(t)
	if err := c.Start(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Start = %v, want ErrNotFound", err)
	}
	waitDone(t, c, time.Second)
	if _, ok := <-c.Events(); ok {
		t.Error("events channel should be closed")
	}
}

func TestCollector_RestartsAfterCrash(t *testing.T) {
	skipWithoutSh(t)
	dir := t.TempDir()
	runs := filepath.Join(dir, "runs")
	script := writeScript(t, dir, fmt.Sprintf(`echo run >> %q
cat %q
sleep 0.6
exit 2`, runs, fixturePath(t, "exec.jsonl")))
	useBinary(t, script)

	c := newTestCollector(t, "exec")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// One exec event per run: the first run and at least one restart.
	for i := 0; i < 2; i++ {
		ev, ok := recv(t, c.Events(), 5*time.Second)
		if !ok || ev.Type != esevents.EventExec {
			t.Fatalf("run %d: event %+v ok=%v", i, ev, ok)
		}
	}
	if c.Restarts() < 1 {
		t.Errorf("restarts = %d, want >= 1", c.Restarts())
	}
	data, _ := os.ReadFile(runs)
	if n := strings.Count(string(data), "run"); n < 2 {
		t.Errorf("fake eslogger ran %d times, want >= 2", n)
	}
	cancel()
	waitDone(t, c, 5*time.Second)
}

func TestCollector_GivesUpAfterTooManyRestarts(t *testing.T) {
	skipWithoutSh(t)
	script := writeScript(t, t.TempDir(), `sleep 0.4
exit 2`)
	useBinary(t, script)

	c := newTestCollector(t)
	c.StartupGrace = 200 * time.Millisecond
	c.MaxRestartsPerMinute = 2
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Without cancelling: two restarts are allowed, the third death ends it.
	waitDone(t, c, 10*time.Second)
	if _, ok := <-c.Events(); ok {
		t.Error("events channel should be closed after giving up")
	}
	if c.Restarts() != 2 {
		t.Errorf("restarts = %d, want 2", c.Restarts())
	}
}

func TestCollector_DropsWhenChannelFull(t *testing.T) {
	skipWithoutSh(t)
	dir := t.TempDir()
	line, err := os.ReadFile(fixturePath(t, "exec.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	many := filepath.Join(dir, "many.jsonl")
	if err := os.WriteFile(many, []byte(strings.Repeat(strings.TrimSpace(string(line))+"\n", 50)), 0o600); err != nil {
		t.Fatal(err)
	}
	script := writeScript(t, dir, fmt.Sprintf(`cat %q
exec sleep 60`, many))
	useBinary(t, script)

	c := newTestCollector(t, "exec")
	c.ChannelSize = 4
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Nobody reads: the buffer fills and the rest is dropped and counted.
	waitUntil(t, 3*time.Second, func() bool { return c.Parsed() == 50 })
	if c.Dropped() != 46 || len(c.Events()) != 4 {
		t.Errorf("dropped = %d buffered = %d, want 46 and 4", c.Dropped(), len(c.Events()))
	}
	cancel()
	waitDone(t, c, 5*time.Second)
}

func TestCollector_SkipsOversizedLinesAndCountsParseErrors(t *testing.T) {
	skipWithoutSh(t)
	dir := t.TempDir()
	huge := `{"schema_version":1,"event_type":9,"process":{"audit_token":{"pid":9999},"ppid":1,"executable":{"path":"/bin/huge"}},"event":{"exec":{"env":["` +
		strings.Repeat("A", 100<<10) + `"],"args":["huge"]}}}` + "\n"
	mixed := filepath.Join(dir, "mixed.jsonl")
	malformed, err := os.ReadFile(fixturePath(t, "malformed.txt"))
	if err != nil {
		t.Fatal(err)
	}
	execLine, err := os.ReadFile(fixturePath(t, "exec.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mixed, []byte(huge+string(malformed)+string(execLine)), 0o600); err != nil {
		t.Fatal(err)
	}
	script := writeScript(t, dir, fmt.Sprintf(`cat %q
exec sleep 60`, mixed))
	useBinary(t, script)

	c := newTestCollector(t, "exec")
	c.MaxLineBytes = 64 << 10
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ev, ok := recv(t, c.Events(), 3*time.Second)
	if !ok || ev.PID != 4242 {
		t.Fatalf("event = %+v ok=%v", ev, ok)
	}
	waitUntil(t, 3*time.Second, func() bool { return c.ParseErrors() == 3 })
	if c.Oversized() != 1 || c.Parsed() != 1 {
		t.Errorf("oversized = %d parsed = %d", c.Oversized(), c.Parsed())
	}
	cancel()
	waitDone(t, c, 5*time.Second)
}

func TestCollector_FiltersOwnPIDAndEsloggerPID(t *testing.T) {
	skipWithoutSh(t)
	dir := t.TempDir()
	lines := fmt.Sprintf(`{"event_type":15,"event":{"exit":{"stat":0}},"process":{"audit_token":{"pid":%d},"ppid":1,"executable":{"path":"/correlic-agent"}}}
{"event_type":15,"event":{"exit":{"stat":0}},"process":{"audit_token":{"pid":$$},"ppid":1,"executable":{"path":"/usr/bin/eslogger"}}}
{"event_type":15,"event":{"exit":{"stat":0}},"process":{"audit_token":{"pid":4242},"ppid":1,"executable":{"path":"/usr/local/bin/claude"}}}
`, os.Getpid())
	// The script substitutes its own pid ($$) for the second line.
	script := writeScript(t, dir, "cat <<EOF\n"+lines+"EOF\nexec sleep 60")
	useBinary(t, script)

	c := newTestCollector(t, "exit")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ev, ok := recv(t, c.Events(), 3*time.Second)
	if !ok || ev.PID != 4242 {
		t.Fatalf("event = %+v ok=%v", ev, ok)
	}
	waitUntil(t, time.Second, func() bool { return c.Parsed() == 1 })
	if len(c.Events()) != 0 {
		t.Errorf("own-PID events leaked: %d buffered", len(c.Events()))
	}
	cancel()
	waitDone(t, c, 5*time.Second)
}

func TestCollector_CancelBeforeGraceStopsProcess(t *testing.T) {
	skipWithoutSh(t)
	dir := t.TempDir()
	script := writeScript(t, dir, fmt.Sprintf(`echo "$$" > %q
exec sleep 60`, filepath.Join(dir, "pid")))
	useBinary(t, script)

	c := newTestCollector(t)
	c.StartupGrace = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	if err := c.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v, want context.Canceled", err)
	}
	waitDone(t, c, 5*time.Second)
	pidText, _ := os.ReadFile(filepath.Join(dir, "pid"))
	var pid int
	fmt.Sscan(strings.TrimSpace(string(pidText)), &pid)
	if pid > 0 {
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Errorf("fake eslogger still alive: %v", err)
		}
	}
}

func TestCollector_DefaultsAndStartTwice(t *testing.T) {
	c := New(nil, nil)
	if len(c.names) != len(DefaultEvents) || c.StartupGrace != 2*time.Second || c.MaxLineBytes != 4<<20 || c.ChannelSize != 8192 {
		t.Errorf("defaults = %+v", c)
	}
	useBinary(t, filepath.Join(t.TempDir(), "missing"))
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("expected a start error")
	}
	if err := c.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "already started") {
		t.Errorf("second Start = %v", err)
	}
}

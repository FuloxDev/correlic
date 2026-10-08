package eslogger

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/darwin/esevents"
)

// fixtureLines returns the non-blank lines of a testdata file.
func fixtureLines(t *testing.T, name string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var lines [][]byte
	for _, l := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(l)) > 0 {
			lines = append(lines, l)
		}
	}
	return lines
}

func mustParse(t *testing.T, line []byte) esevents.Event {
	t.Helper()
	ev, ok, err := Parse(line)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if !ok {
		t.Fatalf("Parse ignored a line it should accept: %s", line)
	}
	return ev
}

func TestParse_Exec(t *testing.T) {
	ev := mustParse(t, fixtureLines(t, "exec.jsonl")[0])
	if ev.Type != esevents.EventExec {
		t.Fatalf("type = %v", ev.Type)
	}
	// The exec target, not the calling image, describes the event.
	if ev.PID != 4242 || ev.PPID != 3310 || ev.UID != 501 {
		t.Errorf("pid/ppid/uid = %d/%d/%d", ev.PID, ev.PPID, ev.UID)
	}
	if ev.ExePath != "/usr/local/bin/claude" || ev.Comm != "claude" {
		t.Errorf("exe/comm = %q/%q", ev.ExePath, ev.Comm)
	}
	want := []string{"claude", "--dangerously-skip-permissions", "-p", "fix the tests"}
	if len(ev.Args) != len(want) {
		t.Fatalf("args = %q", ev.Args)
	}
	for i := range want {
		if ev.Args[i] != want[i] {
			t.Errorf("args[%d] = %q, want %q", i, ev.Args[i], want[i])
		}
	}
	ts := time.Date(2026, 9, 30, 10, 15, 42, 123456789, time.UTC)
	if !ev.Timestamp.Equal(ts) {
		t.Errorf("timestamp = %v, want %v", ev.Timestamp, ts)
	}
	if ev.FilePath != "" || ev.ExitCode != 0 || ev.Domain != "" {
		t.Errorf("unrelated fields set: %+v", ev)
	}
}

func TestParse_Open(t *testing.T) {
	ev := mustParse(t, fixtureLines(t, "open.jsonl")[0])
	if ev.Type != esevents.EventOpen {
		t.Fatalf("type = %v", ev.Type)
	}
	if ev.PID != 4242 || ev.PPID != 3310 || ev.Comm != "claude" || ev.ExePath != "/usr/local/bin/claude" {
		t.Errorf("process = %+v", ev)
	}
	if ev.FilePath != "/Users/dev/.ssh/id_ed25519" || ev.OpenFlags != 1 {
		t.Errorf("file = %q flags = %d", ev.FilePath, ev.OpenFlags)
	}
}

func TestParse_Exit(t *testing.T) {
	ev := mustParse(t, fixtureLines(t, "exit.jsonl")[0])
	if ev.Type != esevents.EventExit {
		t.Fatalf("type = %v", ev.Type)
	}
	if ev.PID != 4242 || ev.PPID != 3310 || ev.Comm != "claude" {
		t.Errorf("process = %+v", ev)
	}
	if ev.ExitCode != 1 {
		t.Errorf("exit code = %d, want 1 (stat 256)", ev.ExitCode)
	}
}

func TestParse_Fork(t *testing.T) {
	ev := mustParse(t, fixtureLines(t, "fork.jsonl")[0])
	if ev.Type != esevents.EventFork {
		t.Fatalf("type = %v", ev.Type)
	}
	// The child is the subject; the forking process is its parent.
	if ev.PID != 4300 || ev.PPID != 4242 {
		t.Errorf("pid/ppid = %d/%d, want 4300/4242", ev.PID, ev.PPID)
	}
	if ev.Comm != "claude" || ev.UID != 501 {
		t.Errorf("comm/uid = %q/%d", ev.Comm, ev.UID)
	}
}

func TestParse_UnknownEventsIgnored(t *testing.T) {
	for i, line := range fixtureLines(t, "unknown.jsonl") {
		ev, ok, err := Parse(line)
		if err != nil {
			t.Errorf("line %d: unexpected error %v", i, err)
		}
		if ok {
			t.Errorf("line %d: unknown event accepted as %v", i, ev.Type)
		}
	}
}

func TestParse_MalformedLines(t *testing.T) {
	lines := fixtureLines(t, "malformed.txt")
	if len(lines) != 5 {
		t.Fatalf("fixture has %d lines, want 5", len(lines))
	}
	// Truncated object, free text and a JSON array are decode errors.
	for _, i := range []int{0, 1, 2} {
		if _, ok, err := Parse(lines[i]); err == nil || ok {
			t.Errorf("line %d: expected a decode error, got ok=%v err=%v", i, ok, err)
		}
	}
	// Valid JSON that lacks a process or carries wrong field types is
	// ignored, not an error.
	for _, i := range []int{3, 4} {
		if _, ok, err := Parse(lines[i]); err != nil || ok {
			t.Errorf("line %d: expected ignore, got ok=%v err=%v", i, ok, err)
		}
	}
}

func TestParse_BlankLine(t *testing.T) {
	for _, l := range []string{"", "   ", "\n", "\r\n"} {
		if _, ok, err := Parse([]byte(l)); ok || err != nil {
			t.Errorf("blank %q: ok=%v err=%v", l, ok, err)
		}
	}
}

func TestParse_NumericHintWhenEventObjectIsEmpty(t *testing.T) {
	line := []byte(`{"schema_version":1,"event_type":15,"process":{"audit_token":{"pid":77,"euid":0},"ppid":1,"executable":{"path":"/bin/sleep"}},"event":{}}`)
	ev := mustParse(t, line)
	if ev.Type != esevents.EventExit || ev.PID != 77 || ev.PPID != 1 || ev.Comm != "sleep" || ev.ExitCode != 0 {
		t.Errorf("event = %+v", ev)
	}
	// A quoted enumerator name is understood too.
	line = []byte(`{"event_type":"ES_EVENT_TYPE_NOTIFY_EXEC","process":{"audit_token":{"pid":78},"ppid":1,"executable":{"path":"/bin/ls"}}}`)
	ev = mustParse(t, line)
	if ev.Type != esevents.EventExec || ev.PID != 78 || ev.Comm != "ls" {
		t.Errorf("event = %+v", ev)
	}
	// An unknown number without an event object is ignored.
	line = []byte(`{"event_type":33,"process":{"audit_token":{"pid":79},"ppid":1,"executable":{"path":"/bin/ls"}}}`)
	if _, ok, err := Parse(line); ok || err != nil {
		t.Errorf("write event: ok=%v err=%v", ok, err)
	}
}

func TestParse_EventKeyBeatsNumber(t *testing.T) {
	line := []byte(`{"event_type":15,"process":{"audit_token":{"pid":80},"ppid":2,"executable":{"path":"/usr/bin/vim"}},"event":{"open":{"fflag":2,"file":{"path":"/etc/hosts"}}}}`)
	ev := mustParse(t, line)
	if ev.Type != esevents.EventOpen || ev.FilePath != "/etc/hosts" || ev.OpenFlags != 2 {
		t.Errorf("event = %+v", ev)
	}
}

func TestParse_MissingFieldsNeverPanic(t *testing.T) {
	cases := []string{
		`{}`,
		`{"event":{}}`,
		`{"event":{"exec":{}}}`,
		`{"event":{"exec":null},"process":null}`,
		`{"event":{"open":{"file":null}},"process":{"audit_token":{"pid":5}}}`,
		`{"event":{"fork":{"child":null}},"process":{"audit_token":{"pid":5}}}`,
		`{"event":{"exit":{"stat":"nope"}},"process":{"audit_token":{"pid":5},"executable":{}}}`,
		`{"process":{"audit_token":{"pid":-5,"euid":-1},"ppid":-1,"executable":{"path":"/"}},"event":{"exec":{"args":[1,2]}}}`,
		`{"process":{"audit_token":{"pid":99999999999}},"event":{"exec":{}}}`,
	}
	for _, c := range cases {
		ev, ok, err := Parse([]byte(c))
		if err != nil {
			t.Errorf("%s: unexpected error %v", c, err)
		}
		if ok && ev.PID == 0 {
			t.Errorf("%s: accepted an event without a PID", c)
		}
	}
	// A process without an exe path still yields a usable event.
	ev := mustParse(t, []byte(`{"event":{"exit":{"stat":9}},"process":{"audit_token":{"pid":5},"ppid":1}}`))
	if ev.PID != 5 || ev.PPID != 1 || ev.Comm != "" || ev.ExitCode != 137 {
		t.Errorf("event = %+v", ev)
	}
}

func TestParse_TimestampFallsBackToNow(t *testing.T) {
	before := time.Now()
	ev := mustParse(t, []byte(`{"time":"yesterday","event":{"exit":{"stat":0}},"process":{"audit_token":{"pid":6}}}`))
	if ev.Timestamp.Before(before) || ev.Timestamp.After(time.Now().Add(time.Second)) {
		t.Errorf("timestamp %v not near now", ev.Timestamp)
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		stat int64
		want int32
	}{
		{0, 0},
		{256, 1},
		{19968, 78}, // xpcproxy exit reported by eslogger: 0x4E00
		{9, 137},    // SIGKILL
		{15, 143},   // SIGTERM
		{0x057f, 5}, // stopped with signal 5: report the signal byte
		{-1, 0},
	}
	for _, c := range cases {
		if got := exitCode(c.stat); got != c.want {
			t.Errorf("exitCode(%d) = %d, want %d", c.stat, got, c.want)
		}
	}
}

func TestBasename(t *testing.T) {
	cases := map[string]string{
		"/usr/local/bin/claude": "claude",
		"claude":                "claude",
		"/":                     "",
		"":                      "",
		"/Applications/Cursor.app/Contents/MacOS/Cursor": "Cursor",
	}
	for in, want := range cases {
		if got := basename(in); got != want {
			t.Errorf("basename(%q) = %q, want %q", in, got, want)
		}
	}
}

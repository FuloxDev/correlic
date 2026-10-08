//go:build linux

package ebpf

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildExitRecord lays out struct exit_event as the BPF program writes it:
// pid(4) @0, tid(4) @4, ppid(4) @8, exit_code(4) @12, timestamp_ns(8) @16, comm[16] @24 = 40 bytes.
func buildExitRecord(pid, tid, ppid, exitCode uint32, comm string) []byte {
	data := make([]byte, exitEventSize)
	binary.LittleEndian.PutUint32(data[0:4], pid)
	binary.LittleEndian.PutUint32(data[4:8], tid)
	binary.LittleEndian.PutUint32(data[8:12], ppid)
	binary.LittleEndian.PutUint32(data[12:16], exitCode)
	binary.LittleEndian.PutUint64(data[16:24], 1706702400000000000) // boot-time placeholder; parser uses wall-clock time
	copy(data[24:40], comm)
	return data
}

func TestParseExitEvent(t *testing.T) {
	ev, err := parseExitEvent(buildExitRecord(100, 100, 1, 3, "sleep"))
	if err != nil {
		t.Fatal(err)
	}
	if ev.PID != 100 || ev.TID != 100 || ev.PPID != 1 || ev.ExitCode != 3 {
		t.Errorf("pid=100 tid=100 ppid=1 exit_code=3, got pid=%d tid=%d ppid=%d exit_code=%d", ev.PID, ev.TID, ev.PPID, ev.ExitCode)
	}
	if !ev.IsProcessExit() {
		t.Error("tid == pid must be a process exit")
	}
	if ev.Timestamp.Before(time.Now().Add(-5*time.Second)) || ev.Timestamp.After(time.Now().Add(5*time.Second)) {
		t.Errorf("timestamp should be near wall-clock now, got %v", ev.Timestamp)
	}
	if ev.Comm != "sleep" {
		t.Errorf("comm: want sleep, got %q", ev.Comm)
	}
}

func TestParseExitEvent_ThreadExit(t *testing.T) {
	ev, err := parseExitEvent(buildExitRecord(200, 205, 1, 0, "node"))
	if err != nil {
		t.Fatal(err)
	}
	if ev.PID != 200 || ev.TID != 205 {
		t.Errorf("got pid=%d tid=%d, want 200/205", ev.PID, ev.TID)
	}
	if ev.IsProcessExit() {
		t.Error("tid != pid is a thread exit, not a process exit")
	}
}

func TestParseExitEvent_TooShort(t *testing.T) {
	_, err := parseExitEvent([]byte{0, 1, 2})
	if err == nil {
		t.Error("expected error for short buffer")
	}
}

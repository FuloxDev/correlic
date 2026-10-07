//go:build linux

package ebpf

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestParseExitEvent(t *testing.T) {
	// Layout: pid(4) + ppid(4) + exit_code(4) + timestamp_ns(8) + comm(16) = 36 bytes
	base := time.Unix(0, 1706702400000000000) // boot-time placeholder; parser uses wall-clock time
	data := make([]byte, exitEventSize)
	binary.LittleEndian.PutUint32(data[0:4], 100)
	binary.LittleEndian.PutUint32(data[4:8], 1)
	binary.LittleEndian.PutUint32(data[8:12], 0)
	binary.LittleEndian.PutUint64(data[12:20], uint64(base.UnixNano()))
	copy(data[20:36], []byte("sleep\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))

	ev, err := parseExitEvent(data)
	if err != nil {
		t.Fatal(err)
	}
	if ev.PID != 100 || ev.PPID != 1 || ev.ExitCode != 0 {
		t.Errorf("pid=100 ppid=1 exit_code=0, got pid=%d ppid=%d exit_code=%d", ev.PID, ev.PPID, ev.ExitCode)
	}
	if ev.Timestamp.Before(time.Now().Add(-5*time.Second)) || ev.Timestamp.After(time.Now().Add(5*time.Second)) {
		t.Errorf("timestamp should be near wall-clock now, got %v", ev.Timestamp)
	}
	if ev.Comm != "sleep" {
		t.Errorf("comm: want sleep, got %q", ev.Comm)
	}
}

func TestParseExitEvent_TooShort(t *testing.T) {
	_, err := parseExitEvent([]byte{0, 1, 2})
	if err == nil {
		t.Error("expected error for short buffer")
	}
}

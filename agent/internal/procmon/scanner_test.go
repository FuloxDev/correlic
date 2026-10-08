//go:build linux

package procmon

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseLinuxStat_StartTime(t *testing.T) {
	t.Parallel()

	// starttime is field 22. After state (field 3), we provide 19 tokens and place starttime as the 19th.
	line := "1234 (bash) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 21 22"
	comm, start, err := parseLinuxStat(line)
	if err != nil {
		t.Fatalf("parseLinuxStat error: %v", err)
	}
	if comm != "bash" {
		t.Fatalf("comm=%q want %q", comm, "bash")
	}
	if start != 424242 {
		t.Fatalf("start=%d want %d", start, 424242)
	}
}

func TestScanner_SnapshotAndReadProcess_FakeProcfs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("procfs test not supported on windows")
	}

	root := t.TempDir()
	pidDir := filepath.Join(root, "123")
	if err := os.Mkdir(pidDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Minimal /proc/<pid>/stat with comm + starttime token.
	stat := "123 (myproc) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 21 22"
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatalf("write stat: %v", err)
	}
	// status with PPid + Uid
	status := "Name:\tmyproc\nPPid:\t42\nUid:\t1000\t1000\t1000\t1000\n"
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatalf("write status: %v", err)
	}
	// cmdline with null separated args
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("a\x00b\x00c\x00"), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	// exe symlink
	_ = os.Symlink("/bin/myproc", filepath.Join(pidDir, "exe"))

	s := NewScanner(root)
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, ok := snap[123]; !ok {
		t.Fatalf("expected pid 123 in snapshot")
	}

	info, err := s.ReadProcess(123)
	if err != nil {
		t.Fatalf("ReadProcess: %v", err)
	}
	if info.PPID != 42 || info.UID != 1000 {
		t.Fatalf("unexpected ppid/uid: %+v", info)
	}
	if info.Comm != "myproc" {
		t.Fatalf("comm=%q", info.Comm)
	}
	if info.Argv0 != "a" || len(info.Argv) != 3 {
		t.Fatalf("argv=%v argv0=%q", info.Argv, info.Argv0)
	}
	if info.StartTimeTicks != 777 {
		t.Fatalf("start=%d want %d", info.StartTimeTicks, 777)
	}
}

//go:build !windows

package enforcer

import (
	"fmt"
	"runtime"
	"syscall"
)

// KillProcess terminates a process by PID using SIGKILL on Unix.
func KillProcess(pid uint32) (bool, error) {
	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
		return false, fmt.Errorf("kill(%d, SIGKILL): %w", pid, err)
	}
	return true, nil
}

// KillProcessTree terminates a process and its children on Unix.
// Uses negative PID to kill the process group.
func KillProcessTree(pid uint32) (bool, error) {
	// Try process group kill first
	if err := syscall.Kill(-int(pid), syscall.SIGKILL); err != nil {
		// Fallback to single process kill
		return KillProcess(pid)
	}
	return true, nil
}

func init() {
	_ = runtime.GOOS // prevent unused import
	_ = fmt.Sprintf  // prevent unused import
}

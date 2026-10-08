//go:build !windows

package enforcer

import (
	"fmt"
	"syscall"
)

// KillProcess terminates exactly one process by PID using SIGKILL. It never
// signals the process group: the target may share its group with the shell
// or service manager that launched it.
func KillProcess(pid uint32) (bool, error) {
	if pid <= 1 {
		return false, fmt.Errorf("refusing to kill pid %d", pid)
	}
	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
		return false, fmt.Errorf("kill(%d, SIGKILL): %w", pid, err)
	}
	return true, nil
}

// KillProcessTree terminates a process and all of its descendants (deepest
// first). Descendants are discovered by parent id (see descendantsOf), never
// by process group, so unrelated processes in the same group are untouched.
// skip, when non-nil, protects individual descendants (e.g. the agent itself).
// Only used when a rule explicitly sets kill_tree.
func KillProcessTree(pid uint32, skip func(uint32) bool) (bool, error) {
	for _, child := range descendantsOf(pid) {
		if skip != nil && skip(child) {
			continue
		}
		_ = syscall.Kill(int(child), syscall.SIGKILL) // best-effort for children
	}
	return KillProcess(pid)
}

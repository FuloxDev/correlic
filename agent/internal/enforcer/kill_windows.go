//go:build windows

package enforcer

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// KillProcess terminates a single process by PID using TerminateProcess.
func KillProcess(pid uint32) (bool, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return false, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	if err := windows.TerminateProcess(handle, 1); err != nil {
		return false, fmt.Errorf("TerminateProcess(%d): %w", pid, err)
	}
	return true, nil
}

// KillProcessTree terminates a process and all its descendants (bottom-up).
// skip, when non-nil, protects individual descendants (e.g. the agent itself).
func KillProcessTree(pid uint32, skip func(uint32) bool) (bool, error) {
	for _, child := range descendantsOf(pid) {
		if skip != nil && skip(child) {
			continue
		}
		KillProcess(child) // best-effort for children
	}
	return KillProcess(pid)
}

// descendantsOf returns every descendant of pid from a toolhelp snapshot,
// ordered deepest first.
func descendantsOf(pid uint32) []uint32 {
	children := snapshotChildren()
	var out []uint32
	var walk func(p uint32)
	walk = func(p uint32) {
		for _, c := range children[p] {
			if c == p {
				continue
			}
			walk(c)
			out = append(out, c)
		}
	}
	walk(pid)
	return out
}

// snapshotChildren builds ppid → children from a process snapshot.
func snapshotChildren() map[uint32][]uint32 {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	children := make(map[uint32][]uint32)
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil
	}
	for {
		if entry.ProcessID != entry.ParentProcessID {
			children[entry.ParentProcessID] = append(children[entry.ParentProcessID], entry.ProcessID)
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return children
}

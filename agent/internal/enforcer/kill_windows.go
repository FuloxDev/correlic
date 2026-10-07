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

// KillProcessTree terminates a process and all its children (bottom-up).
func KillProcessTree(pid uint32) (bool, error) {
	children := findChildPIDs(pid)
	// Kill children first (bottom-up)
	for _, child := range children {
		KillProcess(child) // best-effort for children
	}
	return KillProcess(pid)
}

// findChildPIDs returns all immediate child PIDs of a process.
func findChildPIDs(pid uint32) []uint32 {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var children []uint32
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil
	}
	for {
		if entry.ParentProcessID == pid && entry.ProcessID != pid {
			children = append(children, entry.ProcessID)
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return children
}

//go:build darwin

package procinfo

import (
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// DetectContainerID returns "" on macOS.
// Docker Desktop runs containers inside a Linux VM; the macOS host has no cgroups.
func DetectContainerID(pid uint32) string {
	return ""
}

// DetectSessionID returns the session ID for a process using getsid(2).
func DetectSessionID(pid uint32) uint32 {
	sid, err := syscall.Getsid(int(pid))
	if err != nil {
		return 0
	}
	return uint32(sid)
}

// LookupPPID returns the parent PID of a process using ps(1).
// Returns 0 if the process doesn't exist or the lookup fails.
func LookupPPID(pid uint32) uint32 {
	out, err := exec.Command("ps", "-p", strconv.FormatUint(uint64(pid), 10), "-o", "ppid=").Output()
	if err != nil {
		return 0
	}
	line := strings.TrimSpace(string(out))
	ppid, err := strconv.ParseUint(line, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(ppid)
}

// LookupChildPIDs returns the immediate child PIDs of a process using pgrep(1).
// Returns nil if the process has no children or the lookup fails.
func LookupChildPIDs(pid uint32) []uint32 {
	out, err := exec.Command("pgrep", "-P", strconv.FormatUint(uint64(pid), 10)).Output()
	if err != nil {
		return nil
	}
	var children []uint32
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		childPID, err := strconv.ParseUint(line, 10, 32)
		if err != nil {
			continue
		}
		children = append(children, uint32(childPID))
	}
	return children
}

// ReadProcCmdline reads the command line of a process using ps(1).
// macOS has no /proc filesystem; we use `ps -p <pid> -o args=` instead.
func ReadProcCmdline(pid uint32) []string {
	out, err := exec.Command("ps", "-p", strconv.FormatUint(uint64(pid), 10), "-o", "args=").Output()
	if err != nil {
		return nil
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return nil
	}
	return strings.Fields(line)
}

//go:build linux

package enforcer

import (
	"os"
	"strconv"
	"strings"
)

// descendantsOf returns every descendant of pid from /proc, ordered deepest
// first so callers can kill bottom-up. It never returns pid itself.
func descendantsOf(pid uint32) []uint32 {
	children := procChildrenMap()
	var out []uint32
	var walk func(p uint32)
	walk = func(p uint32) {
		for _, c := range children[p] {
			walk(c)
			out = append(out, c)
		}
	}
	walk(pid)
	return out
}

// procChildrenMap builds ppid → children from /proc/<pid>/stat.
func procChildrenMap() map[uint32][]uint32 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	children := make(map[uint32][]uint32)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		ppid, ok := readPPID(e.Name())
		if !ok {
			continue
		}
		children[ppid] = append(children[ppid], uint32(pid))
	}
	return children
}

// readPPID parses the ppid field of /proc/<pid>/stat.
func readPPID(pidStr string) (uint32, bool) {
	data, err := os.ReadFile("/proc/" + pidStr + "/stat")
	if err != nil {
		return 0, false
	}
	content := string(data)
	// comm is wrapped in parentheses and may contain spaces; fields start
	// after the last ')'.
	i := strings.LastIndex(content, ")")
	if i < 0 {
		return 0, false
	}
	fields := strings.Fields(content[i+1:])
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(ppid), true
}

//go:build linux

package scanner

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/ebpf"
)

// ProcScanner scans /proc for existing AI processes.
type ProcScanner struct {
	logger         *slog.Logger
	tracker        *ebpf.LineageTracker
	dockerResolver *ebpf.DockerResolver // nil-safe — nil on non-Docker hosts
}

// NewProcScanner creates a new ProcScanner.
// dockerResolver is optional (nil-safe) — pass nil on non-Docker hosts.
func NewProcScanner(logger *slog.Logger, dockerResolver *ebpf.DockerResolver) *ProcScanner {
	return &ProcScanner{
		logger:         logger,
		tracker:        ebpf.GetLineageTracker(),
		dockerResolver: dockerResolver,
	}
}

func (s *ProcScanner) Scan(emit func(eventType string, payload any) bool) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("failed to read /proc: %w", err)
	}

	// Track visited ancestors to avoid duplicate emissions per scan
	visitedAncestors := make(map[int]bool)

	type procInfo struct {
		pid       int
		ppid      int
		comm      string
		cmdline   string
		exePath   string
		startTime time.Time
		isAI      bool
	}

	procs := make(map[int]procInfo)
	children := make(map[int][]int)
	var aiRoots []int

	// Pass 1: Gather all processes and identify AI roots directly matching patterns
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue // Not a PID directory
		}

		comm, err := readFile(filepath.Join("/proc", pidStr, "comm"))
		if err != nil {
			continue // Process might have exited
		}
		comm = strings.TrimSpace(comm)

		cmdline, err := readFile(filepath.Join("/proc", pidStr, "cmdline"))
		if err == nil {
			cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
		}

		ppid, startTime, err := getProcessStat(pidStr)
		if err != nil {
			continue
		}

		exePath, _ := os.Readlink(filepath.Join("/proc", pidStr, "exe"))

		// Check if it's a direct AI pattern match (comm, cmdline, or container name/image)
		isAI := s.tracker.CheckPattern(comm) || s.tracker.CheckPattern(cmdline)

		// If comm/cmdline didn't match, check Docker container name/image
		if !isAI {
			containerID := ebpf.DetectContainerID(uint32(pid))
			if containerID != "" && s.dockerResolver != nil {
				isAI = s.dockerResolver.CheckContainerPatterns(containerID, s.tracker)
			}
		}

		p := procInfo{
			pid:       pid,
			ppid:      ppid,
			comm:      comm,
			cmdline:   cmdline,
			exePath:   exePath,
			startTime: startTime,
			isAI:      isAI,
		}
		procs[pid] = p
		children[ppid] = append(children[ppid], pid)

		if isAI {
			aiRoots = append(aiRoots, pid)
		}
	}

	// Pass 2: BFS from AI roots to mark all descendants
	queue := append([]int{}, aiRoots...)
	seen := make(map[int]bool)

	count := 0
	for len(queue) > 0 {
		curPID := queue[0]
		queue = queue[1:]

		if seen[curPID] {
			continue
		}
		seen[curPID] = true

		p, exists := procs[curPID]
		if !exists {
			continue
		}

		// Register with tracker
		if s.tracker.RegisterProcess(uint32(p.pid), uint32(p.ppid), p.comm) {
			count++
			if p.isAI {
				s.logger.Info("found existing AI root", "pid", p.pid, "comm", p.comm)
			} else {
				s.logger.Debug("found existing AI descendant", "pid", p.pid, "comm", p.comm)
			}

			// Emit synthetic process_exec event
			payload := map[string]any{
				"pid":        p.pid,
				"ppid":       p.ppid,
				"comm":       p.comm,
				"exe":        p.exePath,
				"cmdline":    strings.Split(p.cmdline, " "),
				"start_time": p.startTime.Format(time.RFC3339Nano),
				"trace_role": "existing_process",
				"role":       ebpf.CheckRole(p.comm),
				"source":     "proc_scanner",
			}
			emit("process_exec", payload)

			// Harvest ancestors for roots to bridge gaps
			if p.isAI {
				s.harvestAncestors(p.ppid, emit, visitedAncestors)
			}
		}

		// Enqueue children to mark them as AI descendants too
		for _, childPID := range children[curPID] {
			queue = append(queue, childPID)
		}
	}

	s.logger.Info("proc scan complete", "ai_processes_and_descendants_found", count)
	return nil
}

// harvestAncestors walks up the process tree and emits events for ancestors
// to ensure the graph is fully connected. limits depth to avoid scanning full system.
func (s *ProcScanner) harvestAncestors(pid int, emit func(eventType string, payload any) bool, visited map[int]bool) {
	currentPID := pid
	depth := 0
	maxDepth := 10 // Reasonable limit to find session leader/init

	for depth < maxDepth {
		// Get parent info
		ppid, _, err := getProcessStat(strconv.Itoa(currentPID))
		if err != nil {
			break // Parent dead/process gone
		}

		if ppid <= 1 {
			break // Stop at init
		}

		// Avoid duplicates locally in this scan
		// Initialize map if nil (though caller should provide it)
		if visited != nil {
			if visited[ppid] {
				break
			}
			visited[ppid] = true
		}

		// Read parent details
		ppidStr := strconv.Itoa(ppid)
		comm, err := readFile(filepath.Join("/proc", ppidStr, "comm"))
		if err != nil {
			break
		}
		comm = strings.TrimSpace(comm)

		cmdline, err := readFile(filepath.Join("/proc", ppidStr, "cmdline"))
		if err == nil {
			cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
		}

		exePath, _ := os.Readlink(filepath.Join("/proc", ppidStr, "exe"))
		_, startTime, _ := getProcessStat(ppidStr)

		// Emit parent event
		payload := map[string]any{
			"pid": ppid,
			// Grandparent is needed for next iteration's link, but we'll get it in next loop
			// For this specific event, we need the grandparent ID.
			// Let's get grandparent now.
			"ppid":       0, // Will be filled in next block or if we continue
			"comm":       comm,
			"exe":        exePath,
			"cmdline":    strings.Split(cmdline, " "),
			"start_time": startTime.Format(time.RFC3339Nano),
			"trace_role": "inferred_ancestor",
			"role":       ebpf.CheckRole(comm),
			"source":     "proc_scanner",
		}

		// Get grandparent for ppid field
		gppid, _, err := getProcessStat(ppidStr)
		if err == nil {
			payload["ppid"] = gppid
		}

		// Filter out system/desktop infrastructure processes to keep the tree focused on the AI application.
		// This makes the actual AI process appear as a root, which is more meaningful to the user.
		if isInfrastructureProcess(comm) {
			s.logger.Debug("skipping infrastructure process emission", "comm", comm, "pid", ppid)
			// We still traverse up to mark as visited, but we don't emit this node.
			// This breaks the link, making the child a root.
		} else {
			emit("process_exec", payload)
		}

		s.logger.Debug("harvested ancestor", "pid", ppid, "child_pid", currentPID, "comm", comm)

		// Move up
		currentPID = ppid
		depth++
	}
}

func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// getProcessStat reads /proc/<pid>/stat to get PPID and StartTime.
// Returns ppid, startTime, error.
func getProcessStat(pidStr string) (int, time.Time, error) {
	data, err := os.ReadFile(filepath.Join("/proc", pidStr, "stat"))
	if err != nil {
		return 0, time.Time{}, err
	}

	// Format is: pid (comm) state ppid ... starttime ...
	// Comm can contain spaces and parentheses, so we need to be careful.
	// We locate the last ')' to find the end of comm.
	content := string(data)
	lastParen := strings.LastIndex(content, ")")
	if lastParen == -1 || lastParen+2 >= len(content) {
		return 0, time.Time{}, fmt.Errorf("invalid stat format")
	}

	parts := strings.Fields(content[lastParen+2:])
	if len(parts) < 20 { // PPID is 0th (actually 3rd field overall), starttime is 19th (22nd overall) but fields are shifting
		// The fields after comm are:
		// 0: state
		// 1: ppid
		// ...
		// 19: starttime (clock ticks since boot)
		return 0, time.Time{}, fmt.Errorf("stat too short")
	}

	ppid, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("invalid ppid")
	}

	// Calculate start time
	// This requires system boot time and clock ticks.
	// Simplified: just return current time for "discovery" time or try to calculate.
	// For accurate "start_time", we need /proc/stat btime.
	// Let's rely on backend or just use time.Now() - uptime + starttime_ticks/hz.
	// For MVP, using time.Now() is acceptable as "detection time", OR we try to read uptime.
	// Better: use the file modification time of /proc/<pid> as a proxy?
	// /proc/<pid> dir mod time is usually start time.

	fi, err := os.Stat(filepath.Join("/proc", pidStr))
	if err == nil {
		return ppid, fi.ModTime(), nil
	}

	return ppid, time.Now(), nil
}

// isInfrastructureProcess checks if a process should be hidden from the graph root.
// These are typically desktop environment wrappers or system managers.
func isInfrastructureProcess(comm string) bool {
	// List of processes that should NOT be roots because they are just infrastructure/wrappers.
	// If scan hits these, we stop emitting events, making the child the new root.
	ignored := []string{
		// "containerd-shim", // Removed to allow Docker linkage.
		// We need shim to link containers to the system, otherwise containers appear as roots.
		"lightdm",
		"gdm",
		"sddm", // Display managers
		"xfce4-session",
		"xfce4-panel",
		"gnome-session",
		"plasma-session", // Desktop sessions
		"wrapper-2.0",    // Generic wrappers (e.g. xfce panel plugins)
		"systemd",        // System manager (though usually PID 1 stop handles it, sometimes user sessions run systemd)
		"init",
		"dbus-daemon", // Message bus
	}

	for _, name := range ignored {
		if strings.Contains(comm, name) {
			return true
		}
	}
	return false
}

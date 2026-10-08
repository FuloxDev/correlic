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

type procInfo struct {
	pid       int
	ppid      int
	comm      string
	argv      []string
	exePath   string
	startTime time.Time
	isAI      bool   // direct pattern/container match (AI root candidate)
	aiType    string // matched pattern for roots
	container bool   // matched via container name/image rather than argv
}

// Scan walks /proc once, registers already-running AI process trees with the
// lineage tracker and emits synthetic process_exec events for them. Emitted
// payloads carry ai_session_id, is_ai and ai_type so the canonical events
// built from them are attributed like live exec events.
func (s *ProcScanner) Scan(emit func(eventType string, payload any) bool) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("failed to read /proc: %w", err)
	}

	// Track visited ancestors to avoid duplicate emissions per scan
	visitedAncestors := make(map[int]bool)

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

		argv := readArgv(pidStr)

		ppid, startTime, err := getProcessStat(pidStr)
		if err != nil {
			continue
		}

		exePath, _ := os.Readlink(filepath.Join("/proc", pidStr, "exe"))

		// Direct AI match: comm, exe or an argv token (whole-token semantics).
		p := procInfo{
			pid:       pid,
			ppid:      ppid,
			comm:      comm,
			argv:      argv,
			exePath:   exePath,
			startTime: startTime,
		}
		if aiType, ok := s.tracker.MatchCommand(exePath, append([]string{comm}, argv...)); ok {
			p.isAI, p.aiType = true, aiType
		} else if s.dockerResolver != nil {
			// If comm/cmdline didn't match, check Docker container name/image
			if containerID := ebpf.DetectContainerID(uint32(pid)); containerID != "" {
				if aiType, ok := s.dockerResolver.MatchContainerPatterns(containerID, s.tracker); ok {
					p.isAI, p.aiType, p.container = true, aiType, true
				}
			}
		}
		procs[pid] = p
		children[ppid] = append(children[ppid], pid)

		if p.isAI {
			aiRoots = append(aiRoots, pid)
		}
	}

	// Pass 2: BFS from AI roots to mark all descendants. Roots are registered
	// before their children, so a child that also matches a pattern inherits
	// the root's session instead of opening its own.
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
		if s.register(p) {
			count++
			if p.isAI {
				s.logger.Info("found existing AI root", "pid", p.pid, "comm", p.comm, "ai_type", s.tracker.GetAIType(uint32(p.pid)))
			} else {
				s.logger.Debug("found existing AI descendant", "pid", p.pid, "comm", p.comm)
			}

			// Emit synthetic process_exec event with the AI attribution the
			// tracker assigned (session + type).
			payload := map[string]any{
				"pid":        p.pid,
				"ppid":       p.ppid,
				"comm":       p.comm,
				"exe":        p.exePath,
				"cmdline":    argvOrComm(p.argv, p.comm),
				"start_time": p.startTime.Format(time.RFC3339Nano),
				"trace_role": "existing_process",
				"role":       ebpf.CheckRole(p.comm),
				"source":     "proc_scanner",
			}
			s.tracker.Annotate(payload, uint32(p.pid))
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

// register adds p to the lineage tracker. Container-matched roots have no
// matching token, so they are marked explicitly with the container's ai_type.
func (s *ProcScanner) register(p procInfo) bool {
	pid, ppid := uint32(p.pid), uint32(p.ppid)
	if s.tracker.RegisterProcessWithCommand(pid, ppid, p.comm, p.exePath, p.argv) {
		return true
	}
	if p.isAI && p.container {
		s.tracker.MarkAIWithType(pid, ppid, p.aiType)
		return true
	}
	return false
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

		exePath, _ := os.Readlink(filepath.Join("/proc", ppidStr, "exe"))
		gppid, startTime, _ := getProcessStat(ppidStr)

		// Emit parent event (ancestors are context only: they are not part of
		// the AI session, so no AI attribution is added).
		payload := map[string]any{
			"pid":        ppid,
			"ppid":       gppid,
			"comm":       comm,
			"exe":        exePath,
			"cmdline":    argvOrComm(readArgv(ppidStr), comm),
			"start_time": startTime.Format(time.RFC3339Nano),
			"trace_role": "inferred_ancestor",
			"role":       ebpf.CheckRole(comm),
			"source":     "proc_scanner",
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

// readArgv returns /proc/<pid>/cmdline split on NUL (nil when unreadable or empty).
func readArgv(pidStr string) []string {
	data, err := os.ReadFile(filepath.Join("/proc", pidStr, "cmdline"))
	if err != nil {
		return nil
	}
	raw := strings.TrimRight(string(data), "\x00")
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\x00")
}

func argvOrComm(argv []string, comm string) []string {
	if len(argv) > 0 {
		return argv
	}
	return []string{comm}
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
	if len(parts) < 20 {
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

	// /proc/<pid> dir mod time is a good proxy for the start time without
	// needing btime + clock tick arithmetic.
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

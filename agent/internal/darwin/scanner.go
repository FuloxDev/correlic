//go:build darwin

package darwin

import (
	"bufio"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/classify"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/procinfo"
)

// ProcScanner scans running processes on macOS for existing AI processes.
// Equivalent of internal/scanner/proc.go on Linux, but uses ps(1) instead of /proc.
type ProcScanner struct {
	logger  *slog.Logger
	tracker *lineage.LineageTracker
}

// NewProcScanner creates a new macOS process scanner.
func NewProcScanner(logger *slog.Logger) *ProcScanner {
	return &ProcScanner{
		logger:  logger,
		tracker: lineage.GetLineageTracker(),
	}
}

type darwinProcInfo struct {
	pid     int
	ppid    int
	comm    string // short name
	args    string // full command line
	exePath string
}

// Scan enumerates all running processes, finds AI roots and their descendants,
// and emits synthetic process_exec events for each.
func (s *ProcScanner) Scan(emit func(eventType string, payload any) bool) error {
	_, err := s.scanInternal(emit)
	return err
}

// scanInternal performs the BFS scan and returns the process map for reuse by RegisterAndWatch.
func (s *ProcScanner) scanInternal(emit func(eventType string, payload any) bool) (map[int]darwinProcInfo, error) {
	procs, err := s.listProcesses()
	if err != nil {
		return nil, err
	}

	children := make(map[int][]int)
	var aiRoots []int

	for _, p := range procs {
		children[p.ppid] = append(children[p.ppid], p.pid)

		isAI := s.tracker.CheckPattern(p.comm) || s.tracker.CheckPattern(p.args)
		if isAI {
			aiRoots = append(aiRoots, p.pid)
		}
	}

	// BFS from AI roots to mark all descendants.
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

		if s.tracker.RegisterProcess(uint32(p.pid), uint32(p.ppid), p.comm) {
			count++
			if s.tracker.CheckPattern(p.comm) || s.tracker.CheckPattern(p.args) {
				s.logger.Info("found existing AI root", "pid", p.pid, "comm", p.comm)
			} else {
				s.logger.Debug("found existing AI descendant", "pid", p.pid, "comm", p.comm)
			}

			payload := map[string]any{
				"pid":        p.pid,
				"ppid":       p.ppid,
				"comm":       p.comm,
				"exe":        p.exePath,
				"cmdline":    strings.Fields(p.args),
				"start_time": time.Now().Format(time.RFC3339Nano),
				"trace_role": "existing_process",
				"role":       classify.CheckRole(p.comm),
				"source":     "proc_scanner",
			}
			s.tracker.Annotate(payload, uint32(p.pid))
			emit("process_exec", payload)
		}

		for _, childPID := range children[curPID] {
			queue = append(queue, childPID)
		}
	}

	s.logger.Info("proc scan complete", "ai_processes_found", count)
	return procs, nil
}

// RegisterAndWatch finds AI processes and registers them with the given ProcCollector
// for kqueue monitoring. Reuses the process list from Scan to avoid a redundant ps(1) call.
func (s *ProcScanner) RegisterAndWatch(emit func(eventType string, payload any) bool, collector *ProcCollector) error {
	procs, err := s.scanInternal(emit)
	if err != nil {
		return err
	}

	// Watch all AI PIDs discovered by the scan in kqueue.
	watched := 0
	for _, p := range procs {
		if s.tracker.IsAI(uint32(p.pid)) {
			if err := collector.WatchPID(p.pid); err != nil {
				s.logger.Debug("failed to watch PID", "pid", p.pid, "error", err)
			} else {
				watched++
			}
		}
	}
	s.logger.Info("kqueue watching AI PIDs", "count", watched)

	return nil
}

// listProcesses enumerates all running processes using ps(1).
func (s *ProcScanner) listProcesses() (map[int]darwinProcInfo, error) {
	// ps -eo pid,ppid,comm,args — all processes with PID, PPID, short name, full args
	out, err := exec.Command("ps", "-eo", "pid,ppid,comm,args").Output()
	if err != nil {
		return nil, fmt.Errorf("ps failed: %w", err)
	}

	procs := make(map[int]darwinProcInfo)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))

	// Skip header
	if scanner.Scan() {
		// consume header
	}

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		// Fields: PID PPID COMM ARGS...
		// COMM is the short name, ARGS is the full command line.
		// ps right-justifies PID/PPID, so trim.
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		comm := fields[2]
		// Extract just the binary name from comm (may be full path on some macOS versions).
		if idx := strings.LastIndex(comm, "/"); idx >= 0 {
			comm = comm[idx+1:]
		}

		args := strings.Join(fields[3:], " ")

		// Get full exe path if possible.
		exePath := ""
		cmdline := procinfo.ReadProcCmdline(uint32(pid))
		if len(cmdline) > 0 {
			exePath = cmdline[0]
		}

		procs[pid] = darwinProcInfo{
			pid:     pid,
			ppid:    ppid,
			comm:    comm,
			args:    args,
			exePath: exePath,
		}
	}

	return procs, nil
}

//go:build windows

package windows

import (
	"log/slog"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/correlic/correlic-agent/internal/classify"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/lineage"
)

// ProcScanner scans the running process table at startup and finds existing AI processes.
// Equivalent of internal/darwin/scanner.go on macOS and internal/scanner/proc.go on Linux.
type ProcScanner struct {
	logger     *slog.Logger
	tracker    *lineage.LineageTracker
	dispatcher dispatch.Dispatcher
	hostID     string
}

// NewProcScanner creates a Windows process scanner.
func NewProcScanner(logger *slog.Logger, disp dispatch.Dispatcher, hostID string) *ProcScanner {
	if logger == nil {
		logger = slog.Default()
	}
	return &ProcScanner{
		logger:     logger,
		tracker:    lineage.GetLineageTracker(),
		dispatcher: disp,
		hostID:     hostID,
	}
}

type winProcInfo struct {
	pid     uint32
	ppid    uint32
	comm    string
	exePath string
}

// Scan enumerates all running processes, finds AI roots and their descendants,
// and emits synthetic process_exec events for each.
func (s *ProcScanner) Scan(emit func(eventType string, payload any) bool) error {
	procs, err := s.listProcesses()
	if err != nil {
		return err
	}

	children := make(map[uint32][]uint32)
	var aiRoots []uint32

	for _, p := range procs {
		children[p.ppid] = append(children[p.ppid], p.pid)
		if s.tracker.CheckPattern(p.comm) || s.tracker.CheckPattern(p.exePath) {
			aiRoots = append(aiRoots, p.pid)
		}
	}

	// BFS from AI roots to mark all descendants.
	queue := append([]uint32{}, aiRoots...)
	seen := make(map[uint32]bool)
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

		if s.tracker.RegisterProcess(p.pid, p.ppid, p.comm) {
			count++
			if s.tracker.CheckPattern(p.comm) {
				s.logger.Info("found existing AI root", "pid", p.pid, "comm", p.comm)
			} else {
				s.logger.Debug("found existing AI descendant", "pid", p.pid, "comm", p.comm)
			}

			role := classify.CheckRole(p.comm)
			payload := map[string]any{
				"pid":        int(p.pid),
				"ppid":       int(p.ppid),
				"comm":       p.comm,
				"exe":        p.exePath,
				"cmdline":    []string{p.exePath},
				"start_time": time.Now().Format(time.RFC3339Nano),
				"trace_role": "existing_process",
				"role":       role,
			}
			emit("process_exec", payload)

			// Also dispatch as canonical event so it reaches the backend.
			if s.dispatcher != nil {
				ts := time.Now()
				evt := event.Event{
					SchemaVersion: 1,
					HostID:        s.hostID,
					Timestamp:     ts,
					Source:        "proc_scanner",
					Type:          "process_exec",
					Actor: &event.Actor{
						PID:     int(p.pid),
						PPID:    int(p.ppid),
						Comm:    p.comm,
						ExePath: p.exePath,
						Cmdline: []string{p.exePath},
						Role:    role,
					},
					Context: map[string]any{
						"trace_role": "existing_process",
					},
				}
				if aiSess := s.tracker.GetSessionID(p.pid); aiSess != "" {
					evt.Context["ai_session_id"] = aiSess
				}
				evt.ID = event.GenerateID(s.hostID, ts.UnixNano(), evt.Source, evt.Type, int(p.pid), p.exePath)
				s.dispatcher.Enqueue(evt)
			}
		}

		for _, childPID := range children[curPID] {
			queue = append(queue, childPID)
		}
	}

	s.logger.Info("proc scan complete", "ai_processes_found", count)
	return nil
}

// listProcesses enumerates all running processes using CreateToolhelp32Snapshot.
func (s *ProcScanner) listProcesses() (map[uint32]winProcInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	procs := make(map[uint32]winProcInfo)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, err
	}
	for {
		exeName := windows.UTF16ToString(entry.ExeFile[:])
		comm := strings.TrimSuffix(strings.ToLower(exeName), ".exe")
		exePath := resolveExePath(entry.ProcessID)

		procs[entry.ProcessID] = winProcInfo{
			pid:     entry.ProcessID,
			ppid:    entry.ParentProcessID,
			comm:    comm,
			exePath: exePath,
		}

		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return procs, nil
}

// resolveExePath queries the full exe path for a PID.
func resolveExePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return normalisePath(windows.UTF16ToString(buf[:size]))
}

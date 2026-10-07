//go:build linux

package procmon

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procKey identifies a process instance so PID reuse doesn't look like "no change".
// We use Linux starttime ticks from /proc/<pid>/stat.
type procKey int64

type ProcInfo struct {
	PID            int
	PPID           int
	UID            int
	Exe            string
	Comm           string
	Argv0          string
	Argv           []string
	Truncated      bool
	StartTimeTicks int64
}

// Scanner is the scanner for the procmon runner.
type Scanner struct {
	procRoot string
}

// NewScanner creates a new Scanner with the given proc root.
func NewScanner(procRoot string) *Scanner {
	return &Scanner{procRoot: procRoot}
}

// Snapshot returns PID->procKey for all numeric /proc entries.
func (s *Scanner) Snapshot() (map[int]procKey, error) {
	entries, err := os.ReadDir(s.procRoot)
	if err != nil {
		return nil, err
	}
	// create a new map for the current processes.
	out := make(map[int]procKey, 1024)
	// loop through the entries.
	for _, e := range entries {
		// if the entry is not a directory, skip it.
		if !e.IsDir() {
			continue
		}
		// convert the entry name to an integer.
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		// read the start time ticks.
		start, err := s.readStartTimeTicks(pid)
		if err != nil {
			continue
		}
		// add the process to the map.
		out[pid] = procKey(start)
	}
	return out, nil
}

// ReadProcess reads the process information for the given PID.
func (s *Scanner) ReadProcess(pid int) (ProcInfo, error) {
	// read the process status.
	ppid, uid, err := s.readStatus(pid)
	if err != nil {
		return ProcInfo{}, err
	}

	// read the process executable.
	exe, _ := os.Readlink(filepath.Join(s.procRoot, strconv.Itoa(pid), "exe"))
	// read the process command and start time.
	comm, start, _ := s.readCommAndStart(pid)

	// read the process command line.
	argv, trunc := s.readCmdline(pid, 20, 256)
	// get the process command line argument 0.
	argv0 := ""
	if len(argv) > 0 {
		argv0 = argv[0]
	}

	// return the process information.
	return ProcInfo{
		PID:            pid,
		PPID:           ppid,
		UID:            uid,
		Exe:            exe,
		Comm:           comm,
		Argv0:          argv0,
		Argv:           argv,
		Truncated:      trunc,
		StartTimeTicks: start,
	}, nil
}

// readStatus reads the process status for the given PID.
func (s *Scanner) readStatus(pid int) (ppid int, uid int, err error) {
	// read the process status file.
	b, err := os.ReadFile(filepath.Join(s.procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, 0, err
	}
	ppid = -1
	uid = -1

	// loop through the lines.
	for _, line := range strings.Split(string(b), "\n") {
		// if the line has the prefix "PPid:", get the process parent ID.
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ppid, _ = strconv.Atoi(fields[1])
			}
		}
		// if the line has the prefix "Uid:", get the process user ID.
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, _ = strconv.Atoi(fields[1]) // real uid
			}
		}
	}
	if ppid < 0 || uid < 0 {
		return 0, 0, fmt.Errorf("missing fields")
	}
	return ppid, uid, nil
}

// readCmdline reads the process command line for the given PID.
func (s *Scanner) readCmdline(pid int, maxArgs int, maxBytes int) ([]string, bool) {
	// read the process command line file.
	b, err := os.ReadFile(filepath.Join(s.procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil || len(b) == 0 {
		return nil, false
	}
	// check if the command line is truncated.
	trunc := false
	// if the command line is longer than the max bytes, truncate it.
	if maxBytes > 0 && len(b) > maxBytes {
		b = b[:maxBytes]
		trunc = true
	}

	// split the command line into parts.
	parts := bytes.Split(b, []byte{0})
	// loop through the parts.
	var argv []string
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		// add the part to the command line arguments.
		argv = append(argv, string(p))
		// if the number of arguments is greater than the max arguments, truncate it.
		if maxArgs > 0 && len(argv) >= maxArgs {
			trunc = true
			break
		}
	}
	return argv, trunc
}

// readStartTimeTicks reads the process start time ticks for the given PID.
func (s *Scanner) readStartTimeTicks(pid int) (int64, error) {
	// read the process command and start time.
	_, start, err := s.readCommAndStart(pid)
	// return the start time ticks.
	return start, err
}

// readCommAndStart reads the process command and start time for the given PID.
func (s *Scanner) readCommAndStart(pid int) (comm string, start int64, err error) {
	// read the process stat file.
	b, err := os.ReadFile(filepath.Join(s.procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", 0, err
	}
	comm, start, err = parseLinuxStat(string(b))
	return comm, start, err
}

// parseLinuxStat parses /proc/<pid>/stat and returns (comm, starttime_ticks).
func parseLinuxStat(statLine string) (string, int64, error) {
	// Format: pid (comm) state ppid ... starttime ...
	// comm may contain spaces; it's wrapped in parentheses.
	l := strings.LastIndex(statLine, ")")
	if l == -1 {
		return "", 0, fmt.Errorf("invalid stat")
	}
	// Find the first '(' after pid.
	f := strings.Index(statLine, "(")
	if f == -1 || f > l {
		return "", 0, fmt.Errorf("invalid stat")
	}
	comm := statLine[f+1 : l]
	rest := strings.Fields(statLine[l+1:])
	// starttime is field 22 overall.
	// After ") " we have fields 3..N, where rest[0] is state (field 3).
	// Therefore starttime (field 22) is rest[19].
	if len(rest) < 21 {
		return comm, 0, fmt.Errorf("stat too short")
	}
	start, err := strconv.ParseInt(rest[19], 10, 64)
	if err != nil {
		return comm, 0, err
	}
	return comm, start, nil
}

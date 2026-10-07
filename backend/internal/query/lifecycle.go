package query

import "time"

// ProcessLifecycle is the derived view of a process: exec + optional exit and duration.
// Query-only; no storage. Missing exit means still running (ExitID/ExitTime/DurationMs nil).
type ProcessLifecycle struct {
	PID        int        `json:"pid"`
	PPID       int        `json:"ppid"`
	ExecID     string     `json:"exec_id"`
	ExecTime   time.Time  `json:"exec_time"`
	ExitID     *string    `json:"exit_id,omitempty"`
	ExitTime   *time.Time `json:"exit_time,omitempty"`
	DurationMs *int64     `json:"duration_ms,omitempty"`
	Exited     bool       `json:"exited"`
}

// BuildProcessLifecycles matches exits to execs by PID and computes duration.
// Pure function, no I/O. If no exit for a PID, ExitID/ExitTime/DurationMs are nil and Exited is false.
// Multiple exits for same PID: first exit in the slice wins (caller should pass ordered exits).
func BuildProcessLifecycles(execs []ExecRow, exits []ProcessExitRow) []ProcessLifecycle {
	exitByPID := make(map[int]ProcessExitRow)
	for _, e := range exits {
		if _, ok := exitByPID[e.PID]; !ok {
			exitByPID[e.PID] = e
		}
	}

	out := make([]ProcessLifecycle, 0, len(execs))
	for _, ex := range execs {
		lc := ProcessLifecycle{
			PID:      ex.PID,
			PPID:     ex.PPID,
			ExecID:   ex.ID,
			ExecTime: ex.Timestamp,
			Exited:   false,
		}
		if exit, ok := exitByPID[ex.PID]; ok {
			lc.ExitID = &exit.ID
			lc.ExitTime = &exit.Timestamp
			ms := exit.Timestamp.Sub(ex.Timestamp).Milliseconds()
			lc.DurationMs = &ms
			lc.Exited = true
		}
		out = append(out, lc)
	}
	return out
}

// Package exechandler converts raw exec events into canonical events.
// Used by both Linux (eBPF) and macOS (kqueue/ESF) runners.
package exechandler

// RawExecEvent is the raw exec event from eBPF, kqueue, ESF, or equivalent.
type RawExecEvent struct {
	TsNano      int64
	PID         uint32
	PPID        uint32
	UID         uint32
	Comm        string   // short process name (15 chars), from bpf_get_current_comm or libproc
	Exe         string   // full resolved path
	Args        []string // command-line arguments
	Cwd         string
	SessionID   uint32
	ContainerID string
	Role        string
	AISessionID string // Correlic AI session UUID (set by lineage tracker)
	Blocked     bool   // true if the process was killed by the enforcer
}

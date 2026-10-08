//go:build darwin

package esevents

import "github.com/correlic/correlic-agent/internal/procinfo"

// lookupPPID resolves a parent PID with ps(1) for events that did not carry
// one. Endpoint Security events always do, so this is a rarely-taken path.
func lookupPPID(pid uint32) uint32 {
	return procinfo.LookupPPID(pid)
}

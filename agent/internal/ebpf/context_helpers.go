package ebpf

import "github.com/correlic/correlic-agent/internal/procinfo"

// DetectContainerID delegates to the shared procinfo package.
func DetectContainerID(pid uint32) string {
	return procinfo.DetectContainerID(pid)
}

// detectSessionID delegates to the shared procinfo package.
func detectSessionID(pid uint32) uint32 {
	return procinfo.DetectSessionID(pid)
}

// readProcCmdline delegates to the shared procinfo package.
func readProcCmdline(pid uint32) []string {
	return procinfo.ReadProcCmdline(pid)
}

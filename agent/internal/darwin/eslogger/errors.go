// Package eslogger runs Apple's /usr/bin/eslogger (macOS 13+) as a child
// process and turns its JSON Lines output into esevents.Event values. It is
// the free way to get Endpoint Security events: eslogger ships with macOS
// and is already entitled, so no Apple Developer Program account is needed.
// The price is Apple's caveat that the tool is not intended for applications
// and that its output format and performance may change, which is why the
// parser is tolerant and the agent falls back to polling when eslogger cannot
// start.
//
// The parser (Parse) and the process supervisor (Collector) have no build tag
// so they are tested on Linux with a fake eslogger script; only Available is
// macOS-specific.
package eslogger

import "errors"

var (
	// ErrNotFound means the eslogger binary is missing (macOS older than 13).
	ErrNotFound = errors.New("eslogger not found")
	// ErrNotRoot means the agent is not running as root.
	ErrNotRoot = errors.New("eslogger needs root")
	// ErrNotPermitted means Endpoint Security refused the client, which on a
	// stock Mac means the responsible process lacks Full Disk Access.
	ErrNotPermitted = errors.New("eslogger not permitted (Full Disk Access missing)")
	// ErrUnsupportedOS is returned by Available off macOS.
	ErrUnsupportedOS = errors.New("eslogger is only available on macOS")
	// ErrUnsupportedVersion means macOS is older than 13 (Ventura).
	ErrUnsupportedVersion = errors.New("eslogger needs macOS 13 or newer")
	// ErrStartup means eslogger exited right after starting for a reason
	// its stderr did not make recognizable.
	ErrStartup = errors.New("eslogger exited during startup")
	// ErrGaveUp means eslogger kept dying and the collector stopped
	// restarting it.
	ErrGaveUp = errors.New("eslogger restarted too often; giving up")
)

// Remediation is the operator hint logged when eslogger cannot be used.
const Remediation = "run as root; grant correlic-agent Full Disk Access in System Settings > Privacy & Security; macOS 13 or newer"

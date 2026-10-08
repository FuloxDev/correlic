// Package esevents holds the flat Endpoint Security event shape shared by the
// native ESF client (internal/darwin/esf, cgo, esf build tag) and the
// eslogger collector (internal/darwin/eslogger), together with the runners
// that turn those events into canonical and telemetry events.
//
// The package has no build tag: the runners are compiled and tested on every
// platform, and only the event sources are macOS-specific.
package esevents

import "time"

// EventType identifies the Endpoint Security event an Event was built from.
// It is independent of the numeric es_event_type_t values, which differ by
// SDK; the sources map their own identifiers to these.
type EventType uint8

const (
	// EventUnknown marks an event the source could not classify; sources
	// drop these before they reach a runner.
	EventUnknown EventType = iota
	// EventExec is ES_EVENT_TYPE_NOTIFY_EXEC: PID, PPID, UID, ExePath, Comm
	// and Args describe the new image.
	EventExec
	// EventExit is ES_EVENT_TYPE_NOTIFY_EXIT; ExitCode is set.
	EventExit
	// EventOpen is ES_EVENT_TYPE_NOTIFY_OPEN; FilePath and OpenFlags are set.
	EventOpen
	// EventFork is ES_EVENT_TYPE_NOTIFY_FORK; PID is the child, PPID the
	// forking parent.
	EventFork
	// EventLookup is ES_EVENT_TYPE_NOTIFY_LOOKUP (a path lookup, not DNS;
	// the DNS runner interprets Domain). Only the native ESF client emits it.
	EventLookup
)

// String returns the lower-case eslogger-style name of the event type.
func (t EventType) String() string {
	switch t {
	case EventExec:
		return "exec"
	case EventExit:
		return "exit"
	case EventOpen:
		return "open"
	case EventFork:
		return "fork"
	case EventLookup:
		return "lookup"
	}
	return "unknown"
}

// Event is a flattened, Go-native Endpoint Security event.
type Event struct {
	Type      EventType
	Timestamp time.Time

	// Process (always populated)
	PID     uint32
	PPID    uint32
	UID     uint32
	Comm    string // basename of ExePath
	ExePath string

	// Exec-specific
	Args []string

	// File-open-specific
	FilePath  string
	OpenFlags int32

	// DNS lookup-specific
	Domain string

	// Exit-specific
	ExitCode int32
}

// EventSource is what the runners consume: a channel of events that is
// closed when the source stops for good.
type EventSource interface {
	Events() <-chan Event
}

// ChanSource adapts a plain channel to an EventSource.
type ChanSource <-chan Event

// Events implements EventSource.
func (c ChanSource) Events() <-chan Event { return c }

//go:build darwin && esf

// Package esf provides Go bindings for Apple's Endpoint Security Framework.
// ESF gives real-time, kernel-enforced events with full PID attribution,
// replacing the polling-based FSEvents and lsof collectors.
//
// The Client is an esevents.EventSource: it emits the shared esevents.Event
// shape, and the runners in internal/darwin/esevents consume it (through an
// esevents.Fanout) exactly as they consume the eslogger collector.
//
// Requirements:
//   - macOS 11+ (Big Sur); DNS lookups need a macOS 12+ SDK
//   - com.apple.developer.endpoint-security.client entitlement
//   - Running as root
//   - Binary must be code-signed: codesign -s "Developer ID Application: ..."
//     --entitlements build/correlic-agent.entitlements --force correlic-agent
package esf

/*
#cgo CFLAGS: -x objective-c
// Endpoint Security is a header-only framework in the SDK; its symbols are
// exported by /usr/lib/libEndpointSecurity.dylib, so link the library. The
// audit_token_to_* helpers come from libbsm.
#cgo LDFLAGS: -lEndpointSecurity -lbsm -framework Foundation
#include "esf.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"runtime/cgo"
	"strings"
	"time"
	"unsafe"

	"github.com/correlic/correlic-agent/internal/darwin/esevents"
)

// EventType mirrors es_event_type_t values we subscribe to.
type EventType uint32

// Event type constants are resolved from C at init time so they are always
// correct regardless of the macOS SDK version used to compile the binary.
var (
	EventExec   = EventType(C.correlic_event_exec())
	EventExit   = EventType(C.correlic_event_exit())
	EventOpen   = EventType(C.correlic_event_open())
	EventLookup = EventType(C.correlic_event_lookup()) // UINT32_MAX if SDK < macOS 12
)

// LookupAvailable reports whether ES_EVENT_TYPE_NOTIFY_LOOKUP is supported
// by the SDK this binary was compiled against (requires macOS 12.0+).
func LookupAvailable() bool {
	return EventLookup != EventType(^uint32(0))
}

// SubscribedEvents returns the event types Correlic subscribes to: exec,
// exit, open and, when the SDK knows it, lookup.
func SubscribedEvents() []EventType {
	types := []EventType{EventExec, EventExit, EventOpen}
	if LookupAvailable() {
		types = append(types, EventLookup)
	}
	return types
}

// Event is the flattened, Go-native Endpoint Security event shared with the
// eslogger collector and consumed by the esevents runners.
type Event = esevents.Event

// canonicalType maps an SDK event type to the shared EventType.
func canonicalType(t EventType) esevents.EventType {
	switch t {
	case EventExec:
		return esevents.EventExec
	case EventExit:
		return esevents.EventExit
	case EventOpen:
		return esevents.EventOpen
	case EventLookup:
		if LookupAvailable() {
			return esevents.EventLookup
		}
	}
	return esevents.EventUnknown
}

// Client wraps the ESF client and exposes a Go channel of events.
type Client struct {
	handle   *C.correlic_es_client_t
	goHandle cgo.Handle // echoed back by the C callback; never a Go pointer in C memory
	events   chan Event
}

// NewClient creates a new ESF client.
// Returns an error if the entitlement is missing, the binary is not signed,
// or the process is not running as root.
func NewClient() (*Client, error) {
	c := &Client{
		events: make(chan Event, 4096),
	}

	// Hand C an opaque cgo.Handle rather than a Go pointer; the callback
	// resolves it back to this Client.
	c.goHandle = cgo.NewHandle(c)

	var outErr *C.char
	handle := C.correlic_es_new_client(C.uintptr_t(c.goHandle), &outErr)
	if handle == nil {
		errMsg := "es_new_client failed"
		if outErr != nil {
			errMsg = C.GoString(outErr)
			C.free(unsafe.Pointer(outErr))
		}
		c.goHandle.Delete()
		return nil, fmt.Errorf("esf: %s", errMsg)
	}

	c.handle = handle

	// Mute the agent itself to prevent monitoring our own events (feedback loop).
	C.correlic_es_mute_self(handle)

	return c, nil
}

// Subscribe subscribes to the given event types.
func (c *Client) Subscribe(types []EventType) error {
	if len(types) == 0 {
		return nil
	}
	cTypes := make([]C.es_event_type_t, len(types))
	for i, t := range types {
		cTypes[i] = C.es_event_type_t(t)
	}
	rc := C.correlic_es_subscribe(c.handle, &cTypes[0], C.uint32_t(len(cTypes)))
	if rc != 0 {
		return fmt.Errorf("esf: es_subscribe failed")
	}
	return nil
}

// Events returns the read-only channel of ESF events (esevents.EventSource).
func (c *Client) Events() <-chan Event {
	return c.events
}

// Close tears down the ESF client and closes the events channel.
func (c *Client) Close() {
	if c.handle != nil {
		C.correlic_es_destroy(c.handle)
		c.handle = nil
		// No callbacks can arrive once the ES client is deleted.
		c.goHandle.Delete()
	}
	close(c.events)
}

// ---------------------------------------------------------------------------
// CGO export: called from C callback into Go
// ---------------------------------------------------------------------------

//export correlic_send_event
func correlic_send_event(goHandle C.uintptr_t, cEv *C.correlic_es_event_t) {
	c, ok := cgo.Handle(goHandle).Value().(*Client)
	if !ok || c == nil {
		return
	}

	typ := canonicalType(EventType(cEv.event_type))
	if typ == esevents.EventUnknown {
		return
	}

	ev := Event{
		Type:      typ,
		Timestamp: time.Now(),
		PID:       uint32(cEv.pid),
		PPID:      uint32(cEv.ppid),
		UID:       uint32(cEv.uid),
		Comm:      C.GoString(&cEv.comm[0]),
		ExePath:   C.GoString(&cEv.exe_path[0]),
		FilePath:  C.GoString(&cEv.file_path[0]),
		OpenFlags: int32(cEv.open_flags),
		Domain:    C.GoString(&cEv.domain[0]),
		ExitCode:  int32(cEv.exit_code),
	}

	// Parse null-separated args
	if cEv.args_count > 0 {
		raw := C.GoStringN(&cEv.args[0], C.int(4096))
		ev.Args = parseNullSeparated(raw, int(cEv.args_count))
	}

	// Non-blocking send — drop events if the consumer is behind.
	select {
	case c.events <- ev:
	default:
	}
}

func parseNullSeparated(s string, count int) []string {
	parts := strings.SplitN(s, "\x00", count+1)
	result := make([]string, 0, count)
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
		if len(result) == count {
			break
		}
	}
	return result
}

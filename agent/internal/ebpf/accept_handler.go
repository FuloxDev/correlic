//go:build linux

package ebpf

import (
	"fmt"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
)

// AcceptHandler converts accept events into canonical event.Event (type net_accept) and dispatches them.
type AcceptHandler struct {
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// Handle builds a canonical net_accept event and enqueues it.
func (h *AcceptHandler) Handle(raw AcceptEvent) {
	ts := time.Unix(0, int64(raw.TimestampNs))

	targetStr := raw.ClientIP()
	if raw.ClientPort != 0 {
		targetStr = fmt.Sprintf("%s:%d", raw.ClientIP(), raw.ClientPort)
	}

	evt := event.Event{
		SchemaVersion: 1,
		HostID:        h.HostID,
		Timestamp:     ts,
		Source:        "kernel",
		Type:          "net_accept",

		Actor: &event.Actor{
			PID:       int(raw.PID),
			PPID:      int(raw.PPID),
			Comm:      raw.Comm,
			SessionID: strconv.FormatUint(uint64(detectSessionID(raw.PID)), 10),
		},
		Target: &event.Target{
			IP:   raw.ClientIP(),
			Port: int(raw.ClientPort),
		},
	}

	evt.ID = event.GenerateID(h.HostID, ts.UnixNano(), evt.Source, evt.Type, evt.Actor.PID, targetStr)
	h.Dispatcher.Enqueue(evt)
}

//go:build linux

package ebpf

import (
	"fmt"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
)

// MsgHandler converts msg events into canonical event.Event (type net_msg) and dispatches them.
type MsgHandler struct {
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// Handle builds a canonical net_msg event and enqueues it.
func (h *MsgHandler) Handle(raw MsgEvent) {
	ts := time.Unix(0, int64(raw.TimestampNs))

	direction := "send"
	if raw.Direction == 1 {
		direction = "recv"
	}

	evt := event.Event{
		SchemaVersion: 1,
		HostID:        h.HostID,
		Timestamp:     ts,
		Source:        "kernel",
		Type:          "net_msg",

		Actor: &event.Actor{
			PID:       int(raw.PID),
			Comm:      raw.Comm,
			SessionID: strconv.FormatUint(uint64(detectSessionID(raw.PID)), 10),
		},
		Context: map[string]any{
			"direction": direction,
			"size":      int(raw.Size),
			"fd":        int(raw.FD),
		},
	}

	targetStr := fmt.Sprintf("%s:%d", direction, raw.FD)
	evt.ID = event.GenerateID(h.HostID, ts.UnixNano(), evt.Source, evt.Type, evt.Actor.PID, targetStr)
	h.Dispatcher.Enqueue(evt)
}

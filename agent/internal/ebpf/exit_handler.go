//go:build linux

package ebpf

import (
	"fmt"
	"strconv"

	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
)

// ExitHandler converts exit events into canonical event.Event (type process_exit) and dispatches them.
// Never drop, no dedupe, no rate limit (Phase 20).
type ExitHandler struct {
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// Handle builds a canonical process_exit event and enqueues it.
func (h *ExitHandler) Handle(raw ExitEvent) {
	evt := event.Event{
		SchemaVersion: 1,
		HostID:        h.HostID,
		Timestamp:     raw.Timestamp,
		Source:        "kernel",
		Type:          "process_exit",

		Actor: &event.Actor{
			PID:       raw.PID,
			PPID:      raw.PPID,
			Comm:      raw.Comm,
			SessionID: strconv.FormatUint(uint64(detectSessionID(uint32(raw.PID))), 10),
			// DO NOT set ExePath: comm is only 16 bytes, not a reliable path.
			// Identity comes from exec only; never trust exe_path on exit.
		},

		Context: map[string]any{
			"exit_code": raw.ExitCode,
		},
	}

	if aiSess := GetLineageTracker().GetSessionID(uint32(raw.PID)); aiSess != "" {
		evt.Context["ai_session_id"] = aiSess
	}
	targetStr := fmt.Sprintf("%d|%d", raw.PID, raw.ExitCode)
	evt.ID = event.GenerateID(h.HostID, raw.Timestamp.UnixNano(), evt.Source, evt.Type, evt.Actor.PID, targetStr)
	h.Dispatcher.Enqueue(evt)
}

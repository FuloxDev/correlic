package exechandler

import (
	"os/user"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/normalize"
)

// ExecHandler converts raw exec events into canonical event.Event and dispatches them.
type ExecHandler struct {
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// Handle converts a raw exec event to a canonical event and dispatches it.
// We use receive time (time.Now()) so timestamps are correct regardless of kernel clock semantics.
func (h *ExecHandler) Handle(raw RawExecEvent) {
	execTime := time.Now()

	evt := event.Event{
		SchemaVersion: 1,
		HostID:        h.HostID,
		Timestamp:     execTime,
		Source:        "kernel",
		Type:          "process_exec",

		Actor: &event.Actor{
			PID:       int(raw.PID),
			PPID:      int(raw.PPID),
			User:      ResolveUser(raw.UID),
			Comm:      raw.Comm,
			ExePath:   raw.Exe,
			Cmdline:   raw.Args,
			SessionID: strconv.FormatUint(uint64(raw.SessionID), 10),
			Role:      raw.Role,
		},

		Context: map[string]any{},
	}

	// Tag with AI session ID if available (cross-PID correlation).
	if raw.AISessionID != "" {
		evt.Context["ai_session_id"] = raw.AISessionID
	}
	// Tag blocked events so the detection engine sets status="blocked" on findings.
	if raw.Blocked {
		evt.Context["action"] = "blocked"
	}

	cls := normalize.ClassifyExec(evt.Actor.ExePath, evt.Actor.Cmdline, evt.Actor.PPID)
	if cls.Normalized {
		evt.Context["exec_class"] = cls.Class
		evt.Context["exec_role"] = cls.Role
		evt.Context["exec_group"] = cls.Group
		evt.Context["exec_normalized"] = true
	}

	// Post-normalization exec cleanup (noise suppression). Before enqueue.
	decision := normalize.ShouldDropExec(evt.Context)
	if decision.Drop {
		h.Dispatcher.RecordDrop(evt.Type, decision.Reason)
		return
	}

	evt.ID = event.GenerateID(
		h.HostID,
		execTime.UnixNano(),
		evt.Source,
		evt.Type,
		evt.Actor.PID,
		raw.Exe,
	)

	h.Dispatcher.Enqueue(evt)
}

// ResolveUser converts a UID to a username string.
func ResolveUser(uid uint32) string {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return strconv.FormatUint(uint64(uid), 10)
	}
	return u.Username
}

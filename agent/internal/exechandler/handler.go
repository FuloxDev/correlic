package exechandler

import (
	"os/user"
	"strconv"
	"sync"
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

	// Tag with the AI session (cross-PID correlation). Every event of an AI
	// process tree carries ai_session_id + is_ai, and ai_type when known.
	if raw.AISessionID != "" {
		evt.Context["ai_session_id"] = raw.AISessionID
		evt.Context["is_ai"] = true
		if raw.AIType != "" {
			evt.Context["ai_type"] = raw.AIType
		}
	}
	if raw.ContainerID != "" {
		evt.Context["container_id"] = raw.ContainerID
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

// userCacheMax bounds the uid → username cache. Hosts rarely have more than a
// few hundred distinct uids; the cache is simply cleared when it fills.
const userCacheMax = 1024

var userCache = struct {
	sync.Mutex
	m map[uint32]string
}{m: make(map[uint32]string)}

// ResolveUser converts a UID to a username string. Lookups hit NSS (and
// possibly LDAP/sssd) so results, including failures, are cached.
func ResolveUser(uid uint32) string {
	userCache.Lock()
	name, ok := userCache.m[uid]
	userCache.Unlock()
	if ok {
		return name
	}

	name = strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(name); err == nil && u.Username != "" {
		name = u.Username
	}

	userCache.Lock()
	if len(userCache.m) >= userCacheMax {
		userCache.m = make(map[uint32]string)
	}
	userCache.m[uid] = name
	userCache.Unlock()
	return name
}

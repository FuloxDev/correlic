package eslogger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/darwin/esevents"
)

// eslogger prints one JSON object per line, modelled on es_message_t
// (EndpointSecurity/ESMessage.h). Only the fields below are read; the rest
// (stat blocks, code signing data, env, fds) are skipped by the decoder.
// Every field is optional: a line that lacks some never panics, and a line
// whose event is not exec, open, exit or fork is ignored.
type message struct {
	SchemaVersion int                        `json:"schema_version"`
	EventType     json.RawMessage            `json:"event_type"` // es_event_type_t as a number
	Time          string                     `json:"time"`       // ISO 8601 UTC
	Process       *process                   `json:"process"`
	Event         map[string]json.RawMessage `json:"event"`
}

// process mirrors es_process_t.
type process struct {
	AuditToken       *auditToken `json:"audit_token"`
	ParentAuditToken *auditToken `json:"parent_audit_token"`
	PPID             *int64      `json:"ppid"`
	Executable       *fileRef    `json:"executable"`
}

// auditToken mirrors the decoded audit_token_t.
type auditToken struct {
	PID  int64  `json:"pid"`
	EUID *int64 `json:"euid"`
	RUID *int64 `json:"ruid"`
}

// fileRef mirrors es_file_t (only the path is used).
type fileRef struct {
	Path string `json:"path"`
}

type execEvent struct {
	Target *process        `json:"target"`
	Args   json.RawMessage `json:"args"`
}

type openEvent struct {
	File  *fileRef `json:"file"`
	Fflag int64    `json:"fflag"`
}

type exitEvent struct {
	Stat int64 `json:"stat"`
}

type forkEvent struct {
	Child *process `json:"child"`
}

// eventKeys maps the key under "event" to the event type. The key is the
// primary classification; the numeric event_type is only a hint.
var eventKeys = []struct {
	key string
	typ esevents.EventType
}{
	{"exec", esevents.EventExec},
	{"open", esevents.EventOpen},
	{"exit", esevents.EventExit},
	{"fork", esevents.EventFork},
}

// eventNumbers maps es_event_type_t values (ESMessage.h; stable since macOS
// 10.15) to event types, used when the "event" object does not name one.
var eventNumbers = map[int]esevents.EventType{
	9:  esevents.EventExec, // ES_EVENT_TYPE_NOTIFY_EXEC
	10: esevents.EventOpen, // ES_EVENT_TYPE_NOTIFY_OPEN
	11: esevents.EventFork, // ES_EVENT_TYPE_NOTIFY_FORK
	15: esevents.EventExit, // ES_EVENT_TYPE_NOTIFY_EXIT
}

// Parse decodes one eslogger output line. ok is false for blank lines and
// for valid messages of an event type the agent does not use; err is set
// only when the line is not a JSON object.
func Parse(line []byte) (ev esevents.Event, ok bool, err error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return esevents.Event{}, false, nil
	}
	var m message
	if err := json.Unmarshal(line, &m); err != nil {
		return esevents.Event{}, false, fmt.Errorf("eslogger: decode line: %w", err)
	}

	typ, payload := classify(&m)
	if typ == esevents.EventUnknown {
		return esevents.Event{}, false, nil
	}

	ev = esevents.Event{Type: typ, Timestamp: parseTime(m.Time)}
	fillProcess(&ev, m.Process)

	switch typ {
	case esevents.EventExec:
		var e execEvent
		decode(payload, &e)
		// process is the image that called exec; target is the new one.
		if e.Target != nil {
			fillProcess(&ev, e.Target)
		}
		ev.Args = parseArgs(e.Args)
	case esevents.EventOpen:
		var e openEvent
		decode(payload, &e)
		if e.File != nil {
			ev.FilePath = e.File.Path
		}
		ev.OpenFlags = clampInt32(e.Fflag)
	case esevents.EventExit:
		var e exitEvent
		decode(payload, &e)
		ev.ExitCode = exitCode(e.Stat)
	case esevents.EventFork:
		var e forkEvent
		decode(payload, &e)
		// process is the parent; the child carries its own ppid.
		parent := ev.PID
		if e.Child != nil {
			fillProcess(&ev, e.Child)
		}
		if ev.PPID == 0 {
			ev.PPID = parent
		}
	}
	// Every real message names a process; without a PID the event cannot be
	// attributed, so it is ignored rather than passed on as PID 0.
	if ev.PID == 0 {
		return esevents.Event{}, false, nil
	}
	return ev, true, nil
}

// classify picks the event type from the "event" object's key, falling back
// to the numeric event_type.
func classify(m *message) (esevents.EventType, json.RawMessage) {
	for _, k := range eventKeys {
		if raw, found := m.Event[k.key]; found {
			return k.typ, raw
		}
	}
	if n, found := eventTypeNumber(m.EventType); found {
		if typ, known := eventNumbers[n]; known {
			return typ, nil
		}
	}
	return esevents.EventUnknown, nil
}

// eventTypeNumber reads event_type as a number, or as a quoted number or
// enumerator name ("NOTIFY_EXEC") should a future schema switch to strings.
func eventTypeNumber(raw json.RawMessage) (int, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return 0, false
	}
	s = strings.Trim(s, `"`)
	if n, err := strconv.Atoi(s); err == nil {
		return n, true
	}
	name := strings.ToLower(s)
	name = strings.TrimPrefix(name, "es_event_type_")
	name = strings.TrimPrefix(name, "notify_")
	for n, typ := range eventNumbers {
		if typ.String() == name {
			return n, true
		}
	}
	return 0, false
}

// decode unmarshals payload into v, ignoring errors: a field of an
// unexpected type leaves the Go zero value, which the runners tolerate.
func decode(payload json.RawMessage, v any) {
	if len(payload) == 0 {
		return
	}
	_ = json.Unmarshal(payload, v)
}

// fillProcess copies PID, PPID, UID, ExePath and Comm from p into ev,
// leaving the fields alone when p lacks them.
func fillProcess(ev *esevents.Event, p *process) {
	if p == nil {
		return
	}
	if p.AuditToken != nil {
		if p.AuditToken.PID > 0 {
			ev.PID = clampUint32(p.AuditToken.PID)
		}
		if p.AuditToken.EUID != nil {
			ev.UID = clampUint32(*p.AuditToken.EUID)
		} else if p.AuditToken.RUID != nil {
			ev.UID = clampUint32(*p.AuditToken.RUID)
		}
	}
	switch {
	case p.PPID != nil:
		ev.PPID = clampUint32(*p.PPID)
	case p.ParentAuditToken != nil && p.ParentAuditToken.PID > 0:
		ev.PPID = clampUint32(p.ParentAuditToken.PID)
	}
	if p.Executable != nil && p.Executable.Path != "" {
		ev.ExePath = p.Executable.Path
		ev.Comm = basename(p.Executable.Path)
	}
}

// parseArgs decodes the exec args array; anything else yields nil.
func parseArgs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var args []string
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil
	}
	return args
}

// parseTime parses eslogger's ISO 8601 UTC timestamp; now() when it is
// missing or malformed.
func parseTime(s string) time.Time {
	if s != "" {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t
		}
	}
	return time.Now()
}

// exitCode decodes es_event_exit_t.stat, a wait(2) status word, into the
// conventional exit code: the exit status for a normal exit, 128+signal for
// a process killed by a signal.
func exitCode(stat int64) int32 {
	if stat < 0 {
		return 0
	}
	s := stat & 0xffff
	sig := s & 0x7f
	if sig == 0 || sig == 0x7f {
		return int32((s >> 8) & 0xff)
	}
	return int32(128 + sig)
}

func basename(p string) string {
	if p == "" {
		return ""
	}
	b := path.Base(p)
	if b == "." || b == "/" {
		return ""
	}
	return b
}

func clampUint32(v int64) uint32 {
	if v < 0 || v > math.MaxUint32 {
		return 0
	}
	return uint32(v)
}

func clampInt32(v int64) int32 {
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0
	}
	return int32(v)
}

package hook

import (
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
)

// Canonical event identifiers.
const (
	EventSource = "hook"
	EventType   = "ai_tool_call"

	DecisionAllowed = "allowed"
	DecisionBlocked = "blocked"
)

// Decision is the outcome of the block-rule evaluation for one event.
type Decision struct {
	Blocked    bool
	RuleID     int
	SignalType string // process_exec | file_open
	Candidate  string // the token or path that matched
	Pattern    string // the rule pattern
}

// Actor identifies the AI tool process the hook was spawned by.
type Actor struct {
	PID     int    // os.Getppid(): the AI tool (claude / cursor)
	User    string // current user name
	ExePath string // parent's executable when resolvable (Linux)
}

// CurrentActor resolves the actor from the running process.
func CurrentActor() Actor {
	a := Actor{PID: os.Getppid()}
	if u, err := user.Current(); err == nil {
		a.User = u.Username
	}
	if a.User == "" {
		a.User = firstNonEmpty(os.Getenv("USER"), os.Getenv("USERNAME"))
	}
	if a.PID > 0 {
		if exe, err := os.Readlink(filepath.Join("/proc", itoa(a.PID), "exe")); err == nil {
			a.ExePath = exe
		}
	}
	return a
}

// BuildEvent converts a parsed hook event into the canonical ai_tool_call
// event the backend stores (backend/internal/event). Only commands, paths,
// URLs, names and ids are included.
func BuildEvent(ev *ToolEvent, hostID string, actor Actor, ts time.Time, d Decision) event.Event {
	comm := toolComm(ev.Tool)
	ctx := map[string]any{
		"is_ai":         true,
		"ai_type":       ev.Tool,
		"ai_session_id": ev.SessionID,
		"hook_event":    ev.HookEvent,
		"phase":         ev.Phase,
		"decision":      DecisionAllowed,
	}
	if ev.ToolName != "" {
		ctx["tool_name"] = ev.ToolName
	}
	if ev.ToolUseID != "" {
		ctx["tool_use_id"] = ev.ToolUseID
	}
	if ev.GenerationID != "" {
		ctx["generation_id"] = ev.GenerationID
	}
	if ev.Cwd != "" {
		ctx["cwd"] = ev.Cwd
	}
	if ev.Workspace != "" {
		ctx["workspace"] = ev.Workspace
	}
	if ev.PermissionMode != "" {
		ctx["permission_mode"] = ev.PermissionMode
	}
	if ev.Command != "" {
		ctx["command"] = ev.Command
	}
	if ev.FilePath != "" {
		ctx["file_path"] = ev.FilePath
	}
	if ev.URL != "" {
		ctx["url"] = ev.URL
	}
	if ev.EditCount > 0 {
		ctx["edit_count"] = ev.EditCount
	}
	if ev.Phase == PhasePost {
		if ev.Success != nil {
			ctx["success"] = *ev.Success
		}
		if ev.Interrupted {
			ctx["interrupted"] = true
		}
		if ev.Error != "" {
			ctx["error"] = ev.Error
		}
		if ev.DurationMs > 0 {
			ctx["duration_ms"] = ev.DurationMs
		}
	}
	if d.Blocked {
		ctx["decision"] = DecisionBlocked
		ctx["block_rule_id"] = d.RuleID
		ctx["block_signal_type"] = d.SignalType
		ctx["block_candidate"] = d.Candidate
	}

	var target *event.Target
	switch {
	case ev.FilePath != "":
		target = &event.Target{FilePath: ev.FilePath}
	case ev.URL != "":
		target = &event.Target{Domain: urlHost(ev.URL)}
	}

	// The event id must be unique per call: tool_use_id (or the derived Cursor
	// id) plus the phase distinguishes pre/post of the same call.
	idKey := strings.Join([]string{ev.HookEvent, ev.ToolUseID, ev.ToolName, ev.Command, ev.FilePath, ev.URL}, "\x00")
	return event.Event{
		SchemaVersion: 1,
		ID:            event.GenerateID(hostID, ts.UnixNano(), EventSource, EventType, actor.PID, idKey),
		HostID:        hostID,
		Timestamp:     ts,
		Source:        EventSource,
		Type:          EventType,
		Actor: &event.Actor{
			PID:       actor.PID,
			User:      actor.User,
			ExePath:   actor.ExePath,
			Comm:      comm,
			SessionID: ev.SessionID,
			Role:      "agent",
		},
		Target:  target,
		Context: ctx,
	}
}

func toolComm(tool string) string {
	switch tool {
	case ToolClaudeCode:
		return "claude"
	case ToolCursor:
		return "cursor"
	}
	return "ai-tool"
}

func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// --- shell command tokenising (for block rules and the activity stream) ---

// wrapperCommands are skipped when looking for the executable of a shell
// command: `sudo nc ...` is matched as `nc`. The value lists the wrapper's
// options that take a separate argument (`sudo -u root nc` is still `nc`).
var wrapperCommands = map[string]map[string]bool{
	"sudo":    {"-u": true, "-g": true, "-U": true, "-h": true, "-p": true, "-C": true, "-D": true, "-r": true, "-t": true, "-T": true},
	"doas":    {"-u": true, "-C": true},
	"env":     {"-u": true, "-C": true, "-S": true},
	"nohup":   {},
	"exec":    {"-a": true},
	"time":    {"-f": true, "-o": true},
	"command": {},
	"builtin": {},
	"nice":    {"-n": true},
	"ionice":  {"-c": true, "-n": true, "-p": true},
}

// ShellCommands splits a shell command line into its simple commands on the
// usual separators (&&, ||, ;, |, newlines). Quoting is not interpreted; the
// result is a best-effort list of command-line segments.
func ShellCommands(cmdline string) []string {
	var out []string
	cur := strings.Builder{}
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(cmdline); i++ {
		c := cmdline[i]
		switch {
		case c == '\n' || c == ';':
			flush()
		case c == '|':
			flush()
			if i+1 < len(cmdline) && cmdline[i+1] == '|' {
				i++
			}
		case c == '&' && i+1 < len(cmdline) && cmdline[i+1] == '&':
			flush()
			i++
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// Executable returns the program a simple command runs: the first token after
// leading VAR=value assignments and wrapper commands (sudo, env, ...).
func Executable(simple string) string {
	fields := strings.Fields(simple)
	var valueOpts map[string]bool // options of the current wrapper that take a value
	for i := 0; i < len(fields); i++ {
		f := strings.Trim(fields[i], `"'`)
		if f == "" || isAssignment(f) {
			continue
		}
		if strings.HasPrefix(f, "-") {
			if valueOpts[f] {
				i++ // skip the option's argument
			}
			continue
		}
		if opts, isWrapper := wrapperCommands[strings.ToLower(BaseName(f))]; isWrapper {
			valueOpts = opts
			continue
		}
		return f
	}
	return ""
}

// BaseName returns the last path component for both separator styles, so a
// Windows command line is matched correctly from any host.
func BaseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func isAssignment(tok string) bool {
	i := strings.IndexByte(tok, '=')
	if i <= 0 {
		return false
	}
	for _, r := range tok[:i] {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// PathTokens returns the tokens of a command line that look like file paths
// (contain a path separator or start with ~ or .), with ~ expanded to home.
// They are matched against file_open block rules so `cat /etc/shadow` is
// stopped by a rule for that path even though the kernel never saw the open.
func PathTokens(cmdline string, home string) []string {
	var out []string
	for _, f := range strings.Fields(cmdline) {
		f = strings.Trim(f, `"'`+"`")
		if f == "" || strings.HasPrefix(f, "-") || strings.Contains(f, "://") {
			continue
		}
		if i := strings.IndexByte(f, '='); i > 0 && isAssignment(f) {
			f = f[i+1:]
		}
		if !(strings.ContainsAny(f, `/\`) || strings.HasPrefix(f, "~") || strings.HasPrefix(f, ".")) {
			continue
		}
		if home != "" && (f == "~" || strings.HasPrefix(f, "~/")) {
			f = home + f[1:]
		}
		out = append(out, f)
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

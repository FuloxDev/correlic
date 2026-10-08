package hook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// AI tool identifiers (context.ai_type / actor.comm).
const (
	ToolClaudeCode = "claude-code"
	ToolCursor     = "cursor"
	ToolUnknown    = "unknown"
)

// Phases of a hook event.
const (
	PhasePre     = "pre"     // before the tool runs; a decision may be returned
	PhasePost    = "post"    // after the tool ran (or failed)
	PhaseSession = "session" // session start/stop
	PhasePrompt  = "prompt"  // a user prompt was submitted (content is never recorded)
	PhaseOther   = "other"
)

// ToolEvent is one hook invocation normalised across Claude Code and Cursor.
// Only commands, paths, URLs, names and ids are kept: no file contents, tool
// output or prompts.
type ToolEvent struct {
	Tool      string // ToolClaudeCode | ToolCursor | ToolUnknown
	HookEvent string // raw hook_event_name
	Phase     string
	// Blockable is true for pre events whose response may deny the call.
	Blockable bool

	SessionID    string // session_id (Claude Code) | conversation_id (Cursor)
	GenerationID string // Cursor generation_id
	ToolName     string // Bash, Edit, mcp__server__tool, shell, file_edit, ...
	ToolUseID    string

	Command  string
	FilePath string
	URL      string
	Cwd      string
	// Workspace is the project root the AI tool works in (first
	// workspace_roots entry for Cursor, else cwd).
	Workspace      string
	PermissionMode string
	EditCount      int // Cursor afterFileEdit: number of edits (contents are dropped)

	// Post-phase outcome, when the tool reported one.
	Success     *bool
	Interrupted bool
	Error       string // first line of the failure, truncated
	DurationMs  int64
}

const (
	maxCommandLen = 4096
	maxPathLen    = 4096
	maxErrorLen   = 200
)

var claudeEvents = map[string]struct{ phase string }{
	"PreToolUse":         {PhasePre},
	"PostToolUse":        {PhasePost},
	"PostToolUseFailure": {PhasePost},
	"SessionStart":       {PhaseSession},
	"SessionEnd":         {PhaseSession},
	"Stop":               {PhaseSession},
	"SubagentStop":       {PhaseSession},
	"UserPromptSubmit":   {PhasePrompt},
	"Notification":       {PhaseOther},
	"PreCompact":         {PhaseOther},
}

var cursorEvents = map[string]struct {
	phase    string
	toolName string
}{
	"beforeShellExecution": {PhasePre, "shell"},
	"afterShellExecution":  {PhasePost, "shell"},
	"beforeMCPExecution":   {PhasePre, "mcp"},
	"afterMCPExecution":    {PhasePost, "mcp"},
	"afterFileEdit":        {PhasePost, "file_edit"},
	"beforeReadFile":       {PhasePre, "file_read"},
	"beforeSubmitPrompt":   {PhasePrompt, "prompt"},
	"sessionStart":         {PhaseSession, "session"},
	"sessionEnd":           {PhaseSession, "session"},
	"stop":                 {PhaseSession, "stop"},
}

// Parse decodes one hook payload from stdin. The format is detected from the
// fields present: Claude Code sends session_id + PascalCase hook_event_name,
// Cursor sends conversation_id + camelCase hook_event_name. Anything else is
// parsed generically (Tool = ToolUnknown) so a new event never breaks the hook.
func Parse(data []byte) (*ToolEvent, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode hook input: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("empty hook input")
	}
	name := str(raw, "hook_event_name")
	_, isClaude := claudeEvents[name]
	_, isCursor := cursorEvents[name]
	switch {
	case isClaude || (!isCursor && has(raw, "session_id") && has(raw, "transcript_path")):
		return parseClaude(name, raw), nil
	case isCursor || has(raw, "conversation_id") || has(raw, "workspace_roots"):
		return parseCursor(name, raw), nil
	default:
		return parseGeneric(name, raw), nil
	}
}

func parseClaude(name string, raw map[string]any) *ToolEvent {
	ev := &ToolEvent{
		Tool:           ToolClaudeCode,
		HookEvent:      name,
		Phase:          PhaseOther,
		SessionID:      str(raw, "session_id"),
		ToolName:       str(raw, "tool_name"),
		ToolUseID:      str(raw, "tool_use_id"),
		Cwd:            clip(str(raw, "cwd"), maxPathLen),
		PermissionMode: str(raw, "permission_mode"),
	}
	if e, ok := claudeEvents[name]; ok {
		ev.Phase = e.phase
	}
	ev.Workspace = ev.Cwd
	ev.Blockable = name == "PreToolUse"
	if input, ok := raw["tool_input"].(map[string]any); ok {
		extractToolInput(ev, input)
	}
	switch name {
	case "PostToolUse":
		ok := true
		if resp, isMap := raw["tool_response"].(map[string]any); isMap {
			ev.Interrupted = boolean(resp, "interrupted")
			if boolean(resp, "is_error") || boolean(resp, "isError") {
				ok = false
			}
		}
		if ev.Interrupted {
			ok = false
		}
		ev.Success = &ok
		ev.DurationMs = integer(raw, "duration_ms")
	case "PostToolUseFailure":
		failed := false
		ev.Success = &failed
		ev.Interrupted = boolean(raw, "is_interrupt")
		ev.Error = firstLine(str(raw, "error"))
		ev.DurationMs = integer(raw, "duration_ms")
	}
	return ev
}

func parseCursor(name string, raw map[string]any) *ToolEvent {
	ev := &ToolEvent{
		Tool:         ToolCursor,
		HookEvent:    name,
		Phase:        PhaseOther,
		SessionID:    str(raw, "conversation_id"),
		GenerationID: str(raw, "generation_id"),
		Cwd:          clip(str(raw, "cwd"), maxPathLen),
	}
	if roots, ok := raw["workspace_roots"].([]any); ok && len(roots) > 0 {
		if s, ok := roots[0].(string); ok {
			ev.Workspace = clip(s, maxPathLen)
		}
	}
	if ev.Workspace == "" {
		ev.Workspace = ev.Cwd
	}
	if ev.Cwd == "" {
		ev.Cwd = ev.Workspace
	}
	if e, ok := cursorEvents[name]; ok {
		ev.Phase = e.phase
		ev.ToolName = e.toolName
	}
	ev.Blockable = ev.Phase == PhasePre && name != "beforeSubmitPrompt"

	switch name {
	case "beforeShellExecution", "afterShellExecution":
		ev.Command = clip(str(raw, "command"), maxCommandLen)
	case "beforeMCPExecution", "afterMCPExecution":
		if tn := str(raw, "tool_name"); tn != "" {
			ev.ToolName = tn
		}
		if input := asMap(raw["tool_input"]); input != nil {
			extractToolInput(ev, input)
		}
	case "afterFileEdit":
		ev.FilePath = clip(str(raw, "file_path"), maxPathLen)
		if edits, ok := raw["edits"].([]any); ok {
			ev.EditCount = len(edits)
		}
	case "beforeReadFile":
		ev.FilePath = clip(str(raw, "file_path"), maxPathLen)
	default:
		// Unknown Cursor events: pick up whatever generic fields are present.
		extractToolInput(ev, raw)
		if ev.ToolName == "" {
			ev.ToolName = name
		}
	}
	if ev.Phase == PhasePost {
		ev.DurationMs = integer(raw, "duration_ms")
		if v, ok := raw["exit_code"]; ok {
			if n, isNum := v.(float64); isNum {
				ok := n == 0
				ev.Success = &ok
			}
		} else if v, ok := raw["success"].(bool); ok {
			ev.Success = &v
		}
		if e := firstLine(str(raw, "error")); e != "" {
			ev.Error = e
		}
	}
	// Cursor has no per-call id; derive one so a before/after pair of the same
	// generation correlates (and the activity stream shows the pair once).
	if ev.ToolName != "" && (ev.Phase == PhasePre || ev.Phase == PhasePost) {
		ev.ToolUseID = cursorToolUseID(ev)
	}
	return ev
}

func parseGeneric(name string, raw map[string]any) *ToolEvent {
	ev := &ToolEvent{
		Tool:      ToolUnknown,
		HookEvent: name,
		Phase:     PhaseOther,
		SessionID: firstStr(raw, "session_id", "conversation_id"),
		ToolName:  str(raw, "tool_name"),
		ToolUseID: str(raw, "tool_use_id"),
		Cwd:       clip(str(raw, "cwd"), maxPathLen),
	}
	ev.Workspace = ev.Cwd
	if input, ok := raw["tool_input"].(map[string]any); ok {
		extractToolInput(ev, input)
	} else {
		extractToolInput(ev, raw)
	}
	return ev
}

// extractToolInput pulls the only tool_input fields the hook records:
// command, file_path (or notebook_path / path) and url. Everything else in
// tool_input (file contents, edit strings, prompts) is dropped on purpose.
func extractToolInput(ev *ToolEvent, input map[string]any) {
	if ev.Command == "" {
		ev.Command = clip(str(input, "command"), maxCommandLen)
	}
	if ev.FilePath == "" {
		ev.FilePath = clip(firstStr(input, "file_path", "notebook_path", "path"), maxPathLen)
	}
	if ev.URL == "" {
		ev.URL = clip(str(input, "url"), maxPathLen)
	}
}

func cursorToolUseID(ev *ToolEvent) string {
	h := sha256.Sum256([]byte(ev.GenerationID + "|" + ev.ToolName + "|" + ev.Command + "|" + ev.FilePath + "|" + ev.URL))
	return "cursor-" + hex.EncodeToString(h[:8])
}

// --- small JSON helpers ---

func has(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return strings.TrimSpace(v)
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v := str(m, k); v != "" {
			return v
		}
	}
	return ""
}

func boolean(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

func integer(m map[string]any, key string) int64 {
	if m == nil {
		return 0
	}
	if f, ok := m[key].(float64); ok {
		return int64(f)
	}
	return 0
}

// asMap returns v as a map, decoding it first when a tool passed the input
// as a JSON string (seen with some MCP bridges).
func asMap(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return t
	case string:
		var m map[string]any
		if json.Unmarshal([]byte(t), &m) == nil {
			return m
		}
	}
	return nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return clip(s, maxErrorLen)
}

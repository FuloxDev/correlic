package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ClaudeToolMatcher selects the tools correlic-hook observes in Claude Code.
// A second entry with ClaudeMCPMatcher covers MCP tools (mcp__server__tool).
const (
	ClaudeToolMatcher = "Bash|Edit|Write|MultiEdit|NotebookEdit|Read|WebFetch"
	ClaudeMCPMatcher  = "mcp__.*"
)

// claudeHookEvents lists the Claude Code events the hook subscribes to and
// whether a tool matcher applies (session events take none).
var claudeHookEvents = []struct {
	event   string
	matched bool
}{
	{"PreToolUse", true},
	{"PostToolUse", true},
	{"PostToolUseFailure", true},
	{"SessionStart", false},
	{"SessionEnd", false},
}

// cursorHookEvents lists the Cursor events the hook subscribes to.
// beforeSubmitPrompt is left out on purpose: prompts are never recorded.
var cursorHookEvents = []string{
	"beforeShellExecution",
	"afterShellExecution",
	"beforeMCPExecution",
	"afterMCPExecution",
	"afterFileEdit",
	"beforeReadFile",
	"sessionStart",
	"sessionEnd",
}

// SetupOptions selects what `correlic-hook setup` writes.
type SetupOptions struct {
	Claude  bool   // ~/.claude/settings.json or <project>/.claude/settings.json
	Cursor  bool   // ~/.cursor/hooks.json or <project>/.cursor/hooks.json
	Project string // project directory; empty = the user-global files
	Binary  string // absolute path of correlic-hook to register
	Home    string // home directory (for the global files)
}

// SetupResult names the files written.
type SetupResult struct {
	ClaudeSettings string
	CursorHooks    string
}

// Setup merges the hook entries into the Claude Code and/or Cursor hook
// configuration without disturbing anything else in those files. It is
// idempotent: running it again (or after the binary moved) updates the
// existing correlic-hook entries in place.
func Setup(opts SetupOptions) (SetupResult, error) {
	var res SetupResult
	if !opts.Claude && !opts.Cursor {
		opts.Claude, opts.Cursor = true, true
	}
	if opts.Binary == "" {
		return res, errors.New("binary path is required")
	}
	base := opts.Home
	if opts.Project != "" {
		abs, err := filepath.Abs(opts.Project)
		if err != nil {
			return res, err
		}
		base = abs
	}
	if base == "" {
		return res, errors.New("home directory unknown; pass --project")
	}
	if opts.Claude {
		path := filepath.Join(base, ".claude", "settings.json")
		if err := mergeJSONFile(path, func(doc map[string]any) error {
			return mergeClaudeHooks(doc, opts.Binary)
		}); err != nil {
			return res, fmt.Errorf("claude: %w", err)
		}
		res.ClaudeSettings = path
	}
	if opts.Cursor {
		path := filepath.Join(base, ".cursor", "hooks.json")
		if err := mergeJSONFile(path, func(doc map[string]any) error {
			return mergeCursorHooks(doc, opts.Binary)
		}); err != nil {
			return res, fmt.Errorf("cursor: %w", err)
		}
		res.CursorHooks = path
	}
	return res, nil
}

// mergeJSONFile reads path (or starts from {}), applies fn and writes the
// result back with two-space indentation. Numbers are preserved verbatim.
func mergeJSONFile(path string, fn func(doc map[string]any) error) error {
	doc := map[string]any{}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(bytes.TrimSpace(raw)) > 0 {
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			if err := dec.Decode(&doc); err != nil {
				return fmt.Errorf("%s is not a JSON object: %w", path, err)
			}
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return err
	}
	if err := fn(doc); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

// IsHookCommand reports whether a hook command string runs correlic-hook
// (any path, with or without .exe).
func IsHookCommand(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	// First token of the command line; quoted paths are unquoted.
	first := cmd
	if strings.HasPrefix(first, `"`) {
		if end := strings.Index(first[1:], `"`); end >= 0 {
			first = first[1 : end+1]
		}
	} else if i := strings.IndexAny(first, " \t"); i >= 0 {
		first = first[:i]
	}
	base := strings.ToLower(BaseName(first))
	return base == "correlic-hook" || base == "correlic-hook.exe"
}

// --- Claude Code: {"hooks": {"PreToolUse": [{"matcher": "...", "hooks": [{"type": "command", "command": "..."}]}]}} ---

func mergeClaudeHooks(doc map[string]any, binary string) error {
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		if doc["hooks"] != nil {
			return errors.New(`"hooks" is not an object`)
		}
		hooks = map[string]any{}
		doc["hooks"] = hooks
	}
	for _, e := range claudeHookEvents {
		matchers := []string{""}
		if e.matched {
			matchers = []string{ClaudeToolMatcher, ClaudeMCPMatcher}
		}
		entries, _ := hooks[e.event].([]any)
		for _, matcher := range matchers {
			entries = upsertClaudeEntry(entries, matcher, binary)
		}
		hooks[e.event] = entries
	}
	return nil
}

func upsertClaudeEntry(entries []any, matcher string, binary string) []any {
	command := map[string]any{"type": "command", "command": binary}
	// 1. An entry with our matcher that already runs correlic-hook: update the path.
	// 2. An entry with our matcher: append our command to its hooks.
	// 3. Else: a new entry.
	var sameMatcher map[string]any
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		m, _ := entry["matcher"].(string)
		if m != matcher {
			continue
		}
		list, _ := entry["hooks"].([]any)
		for _, h := range list {
			hm, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if c, _ := hm["command"].(string); IsHookCommand(c) {
				hm["command"] = binary
				hm["type"] = "command"
				return entries
			}
		}
		if sameMatcher == nil {
			sameMatcher = entry
		}
	}
	if sameMatcher != nil {
		list, _ := sameMatcher["hooks"].([]any)
		sameMatcher["hooks"] = append(list, command)
		return entries
	}
	entry := map[string]any{"hooks": []any{command}}
	if matcher != "" {
		entry["matcher"] = matcher
	}
	return append(entries, entry)
}

// --- Cursor: {"version": 1, "hooks": {"beforeShellExecution": [{"command": "..."}]}} ---

func mergeCursorHooks(doc map[string]any, binary string) error {
	if _, ok := doc["version"]; !ok {
		doc["version"] = 1
	}
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		if doc["hooks"] != nil {
			return errors.New(`"hooks" is not an object`)
		}
		hooks = map[string]any{}
		doc["hooks"] = hooks
	}
	for _, event := range cursorHookEvents {
		entries, _ := hooks[event].([]any)
		updated := false
		for _, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if c, _ := entry["command"].(string); IsHookCommand(c) {
				entry["command"] = binary
				updated = true
				break
			}
		}
		if !updated {
			entries = append(entries, map[string]any{"command": binary})
		}
		hooks[event] = entries
	}
	return nil
}

package ai_pack

import (
	"fmt"
	"strings"

	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/ingest"
)

// AIToolCallSensitivePath fires when an AI coding tool, observed through
// correlic-hook (event type ai_tool_call from Claude Code or Cursor), runs a
// command or opens a file whose path matches the built-in suspicious-path
// patterns of the ingest sampler (SSH keys, cloud credentials, /etc/shadow,
// secrets, certificates, ...). It is the hook counterpart of
// ai.credential_access / ai.file_activity for hosts where no kernel agent
// sees the file open — in particular macOS.
//
// Only the pre event of a call is evaluated so a call is reported once; a
// call the hook denied is still reported (the attempt is the signal).
type AIToolCallSensitivePath struct{}

func (d *AIToolCallSensitivePath) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.tool_call_sensitive_path",
		Pack:            "ai",
		Name:            "AI Tool Call Sensitive Path",
		Severity:        "high",
		Description:     "AI coding tool (via correlic-hook) ran a command or accessed a file on a sensitive path: credentials, keys, system auth files, secrets",
		Tags:            []string{"ai", "hooks", "credentials", "sensitive-files"},
		MITRETechniques: []string{"T1552", "T1005"},
	}
}

func (d *AIToolCallSensitivePath) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"ai_tool_call"},
		WindowSecs: 0,
	}
}

func (d *AIToolCallSensitivePath) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt == nil || evt.Context == nil || evt.Process == nil {
		return nil
	}
	if phase, _ := evt.Context["phase"].(string); phase != "pre" && phase != "" {
		return nil
	}
	isAI, aiType, err := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if err != nil || !isAI {
		return nil
	}

	toolName, _ := evt.Context["tool_name"].(string)
	command, _ := evt.Context["command"].(string)
	filePath, _ := evt.Context["file_path"].(string)
	if filePath == "" && evt.Target != nil {
		filePath = evt.Target.FilePath
	}
	decision, _ := evt.Context["decision"].(string)

	var (
		matchedPath, pattern string
		signalType           string
		basePattern          string
	)
	switch {
	case filePath != "":
		if p, ok := ingest.MatchSuspiciousPath(filePath); ok {
			matchedPath, pattern = filePath, p
			signalType, basePattern = "file_activity", filePath
		}
	case command != "":
		for _, tok := range commandPathTokens(command) {
			if p, ok := ingest.MatchSuspiciousPath(tok); ok {
				matchedPath, pattern = tok, p
				signalType, basePattern = "command", truncate(command, 200)
				break
			}
		}
	}
	if matchedPath == "" {
		return nil
	}

	verb := "accessed"
	if command != "" {
		verb = "ran a command touching"
	}
	title := fmt.Sprintf("AI tool call touched sensitive path: %s", matchedPath)
	summary := fmt.Sprintf("%s %s %s via %s", aiType, verb, matchedPath, orUnknown(toolName))
	confidence := 0.75
	if decision == "blocked" {
		summary += " (denied by block rule)"
		confidence = 0.70
	}

	fctx := map[string]any{
		"ai_type":          aiType,
		"tool_name":        toolName,
		"hook_event":       evt.Context["hook_event"],
		"file_path":        matchedPath,
		"matched_pattern":  pattern,
		"decision":         decision,
		"pid":              evt.Process.PID,
		"comm":             evt.Process.Comm,
		"signal_type":      signalType,
		"pattern":          basePattern,
		"mitre_techniques": []string{"T1552", "T1005"},
	}
	if command != "" {
		fctx["cmdline"] = truncate(command, 500)
	}
	if sid, ok := evt.Context["ai_session_id"].(string); ok && sid != "" {
		fctx["session_id"] = sid
	}
	return []detection.Finding{{
		Title:      title,
		Summary:    summary,
		Confidence: confidence,
		Context:    fctx,
	}}
}

// commandPathTokens returns the whitespace-separated tokens of a command line
// that look like file paths (contain a separator or start with ~ or .), with
// quotes and VAR= prefixes stripped. Bare words such as `config` in
// `git config` are not tested so the broad substring patterns of the sampler
// do not fire on ordinary commands.
func commandPathTokens(command string) []string {
	var out []string
	for _, f := range strings.Fields(command) {
		f = strings.Trim(f, "\"'`")
		if f == "" || strings.HasPrefix(f, "-") || strings.Contains(f, "://") {
			continue
		}
		if i := strings.IndexByte(f, '='); i > 0 && !strings.ContainsAny(f[:i], "/\\~.") {
			f = f[i+1:]
		}
		if strings.ContainsAny(f, `/\`) || strings.HasPrefix(f, "~") || strings.HasPrefix(f, ".") {
			out = append(out, f)
		}
	}
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown tool"
	}
	return s
}

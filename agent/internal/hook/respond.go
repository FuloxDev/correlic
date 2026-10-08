package hook

import "encoding/json"

// DenyResponse renders the tool-specific "deny" document for a blockable
// event. It is the only thing the hook ever prints on stdout.
//
// Claude Code (PreToolUse):
//
//	{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}
//
// Cursor (beforeShellExecution / beforeMCPExecution / beforeReadFile):
//
//	{"permission":"deny","user_message":"...","agent_message":"..."}
//
// Nothing is printed when the call is allowed: for Claude Code an empty
// stdout means "no decision" so the user's normal permission flow still
// applies (an explicit "allow" would bypass it).
func DenyResponse(ev *ToolEvent, reason string) []byte {
	var doc any
	switch ev.Tool {
	case ToolCursor:
		doc = map[string]any{
			"permission":    "deny",
			"user_message":  reason,
			"agent_message": reason + " Choose another approach; do not retry the same call.",
		}
	default:
		doc = map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            ev.HookEvent,
				"permissionDecision":       "deny",
				"permissionDecisionReason": reason,
			},
		}
	}
	out, _ := json.Marshal(doc)
	return append(out, '\n')
}

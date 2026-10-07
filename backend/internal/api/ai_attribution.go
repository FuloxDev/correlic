package api

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/storage"
)

// exePaths considered risky for AI attribution (impersonation: binary in tmp etc.).
// We only flag when exe is present and in a bad path; empty exe is not flagged (common in
// Docker/containers and for event types that don't report exe, e.g. net_bind).
var suspiciousExePrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

func isSuspiciousExePath(exe string) bool {
	exe = strings.TrimSpace(strings.ToLower(exe))
	if exe == "" {
		return false
	}
	if exe == "/tmp" || exe == "/var/tmp" || exe == "/dev/shm" {
		return true
	}
	for _, p := range suspiciousExePrefixes {
		if strings.HasPrefix(exe, p) {
			return true
		}
	}
	// Relative path (no leading slash) — could be a binary in cwd
	if exe[0] != '/' {
		return true
	}
	return false
}

// fallbackAIProcessNeedles is used when database patterns are not available.
// This is a safety net - the primary source should be the ai_agent_patterns table.
var fallbackAIProcessNeedles = []string{
	"cursor",
	"copilot",
	"claude",
	"codeium",
	"tabnine",
	"aider",
	"continue",
	"antigravity",
}

// aiProcessNeedles is the active list of AI process patterns.
// Set via SetAIProcessNeedles on application startup from the database.
var aiProcessNeedles []string

// SetAIProcessNeedles sets the active AI process needles from the database.
// Should be called on application startup after loading patterns.
func SetAIProcessNeedles(needles []string) {
	if len(needles) > 0 {
		aiProcessNeedles = needles
	}
}

// getAIProcessNeedles returns the active patterns, falling back to defaults if not set.
func getAIProcessNeedles() []string {
	if len(aiProcessNeedles) > 0 {
		return aiProcessNeedles
	}
	return fallbackAIProcessNeedles
}

// buildAIPIDSet derives a set of PIDs that are AI-rooted or AI-descended for the given window.
// It uses:
// - process_exec (comm/pcomm/exe contains AI needles)
// - process_tree edges (parent_pid -> child_pid) to expand descendants
func buildAIPIDSet(
	store storage.TelemetryStore,
	orgID string,
	agentID string,
	since time.Time,
	until time.Time,
) map[int64]struct{} {
	if store == nil {
		return map[int64]struct{}{}
	}

	execEvents, _ := store.ListFiltered(orgID, storage.TelemetryListFilter{
		AgentID:   agentID,
		EventType: "process_exec",
		Since:     since,
		Until:     until,
		Limit:     1000,
		Offset:    0,
	})
	treeEvents, _ := store.ListFiltered(orgID, storage.TelemetryListFilter{
		AgentID:   agentID,
		EventType: "process_tree",
		Since:     since,
		Until:     until,
		Limit:     2000,
		Offset:    0,
	})

	aiPIDs := make(map[int64]struct{}, 256)
	children := make(map[int64][]int64, 512)

	// Seed AI roots from exec events.
	for _, ev := range execEvents {
		var p map[string]any
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			continue
		}
		candidates := []string{
			anyToLowerString(p["comm"]),
			anyToLowerString(p["process"]),
			anyToLowerString(p["pcomm"]),
			anyToLowerString(p["exe"]),
		}
		if !matchesAnyNeedle(candidates, getAIProcessNeedles()) {
			continue
		}
		if pid, ok := anyToInt64(p["pid"]); ok {
			aiPIDs[pid] = struct{}{}
		}
	}

	// Build process_tree adjacency and seed AI roots based on parent_comm.
	for _, ev := range treeEvents {
		var p map[string]any
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			continue
		}
		// Ignore summary rows.
		if strings.TrimSpace(anyToLowerString(p["event"])) == "tree_summary" {
			continue
		}

		parentPID, okP := anyToInt64(p["parent_pid"])
		childPID, okC := anyToInt64(p["child_pid"])
		if okP && okC {
			children[parentPID] = append(children[parentPID], childPID)
		}

		parentComm := anyToLowerString(p["parent_comm"])
		if parentComm != "" && matchesAnyNeedle([]string{parentComm}, getAIProcessNeedles()) {
			if okP {
				aiPIDs[parentPID] = struct{}{}
			}
			if okC {
				aiPIDs[childPID] = struct{}{}
			}
		}
	}

	// Expand descendants (BFS).
	queue := make([]int64, 0, len(aiPIDs))
	seenQueued := make(map[int64]struct{}, len(aiPIDs))
	for pid := range aiPIDs {
		queue = append(queue, pid)
		seenQueued[pid] = struct{}{}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, ch := range children[cur] {
			if _, ok := aiPIDs[ch]; ok {
				continue
			}
			aiPIDs[ch] = struct{}{}
			if _, ok := seenQueued[ch]; !ok {
				queue = append(queue, ch)
				seenQueued[ch] = struct{}{}
			}
		}
	}

	return aiPIDs
}

func eventMatchesAICandidates(payload map[string]any) bool {
	candidates := []string{
		anyToLowerString(payload["comm"]),
		anyToLowerString(payload["process"]),
		anyToLowerString(payload["pcomm"]),
		anyToLowerString(payload["parent_comm"]),
		anyToLowerString(payload["child_comm"]),
		anyToLowerString(payload["exe"]),
	}
	return matchesAnyNeedle(candidates, getAIProcessNeedles())
}

func payloadMatchesAIPIDs(payload map[string]any, aiPIDs map[int64]struct{}) bool {
	if len(aiPIDs) == 0 {
		return false
	}
	for _, k := range []string{"pid", "ppid", "parent_pid", "child_pid"} {
		if n, ok := anyToInt64(payload[k]); ok {
			if _, exists := aiPIDs[n]; exists {
				return true
			}
		}
	}
	return false
}

// IsSuspiciousAIAttribution returns true when the payload would be attributed to AI by name
// and the executable path is present and in an untrusted location (e.g. /tmp, relative path).
// Empty exe is not flagged (common in Docker and for event types that don't report exe).
func IsSuspiciousAIAttribution(payload map[string]any) bool {
	if payload == nil {
		return false
	}
	if !eventMatchesAICandidates(payload) {
		return false
	}
	exe := anyToLowerString(payload["exe"])
	return isSuspiciousExePath(exe)
}

func filterAIAttributedEvents(events []model.TelemetryEvent, aiPIDs map[int64]struct{}, limit int) []model.TelemetryEvent {
	if limit <= 0 {
		limit = 50
	}
	out := make([]model.TelemetryEvent, 0, len(events))
	for _, ev := range events {
		var payload map[string]any
		if err := json.Unmarshal(ev.Payload, &payload); err != nil {
			continue
		}
		if eventMatchesAICandidates(payload) || payloadMatchesAIPIDs(payload, aiPIDs) {
			out = append(out, ev)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

func anyToLowerString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.ToLower(strings.TrimSpace(t))
	default:
		return ""
	}
}

func matchesAnyNeedle(haystacks []string, needles []string) bool {
	for _, h := range haystacks {
		if h == "" {
			continue
		}
		for _, n := range needles {
			if n == "" {
				continue
			}
			if strings.Contains(h, n) {
				return true
			}
		}
	}
	return false
}

func anyToInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		if t <= 0 {
			return 0, false
		}
		return int64(t), true
	case int64:
		if t <= 0 {
			return 0, false
		}
		return t, true
	case int:
		if t <= 0 {
			return 0, false
		}
		return int64(t), true
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, false
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

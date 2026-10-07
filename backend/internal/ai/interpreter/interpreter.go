package interpreter

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/ai/tools"
)

// ErrUnparsedTimePhrase is returned when the question contains a time phrase (e.g. "minute") that could not be parsed.
// Caller should return 400; no silent fallback to default range.
var ErrUnparsedTimePhrase = errors.New("question contains a time phrase that could not be parsed; use e.g. 'last minute', 'last 5 minutes', 'last hour'")

// ErrWindowTooLarge is returned when the requested time range exceeds 24h. No silent widening.
// Use errors.As to detect; Error() includes the parsed window (e.g. "168h").
type ErrWindowTooLarge struct {
	Window time.Duration
}

func (e *ErrWindowTooLarge) Error() string {
	return fmt.Sprintf("time range too large (%s); max supported window is 24h", formatDurationHours(e.Window))
}

func formatDurationHours(d time.Duration) string {
	h := d.Round(time.Hour).Hours()
	if h == float64(int64(h)) {
		return fmt.Sprintf("%dh", int64(h))
	}
	return d.Round(time.Hour).String()
}

// Host scope rule: AI is not allowed to change or broaden host scope.
// Host scope is always provided by the caller (host_id in the request).
// The interpreter only selects a tool and fills since/until/pattern from the question.

// Interpret selects one tool and extracts params from the question. hostID is always from the caller.
// Returns tool name, params, and optionally an error. Default time range (24h) is only used when no time phrase exists.
// If the question contains a time phrase (e.g. "minute") and parsing fails, returns ErrUnparsedTimePhrase.
// Diff phrases ("what changed", "new since", etc.) map to diff_* tools with default windows: base now-2h→now-1h, compare now-1h→now.
func Interpret(question string, hostID string, now time.Time) (toolName string, params tools.Params, err error) {
	params.HostID = hostID
	now = now.UTC()
	if isDiffQuestion(question) {
		params.BaseSince = now.Add(-2 * time.Hour)
		params.BaseUntil = now.Add(-1 * time.Hour)
		params.CompareSince = now.Add(-1 * time.Hour)
		params.CompareUntil = now
		toolName = selectDiffTool(question)
		return toolName, params, nil
	}
	params.Since, params.Until = defaultTimeRange(now)
	since, until := parseTimePhrase(question, now)
	if hasTimeUnit(question) && since.IsZero() {
		return "", tools.Params{}, ErrUnparsedTimePhrase
	}
	if !since.IsZero() {
		params.Since = since
	}
	if !until.IsZero() {
		params.Until = until
	}
	if w := params.Until.Sub(params.Since); w > 24*time.Hour {
		return "", tools.Params{}, &ErrWindowTooLarge{Window: w}
	}
	params.Pattern = extractPattern(question)
	toolName = selectTool(question)
	return toolName, params, nil
}

// isDiffQuestion returns true if the question asks "what changed" / "new since" / "compared to" / "difference between".
func isDiffQuestion(q string) bool {
	q = strings.ToLower(q)
	phrases := []string{"what changed", "new since", "compared to", "difference between", "diff since", "changed since"}
	for _, p := range phrases {
		if strings.Contains(q, p) {
			return true
		}
	}
	return false
}

// selectDiffTool picks diff_processes, diff_connections, or diff_ports by keyword. Default: diff_processes.
func selectDiffTool(q string) string {
	q = strings.ToLower(q)
	switch {
	case strings.Contains(q, "port") || strings.Contains(q, "listen"):
		return "diff_ports"
	case strings.Contains(q, "connection") || strings.Contains(q, "external") || strings.Contains(q, " connect"):
		return "diff_connections"
	case strings.Contains(q, "process") || strings.Contains(q, "executable") || strings.Contains(q, " binary"):
		return "diff_processes"
	default:
		return "diff_processes"
	}
}

func defaultTimeRange(now time.Time) (since, until time.Time) {
	until = now.UTC()
	since = until.Add(-24 * time.Hour)
	return since, until
}

// hasTimeUnit reports whether the question mentions a time unit (minute, hour, today, day). Used to reject silent 24h fallback.
func hasTimeUnit(question string) bool {
	q := strings.ToLower(question)
	return strings.Contains(q, "minute") || strings.Contains(q, "hour") || strings.Contains(q, "today") || strings.Contains(q, "day")
}

// parseTimePhrase returns since/until. Prefer smallest explicit unit first (minute, then hour, then today).
func parseTimePhrase(q string, now time.Time) (since, until time.Time) {
	q = strings.ToLower(strings.TrimSpace(q))
	now = now.UTC()

	// Smallest unit first: minute(s)
	// "last minute" / "past minute"
	if strings.Contains(q, "last minute") || strings.Contains(q, "past minute") {
		return now.Add(-1 * time.Minute), now
	}
	// "last N minutes"
	if re := regexp.MustCompile(`last\s+(\d+)\s*minutes?`); re.MatchString(q) {
		matches := re.FindStringSubmatch(q)
		if len(matches) >= 2 {
			var n int
			if _, err := fmt.Sscanf(matches[1], "%d", &n); err == nil && n > 0 && n <= 10080 {
				return now.Add(-time.Duration(n) * time.Minute), now
			}
		}
	}
	// hour(s)
	// "last hour" / "past hour"
	if strings.Contains(q, "last hour") || strings.Contains(q, "past hour") {
		return now.Add(-1 * time.Hour), now
	}
	// "last N hours"
	if re := regexp.MustCompile(`last\s+(\d+)\s*hours?`); re.MatchString(q) {
		matches := re.FindStringSubmatch(q)
		if len(matches) >= 2 {
			var n int
			if _, err := fmt.Sscanf(matches[1], "%d", &n); err == nil && n > 0 && n <= 24 {
				return now.Add(-time.Duration(n) * time.Hour), now
			}
		}
	}
	// "last N days" -> parsed then capped by Interpret to 24h max (will return ErrWindowTooLarge if N > 1)
	if re := regexp.MustCompile(`last\s+(\d+)\s*days?`); re.MatchString(q) {
		matches := re.FindStringSubmatch(q)
		if len(matches) >= 2 {
			var n int
			if _, err := fmt.Sscanf(matches[1], "%d", &n); err == nil && n > 0 {
				return now.Add(-time.Duration(n) * 24 * time.Hour), now
			}
		}
	}
	// "today" -> start of today UTC to now
	if strings.Contains(q, "today") {
		y, m, d := now.Date()
		since = time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
		return since, now
	}
	return time.Time{}, time.Time{}
}

// selectTool picks one tool by keyword matching. Deterministic; no LLM.
func selectTool(q string) string {
	q = strings.ToLower(q)
	switch {
	case strings.Contains(q, "container") || strings.Contains(q, "docker"):
		return "list_containers"
	case strings.Contains(q, "port") || strings.Contains(q, "listen"):
		return "list_open_ports"
	case strings.Contains(q, "connection") || strings.Contains(q, "external") || strings.Contains(q, " connect") || strings.Contains(q, " ip"):
		return "list_external_connections"
	case strings.Contains(q, "process") || strings.Contains(q, "executable") || strings.Contains(q, " running") || strings.Contains(q, " binary"):
		return "list_processes_by_executable"
	default:
		return "list_containers" // safe default for "what happened" style questions
	}
}

// extractPattern tries to pull a short token (e.g. "python", "node") for list_processes_by_executable.
func extractPattern(q string) string {
	// Very simple: look for quoted string or a single word after "running" / "with" / "like"
	q = strings.TrimSpace(q)
	for _, sep := range []string{" running ", " with ", " like ", " matching "} {
		if i := strings.Index(strings.ToLower(q), sep); i >= 0 {
			rest := q[i+len(sep):]
			rest = strings.TrimSpace(rest)
			if end := strings.IndexAny(rest, " ?.,;"); end > 0 {
				rest = rest[:end]
			}
			rest = strings.Trim(rest, `"'`)
			if len(rest) > 0 && len(rest) < 80 {
				return rest
			}
		}
	}
	return ""
}

package ai_pack

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/detection"
)

const excessiveWriteWindow = 30 * time.Second

// Default thresholds — all configurable per-org via the detection rule settings API.
const (
	defaultProjectFileCount  = 20   // distinct project files to trigger
	defaultProjectFileRate   = 10.0 // files/sec required alongside count (rate gate)
	defaultSystemFileCount   = 5    // critical system files to trigger
	defaultSystemSpreadCount = 10   // files across ≥2 system scopes
)

var criticalSystemPathPrefixes = []string{
	"/etc/",
	"/usr/bin/",
	"/usr/local/bin/",
	"/usr/sbin/",
	"/sbin/",
	"/root/.ssh/",
	"/etc/cron.d/",
	"/var/spool/cron/",
	"/etc/sudoers.d/",
	"/boot/",
	"/lib/systemd/",
	"/usr/lib/systemd/",
	// Windows critical system paths (normalized to forward slashes)
	"C:/Windows/System32/",
	"C:/Windows/SysWOW64/",
	"C:/Windows/System32/drivers/",
	"C:/Windows/System32/Tasks/",
	"C:/Program Files/",
	"C:/Program Files (x86)/",
}

// AIExcessiveWrites detects when an AI agent writes to an unusually high number
// of distinct files within a short window, which may indicate mass modification.
type AIExcessiveWrites struct{}

func (d *AIExcessiveWrites) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.excessive_writes",
		Pack:            "ai",
		Name:            "AI Excessive File Writes",
		Severity:        "medium",
		Description:     "AI agent wrote to an unusually high number of files in a short time window",
		Tags:            []string{"ai", "file-write", "mass-modification"},
		MITRETechniques: []string{"T1485", "T1486"},
	}
}

func (d *AIExcessiveWrites) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"file_open"},
		WindowSecs: 30,
	}
}

func (d *AIExcessiveWrites) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt.Process == nil {
		return nil
	}

	// Check if the process belongs to an AI agent tree
	isAI, aiType, err := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if err != nil || !isAI {
		return nil
	}

	// Skip early if the triggering event is a read-only open (no write flags).
	// This avoids the Neo4j query entirely for pure reads.
	if !isWriteOpen(evt.Context) {
		return nil
	}

	// Look back in the window for file_open events from this PID
	since := evt.Timestamp.Add(-excessiveWriteWindow)
	recentWrites, err := ctx.GraphQuery.GetRecentEvents(
		ctx.Ctx, ctx.HostID, evt.Process.PID, since, []string{"file_open"},
	)
	if err != nil {
		return nil
	}

	// Only count file_open events that are actual writes (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND).
	// Read-only opens (O_RDONLY=0) are excluded — they are NOT file modifications.
	// Also exclude files in baselined directories (auto-learned or user-confirmed).
	distinctFiles := make(map[string]bool)
	for _, we := range recentWrites {
		if we.Target != nil && we.Target.FilePath != "" {
			if !isWriteOpen(we.Context) {
				continue
			}
			if ctx.Baselines != nil && ctx.Baselines.IsFileBaselined(ctx.OrgID, ctx.HostID, aiType, we.Target.FilePath) {
				continue
			}
			distinctFiles[we.Target.FilePath] = true
		}
	}
	// Include the current event — also must be a write
	if evt.Target != nil && evt.Target.FilePath != "" && isWriteOpen(evt.Context) {
		if ctx.Baselines == nil || !ctx.Baselines.IsFileBaselined(ctx.OrgID, ctx.HostID, aiType, evt.Target.FilePath) {
			distinctFiles[evt.Target.FilePath] = true
		}
	}

	if len(distinctFiles) == 0 {
		return nil
	}

	projectScopes := map[string]bool{}
	systemScopes := map[string]bool{}
	systemFiles := 0
	criticalSystemFiles := 0

	for file := range distinctFiles {
		scope := extractPathScope(file)
		if scope == "" {
			continue
		}
		if isProjectScope(file) {
			projectScopes[scope] = true
			continue
		}
		systemScopes[scope] = true
		systemFiles++
		if isCriticalSystemPath(file) {
			criticalSystemFiles++
		}
	}

	// Load per-org thresholds (fall back to constants if settings unavailable).
	criticalThreshold := defaultSystemFileCount
	spreadThreshold := defaultSystemSpreadCount
	projectCountThreshold := defaultProjectFileCount
	projectRateThreshold := defaultProjectFileRate
	if ctx.RuleSettings != nil {
		criticalThreshold = ctx.RuleSettings.GetInt(ctx.OrgID, "ai.excessive_writes", "system_file_count", defaultSystemFileCount)
		spreadThreshold = ctx.RuleSettings.GetInt(ctx.OrgID, "ai.excessive_writes", "system_spread_count", defaultSystemSpreadCount)
		projectCountThreshold = ctx.RuleSettings.GetInt(ctx.OrgID, "ai.excessive_writes", "project_file_count", defaultProjectFileCount)
		projectRateThreshold = ctx.RuleSettings.GetFloat(ctx.OrgID, "ai.excessive_writes", "project_file_rate", defaultProjectFileRate)
	}

	// Compute write rate: distinct files per second across the observed window.
	// Used as an additional gate for the project-only tier to suppress slow,
	// deliberate coding-agent writes (e.g. scaffolding a project over 30s).
	var fileRate float64
	if len(recentWrites) > 0 {
		earliest := recentWrites[0].Timestamp
		for _, we := range recentWrites {
			if we.Timestamp.Before(earliest) {
				earliest = we.Timestamp
			}
		}
		elapsed := evt.Timestamp.Sub(earliest).Seconds()
		if elapsed < 1.0 {
			elapsed = 1.0 // sub-second burst: treat as 1s to avoid div-by-zero
		}
		fileRate = float64(len(distinctFiles)) / elapsed
	} else {
		// Only the current event — rate is count/1s.
		fileRate = float64(len(distinctFiles))
	}

	totalFiles := len(distinctFiles)
	severity := ""
	reason := ""
	confidence := 0.0
	switch {
	case criticalSystemFiles >= criticalThreshold:
		severity = "critical"
		reason = "high-risk system paths modified"
		confidence = 0.90
	case systemFiles >= spreadThreshold && len(systemScopes) >= 2:
		severity = "high"
		reason = "writes spread across multiple system scopes"
		confidence = 0.75
	case systemFiles >= 3 && len(projectScopes) >= 1:
		severity = "medium"
		reason = "mixed project and system modification"
		confidence = 0.60
	case totalFiles >= projectCountThreshold && len(systemScopes) == 0 && len(projectScopes) == 1:
		// Rate gate: slow, deliberate project writes (e.g. coding agent) are not suspicious.
		if fileRate < projectRateThreshold {
			return nil
		}
		severity = "low"
		reason = "high-volume rapid project-only writes"
		confidence = 0.35
	default:
		return nil
	}

	// Collect related event IDs
	var relatedIDs []string
	for _, we := range recentWrites {
		relatedIDs = append(relatedIDs, we.ID)
	}

	// Collect file paths for display (cap at 100 to avoid bloating the finding).
	filePaths := make([]string, 0, len(distinctFiles))
	for f := range distinctFiles {
		filePaths = append(filePaths, f)
	}
	if len(filePaths) > 100 {
		filePaths = filePaths[:100]
	}

	fctx := map[string]any{
		"ai_type":               aiType,
		"file_count":            totalFiles,
		"window_seconds":        int(excessiveWriteWindow.Seconds()),
		"pid":                   evt.Process.PID,
		"comm":                  evt.Process.Comm,
		"path_diversity":        len(projectScopes) + len(systemScopes),
		"project_scope_count":   len(projectScopes),
		"system_scope_count":    len(systemScopes),
		"system_file_count":     systemFiles,
		"critical_system_files": criticalSystemFiles,
		"system_scopes":         mapKeys(systemScopes),
		"project_scopes":        mapKeys(projectScopes),
		"file_rate":             fmt.Sprintf("%.1f files/sec", fileRate),
		"reason":                reason,
		"files":                 filePaths,
		"signal_type":           "file_write_burst",
		"pattern":               fmt.Sprintf("pid:%d:%s", evt.Process.PID, reason),
	}
	if evt.Process.SessionID != "" {
		fctx["session_id"] = evt.Process.SessionID
	}

	// Per-finding MITRE based on write pattern.
	if criticalSystemFiles > 0 {
		fctx["mitre_techniques"] = []string{"T1485"} // Data Destruction
	} else if systemFiles > 0 {
		fctx["mitre_techniques"] = []string{"T1565.001"} // Stored Data Manipulation
	} else {
		fctx["mitre_techniques"] = []string{"T1486"} // Data Encrypted for Impact
	}

	return []detection.Finding{
		{
			Severity:      severity,
			Confidence:    confidence,
			Title:         fmt.Sprintf("AI agent wrote to %d files in %v", totalFiles, excessiveWriteWindow),
			Summary:       fmt.Sprintf("%s modified %d distinct files within %v (%s)", aiType, totalFiles, excessiveWriteWindow, reason),
			RelatedEvents: relatedIDs,
			Context:       fctx,
		},
	}
}

func extractPathScope(path string) string {
	if path == "" {
		return ""
	}
	cleanPath := filepath.ToSlash(filepath.Clean(path))
	if cleanPath == "." || cleanPath == "/" {
		return ""
	}
	if !strings.HasPrefix(cleanPath, "/") {
		parts := strings.Split(cleanPath, "/")
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return parts[0]
	}
	parts := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	if len(parts) >= 2 {
		return "/" + parts[0] + "/" + parts[1]
	}
	return "/" + parts[0]
}

func isProjectScope(path string) bool {
	cleanPath := filepath.ToSlash(filepath.Clean(path))
	return strings.HasPrefix(cleanPath, "/home/") ||
		strings.HasPrefix(cleanPath, "/tmp/") ||
		strings.HasPrefix(cleanPath, "C:/Users/") || // Windows home directories
		strings.HasPrefix(cleanPath, "C:/Temp/") || // Windows temp
		!strings.HasPrefix(cleanPath, "/")
}

func isCriticalSystemPath(path string) bool {
	cleanPath := filepath.ToSlash(filepath.Clean(path))
	for _, prefix := range criticalSystemPathPrefixes {
		if strings.HasPrefix(cleanPath, prefix) {
			return true
		}
	}
	return false
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

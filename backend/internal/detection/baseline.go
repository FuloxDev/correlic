package detection

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/correlic/correlic-backend/internal/enrichment"
	"github.com/correlic/correlic-backend/internal/event"
)

const (
	// observedBaselineTTL is how long an auto-observed baseline stays active.
	// After this period without being seen again, the baseline no longer suppresses findings.
	observedBaselineTTL = 30 * 24 * time.Hour // 30 days

	// observedBaselineThreshold is the minimum number of clean observations before
	// an auto-observed baseline becomes active for suppression. This prevents a single
	// benign event from immediately suppressing future detections.
	observedBaselineThreshold = 5
)

// baselineEntry represents a single cached baseline record.
type baselineEntry struct {
	ID         int
	OrgID      string
	HostID     string
	AIType     string
	SignalType string
	Pattern    string
	Source     string // "observed" or "user_confirmed"
	HitCount   int
	LastSeen   time.Time
	ExpiresAt  *time.Time // nil = never expires (observed uses TTL, user_confirmed = permanent)
}

// BaselineEntry is the exported view of a baseline record.
// Used by the dossier builder to summarize behavioral context per host.
type BaselineEntry struct {
	ID         int
	HostID     string
	AIType     string
	SignalType string
	Pattern    string
	Source     string
	HitCount   int
	LastSeen   time.Time
}

// ListForHost returns all non-expired baseline entries for an org+host from the
// in-memory cache. The result is a flat slice — callers filter by exe_path or
// signal_type as needed. Returns nil if BaselineCollector is nil.
func (bc *BaselineCollector) ListForHost(orgID, hostID string) []BaselineEntry {
	if bc == nil {
		return nil
	}
	bc.mu.RLock()
	orgEntries := bc.byOrg[orgID]
	bc.mu.RUnlock()

	if len(orgEntries) == 0 {
		return nil
	}

	var result []BaselineEntry
	for _, e := range orgEntries {
		if hostID != "" && e.HostID != hostID && e.HostID != "*" {
			continue
		}
		if isExpired(e) {
			continue
		}
		result = append(result, BaselineEntry{
			ID:         e.ID,
			HostID:     e.HostID,
			AIType:     e.AIType,
			SignalType: e.SignalType,
			Pattern:    e.Pattern,
			Source:     e.Source,
			HitCount:   e.HitCount,
			LastSeen:   e.LastSeen,
		})
	}
	return result
}

// ExclusionEntry represents a baseline exclusion record returned by the API.
type ExclusionEntry struct {
	ID         int       `json:"id"`
	OrgID      string    `json:"org_id"`
	HostID     string    `json:"host_id"`
	AIType     string    `json:"ai_type"`
	SignalType string    `json:"signal_type"`
	Pattern    string    `json:"pattern"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
}

// BaselineCollector passively observes clean events and builds behavioral baselines.
// It is detection-gated: only events that triggered zero detection rules are observed.
// Additionally, events matching the never-baseline list are excluded.
//
// Baselines are cached in memory and refreshed every 30 seconds for fast matching.
// Exclusions are also cached: when a user deletes a baseline, an exclusion record
// prevents Observe() from auto-recreating it.
// All operations are org-scoped for multi-tenant isolation.
type BaselineCollector struct {
	db *sql.DB

	mu              sync.RWMutex
	byOrg           map[string]map[string]baselineEntry // orgID → cacheKey → entry
	exclusionsByOrg map[string]map[string]bool          // orgID → cacheKey → true
	done            chan struct{}
	gcCounter       int // counts ticks for periodic expired baseline cleanup

	// neverChecker is the user-defined never-baseline store (nil-safe).
	// Injected after construction via SetNeverBaselineChecker().
	neverChecker NeverBaselineChecker
}

// SetNeverBaselineChecker injects the user-defined never-baseline store.
// Call this after construction before the pipeline starts.
func (bc *BaselineCollector) SetNeverBaselineChecker(c NeverBaselineChecker) {
	if bc == nil {
		return
	}
	bc.neverChecker = c
}

// cacheKey builds the lookup key for a baseline entry.
// Patterns are lowercased for file-related signal types because Windows paths
// are case-insensitive (C:/Users/ == C:/users/). This is safe on Linux too
// since Linux file systems are case-sensitive and patterns will already be
// consistent case from the agent.
func cacheKey(signalType, pattern, hostID, aiType string) string {
	if isFileSignalType(signalType) {
		pattern = strings.ToLower(pattern)
	}
	return signalType + "\x00" + pattern + "\x00" + hostID + "\x00" + aiType
}

func isFileSignalType(st string) bool {
	switch st {
	case "file_pattern", "file_activity", "credential_file", "persistence_path",
		"code_tamper", "file_write_burst", "command_file":
		return true
	}
	return false
}

// NewBaselineCollector creates a new baseline collector with in-memory cache
// and starts a background refresh goroutine.
func NewBaselineCollector(db *sql.DB) *BaselineCollector {
	bc := &BaselineCollector{
		db:              db,
		byOrg:           make(map[string]map[string]baselineEntry),
		exclusionsByOrg: make(map[string]map[string]bool),
		done:            make(chan struct{}),
	}
	if err := bc.reload(context.Background()); err != nil {
		log.Printf("WARN: baseline_collector initial load failed: %v", err)
	}
	go bc.backgroundRefresh()
	return bc
}

// Stop signals the background refresh goroutine to exit.
func (bc *BaselineCollector) Stop() {
	close(bc.done)
}

func (bc *BaselineCollector) backgroundRefresh() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-bc.done:
			return
		case <-ticker.C:
			if err := bc.reload(context.Background()); err != nil {
				log.Printf("WARN: baseline_collector refresh failed: %v", err)
			}
			// Every 10th tick (~5 minutes), resume baselines whose suspension has expired
			// by clearing expires_at so they become active again.
			bc.gcCounter++
			if bc.gcCounter%10 == 0 {
				if _, err := bc.db.Exec(`UPDATE behavioral_baselines SET expires_at = NULL WHERE expires_at IS NOT NULL AND expires_at < NOW()`); err != nil {
					log.Printf("WARN: baseline suspension GC failed: %v", err)
				}
			}
		}
	}
}

func (bc *BaselineCollector) reload(ctx context.Context) error {
	// Load baselines
	rows, err := bc.db.QueryContext(ctx,
		`SELECT id, COALESCE(org_id,'') as org_id, host_id, ai_type, signal_type, pattern, source, hit_count, last_seen, expires_at
		 FROM behavioral_baselines`)
	if err != nil {
		return fmt.Errorf("query behavioral_baselines: %w", err)
	}
	defer rows.Close()

	byOrg := make(map[string]map[string]baselineEntry)
	for rows.Next() {
		var e baselineEntry
		if err := rows.Scan(&e.ID, &e.OrgID, &e.HostID, &e.AIType,
			&e.SignalType, &e.Pattern, &e.Source, &e.HitCount, &e.LastSeen, &e.ExpiresAt); err != nil {
			continue
		}
		orgEntries, ok := byOrg[e.OrgID]
		if !ok {
			orgEntries = make(map[string]baselineEntry)
			byOrg[e.OrgID] = orgEntries
		}
		orgEntries[cacheKey(e.SignalType, e.Pattern, e.HostID, e.AIType)] = e
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// Load exclusions
	exclRows, err := bc.db.QueryContext(ctx,
		`SELECT org_id, host_id, ai_type, signal_type, pattern FROM baseline_exclusions`)
	if err != nil {
		// Non-fatal: exclusions table may not exist yet (pre-migration)
		log.Printf("WARN: baseline_exclusions load failed (table may not exist yet): %v", err)
		bc.mu.Lock()
		bc.byOrg = byOrg
		bc.mu.Unlock()
		return nil
	}
	defer exclRows.Close()

	exclusionsByOrg := make(map[string]map[string]bool)
	for exclRows.Next() {
		var orgID, hostID, aiType, signalType, pattern string
		if err := exclRows.Scan(&orgID, &hostID, &aiType, &signalType, &pattern); err != nil {
			continue
		}
		orgExcl, ok := exclusionsByOrg[orgID]
		if !ok {
			orgExcl = make(map[string]bool)
			exclusionsByOrg[orgID] = orgExcl
		}
		orgExcl[cacheKey(signalType, pattern, hostID, aiType)] = true
	}

	bc.mu.Lock()
	bc.byOrg = byOrg
	bc.exclusionsByOrg = exclusionsByOrg
	bc.mu.Unlock()
	return nil
}

// ShouldBaseline determines if an event is safe to add to the behavioral baseline.
// Returns false if:
//   - The event triggered any detection findings
//   - The event matches the never-baseline list
func ShouldBaseline(evt *event.Event, findings []Finding) bool {
	// Rule 1: Detection triggered → never auto-baseline
	if len(findings) > 0 {
		return false
	}

	// Rule 2: Never-baseline list → never auto-baseline
	if IsNeverBaselineEvent(evt) {
		return false
	}

	return true
}

// Observe extracts behavioral patterns from a clean event and upserts them into
// the behavioral_baselines table. Called only when ShouldBaseline returns true.
func (bc *BaselineCollector) Observe(orgID string, evt *event.Event) {
	if bc == nil || evt == nil {
		return
	}

	hostID := evt.HostID

	// Determine AI type from event context (if attributed)
	aiType := ""
	if ctx := evt.Context; ctx != nil {
		if v, ok := ctx["ai_type"].(string); ok {
			aiType = v
		}
	}

	var signalType, pattern string

	switch evt.Type {
	case "file_open", "file_write":
		if evt.Target == nil || evt.Target.FilePath == "" {
			return
		}
		// Skip non-existent files — these are path resolution probes, not real
		// file accesses. Common source: Git Bash (MSYS2) paths like /c/Users/...
		// get resolved by Windows as C:\c\Users\... which doesn't exist. ETW
		// still fires NameCreate events for each intermediate directory lookup.
		// Without this check, phantom paths pollute the baselines table.
		if ctx := evt.Context; ctx != nil {
			if fe, ok := ctx["file_exists"]; ok {
				if fe == false || fe == "false" {
					return
				}
			}
		}
		signalType = "file_pattern"
		// Baseline the exact file path. Directory-level globs are only created
		// via user-confirmed baselines ("Allow Always"). Auto-observed baselines
		// require observedBaselineThreshold clean hits before suppressing.
		pattern = evt.Target.FilePath

	case "process_exec":
		// Do NOT auto-baseline binary executions. The ai.unauthorized_exec rule
		// only fires for a specific blocklist of suspicious binaries. Non-blocklisted
		// binaries (claude, cursor, git, etc.) can never trigger a finding, so
		// auto-baselining them creates noise that suppresses nothing.
		// Binary baselines are only useful as user_confirmed (via "Allow Always").
		return

	case "net_connect":
		if evt.Target == nil || evt.Target.IP == "" {
			return
		}
		signalType = "network_dest"

		patternIP := evt.Target.IP
		info := enrichment.GlobalEnricher.GetNetInfo(context.Background(), evt.Target.IP)
		if info.BGPPrefix != "" {
			patternIP = info.BGPPrefix
		} else {
			ip := net.ParseIP(evt.Target.IP)
			if ip != nil && ip.To4() != nil {
				ip = ip.To4()
				patternIP = fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
			}
		}

		if evt.Target.Port > 0 {
			pattern = patternIP + ":" + fmt.Sprintf("%d", evt.Target.Port)
		} else {
			pattern = patternIP
		}

	case "net_dns":
		if evt.Target == nil {
			return
		}
		signalType = "dns_domain"
		domain := ""
		if evt.Target.Domain != "" {
			domain = evt.Target.Domain
		}
		if domain == "" {
			return
		}
		pattern = domain

	default:
		return
	}

	// Check exclusion list: if user explicitly deleted this baseline, do not re-create it
	key := cacheKey(signalType, pattern, hostID, aiType)
	bc.mu.RLock()
	excluded := bc.exclusionsByOrg[orgID][key]
	bc.mu.RUnlock()
	if excluded {
		return
	}

	// Skip auto-learning files already covered by a parent directory baseline.
	// e.g. if /home/fulox/go/** is baselined, don't create individual baselines
	// for /home/fulox/go/pkg/mod/file.go.
	if signalType == "file_pattern" {
		if bc.IsFileBaselined(orgID, hostID, aiType, pattern) {
			return
		}
	}

	bc.upsert(orgID, hostID, aiType, signalType, pattern, "observed", nil)
}

// isExpired checks if a baseline entry should NOT be used for suppression.
// A baseline is "expired" (inactive) in these cases:
//  1. It has an expires_at in the FUTURE → it is suspended (temporarily disabled)
//  2. It has an expires_at in the PAST → the suspension expired AND the GC will
//     clean it up, but until then treat as expired so it doesn't re-suppress
//  3. Auto-observed baselines without explicit expiry use a 30-day TTL
//
// After a suspension's expires_at passes, the background GC removes the expires_at
// or deletes the row, and the baseline returns to its normal active state on next reload.
func isExpired(entry baselineEntry) bool {
	if entry.ExpiresAt != nil {
		// Any baseline with an explicit expires_at is inactive:
		// - Future expires_at = suspended (user chose to temporarily disable)
		// - Past expires_at = suspension period over, GC will clean up shortly.
		//   For suspended baselines (future dates), we clear expires_at on expiry
		//   so the baseline resumes. Until GC runs, treat as still active after expiry.
		now := time.Now()
		if now.Before(*entry.ExpiresAt) {
			// Suspended: expires_at is in the future → don't match
			return true
		}
		// expires_at is in the past → suspension has ended, baseline is active again
		return false
	}
	if entry.Source != "user_confirmed" {
		// Threshold gate: auto-observed baselines require N clean observations
		// before they become active for suppression. This prevents a single
		// benign event from immediately suppressing future detections.
		if entry.HitCount < observedBaselineThreshold {
			return true
		}
		// TTL for auto-observed baselines (no explicit expiry set)
		if time.Since(entry.LastSeen) > observedBaselineTTL {
			return true
		}
	}
	return false
}

// MatchesBaseline checks if a finding matches an existing baseline pattern.
// Uses the in-memory cache for O(1) lookup instead of per-finding SQL queries.
// Observed baselines expire after 30 days; user-confirmed baselines never expire
// unless an explicit expires_at is set.
// Returns (matched, patternDescription).
func (bc *BaselineCollector) MatchesBaseline(orgID string, f Finding) (bool, string) {
	if bc == nil {
		return false, ""
	}

	// Extract the signal type and pattern from the finding context
	signalType := ""
	pattern := ""

	if ctx := f.Context; ctx != nil {
		if v, ok := ctx["signal_type"].(string); ok {
			signalType = v
		}
		if v, ok := ctx["pattern"].(string); ok {
			pattern = v
		}
	}

	if signalType == "" || pattern == "" {
		return false, ""
	}

	aiType := ""
	if v, ok := f.Context["ai_type"].(string); ok {
		aiType = v
	}

	// Try all combinations: (exact host, scoped agent) → (exact host, any agent) →
	// (wildcard host, scoped agent) → (wildcard host, any agent)
	bc.mu.RLock()
	orgEntries := bc.byOrg[orgID]
	bc.mu.RUnlock()

	hosts := []string{f.HostID}
	if f.HostID != "*" {
		hosts = append(hosts, "*")
	}
	agents := []string{aiType}
	if aiType != "" {
		agents = append(agents, "")
	}

	var entry baselineEntry
	exists := false
	bc.mu.RLock()
	for _, h := range hosts {
		for _, a := range agents {
			if e, ok := orgEntries[cacheKey(signalType, pattern, h, a)]; ok {
				entry = e
				exists = true
				break
			}
		}
		if exists {
			break
		}
	}
	bc.mu.RUnlock()

	if !exists {
		// For file patterns, walk up directory tree to check parent globs
		if signalType == "file_pattern" || signalType == "credential_file" || signalType == "persistence_path" || signalType == "code_tamper" || signalType == "file_write_burst" || signalType == "file_activity" || signalType == "keyword_heuristic" {
			if bc.IsFileBaselined(orgID, f.HostID, aiType, pattern) {
				return true, signalType + ":" + pattern + " (parent dir baselined)"
			}
			// For non-file_pattern signal types, also check directory baselines
			// stored under that signal type (e.g. file_activity dir globs).
			if signalType != "file_pattern" {
				if bc.isFileBaselinedForSignalType(orgID, f.HostID, aiType, pattern, signalType) {
					return true, signalType + ":" + pattern + " (parent dir baselined)"
				}
			}
		}

		// For any command-based finding (has "binary" in context), check additional baselines:
		// 1. command_binary: user baselined the binary name (any invocation suppressed)
		// 2. command_file: user baselined the script file path
		if binary, ok := f.Context["binary"].(string); ok && binary != "" {
			if bc.isBinaryBaselined(orgID, f.HostID, aiType, binary) {
				return true, "command_binary:" + binary
			}
		}
		if filePath, ok := f.Context["file_path"].(string); ok && filePath != "" {
			if bc.isCommandFileBaselined(orgID, f.HostID, aiType, filePath) {
				return true, "command_file:" + filePath
			}
		}

		return false, ""
	}

	if isExpired(entry) {
		return false, ""
	}

	return true, signalType + ":" + pattern
}

// matchBaseline tries all host+agent combinations for a cache lookup:
// (exact host, scoped agent) → (exact host, any agent) → (wildcard host, scoped agent) → (wildcard host, any agent)
func (bc *BaselineCollector) matchBaseline(orgEntries map[string]baselineEntry, signalType, pattern, hostID, aiType string) bool {
	hosts := []string{hostID}
	if hostID != "*" {
		hosts = append(hosts, "*")
	}
	agents := []string{aiType}
	if aiType != "" {
		agents = append(agents, "")
	}

	bc.mu.RLock()
	defer bc.mu.RUnlock()

	for _, h := range hosts {
		for _, a := range agents {
			if entry, ok := orgEntries[cacheKey(signalType, pattern, h, a)]; ok {
				if !isExpired(entry) {
					return true
				}
			}
		}
	}
	return false
}

// isBinaryBaselined checks if a binary name has a command_binary baseline entry.
// When a user clicks "Allow Binary", any command finding for that binary is suppressed.
func (bc *BaselineCollector) isBinaryBaselined(orgID, hostID, aiType, binary string) bool {
	bc.mu.RLock()
	orgEntries := bc.byOrg[orgID]
	bc.mu.RUnlock()

	return bc.matchBaseline(orgEntries, "command_binary", binary, hostID, aiType)
}

// isCommandFileBaselined checks if a file path has a command_file baseline entry.
func (bc *BaselineCollector) isCommandFileBaselined(orgID, hostID, aiType, filePath string) bool {
	bc.mu.RLock()
	orgEntries := bc.byOrg[orgID]
	bc.mu.RUnlock()

	return bc.matchBaseline(orgEntries, "command_file", filePath, hostID, aiType)
}

// slashDir returns the parent directory of a forward-slash path without using
// filepath.Dir, which converts separators to the OS default on Windows.
// e.g. "C:/Users/foo/bar.go" → "C:/Users/foo", "C:/Users/foo" → "C:/Users"
func slashDir(p string) string {
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "/"
	}
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return "."
	}
	if i == 0 {
		return "/"
	}
	return p[:i]
}

// IsFileBaselined checks if a file path has been baselined.
// Checks both exact file path baselines (auto-observed) and directory glob
// baselines (user-confirmed via "Allow Always"). Used by detection rules
// (e.g. ai.excessive_writes) to exclude writes to known-good files/directories.
func (bc *BaselineCollector) IsFileBaselined(orgID, hostID, aiType, filePath string) bool {
	if bc == nil || filePath == "" {
		return false
	}

	// Normalize to forward slashes so directory walking matches stored baselines
	// on both Linux and Windows (Windows filepath.Dir converts to backslashes).
	filePath = filepath.ToSlash(filePath)

	bc.mu.RLock()
	orgEntries := bc.byOrg[orgID]
	bc.mu.RUnlock()

	if len(orgEntries) == 0 {
		return false
	}

	// Check 1: Exact file path (auto-observed baselines)
	if bc.checkFileBaseline(orgEntries, filePath, hostID, aiType) {
		return true
	}

	// Check 2: Walk up the directory tree checking for glob patterns (/dir/**)
	// and exact directory paths (/dir/) that may have been confirmed via UI.
	// e.g. for /home/fulox/.config/Code/settings.json, checks:
	//   /home/fulox/.config/Code/**  and  /home/fulox/.config/Code/
	//   /home/fulox/.config/**       and  /home/fulox/.config/
	//   /home/fulox/**               and  /home/fulox/
	//   /home/**                     and  /home/
	dir := slashDir(filePath)
	for dir != "/" && dir != "." {
		dirPattern := dir + "/**"
		if bc.checkFileBaseline(orgEntries, dirPattern, hostID, aiType) {
			return true
		}
		// Also check exact directory path (e.g. "/home/fulox/.config/") —
		// baselines confirmed via UI may store the trailing-slash form.
		dirExact := dir + "/"
		if bc.checkFileBaseline(orgEntries, dirExact, hostID, aiType) {
			return true
		}
		parent := slashDir(dir)
		if parent == dir {
			break // reached volume root (e.g. "C:/"), prevent infinite loop
		}
		dir = parent
	}

	return false
}

// checkFileBaseline looks up a specific pattern in the org's baseline cache,
// trying both the scoped aiType and the unscoped (empty) aiType.
// Directory baselines are always stored as signal_type="file_pattern" (from the UI),
// so this function uses "file_pattern" for the cache key.
func (bc *BaselineCollector) checkFileBaseline(orgEntries map[string]baselineEntry, pattern, hostID, aiType string) bool {
	return bc.matchBaseline(orgEntries, "file_pattern", pattern, hostID, aiType)
}

// isFileBaselinedForSignalType checks if a file path has a directory glob
// baseline stored under a specific signal type (e.g. "file_activity").
// This complements IsFileBaselined which only checks "file_pattern" baselines.
func (bc *BaselineCollector) isFileBaselinedForSignalType(orgID, hostID, aiType, filePath, signalType string) bool {
	if bc == nil || filePath == "" {
		return false
	}

	filePath = filepath.ToSlash(filePath)

	bc.mu.RLock()
	orgEntries := bc.byOrg[orgID]
	bc.mu.RUnlock()

	if len(orgEntries) == 0 {
		return false
	}

	// Walk up directory tree checking for glob patterns under this signal type
	// and exact directory paths (trailing-slash form), mirroring IsFileBaselined().
	dir := slashDir(filePath)
	for dir != "/" && dir != "." {
		dirPattern := dir + "/**"
		if bc.checkBaselineForType(orgEntries, signalType, dirPattern, hostID, aiType) {
			return true
		}
		dirExact := dir + "/"
		if bc.checkBaselineForType(orgEntries, signalType, dirExact, hostID, aiType) {
			return true
		}
		parent := slashDir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false
}

// checkBaselineForType looks up a specific signal_type+pattern in the cache.
func (bc *BaselineCollector) checkBaselineForType(orgEntries map[string]baselineEntry, signalType, pattern, hostID, aiType string) bool {
	return bc.matchBaseline(orgEntries, signalType, pattern, hostID, aiType)
}

// LearnFromFinding adds a finding's pattern as a user-confirmed baseline.
// Called when a user marks a finding as "allowed".
// expiresAt is optional: nil = permanent, non-nil = temporary baseline.
// Returns an error if the pattern is on the never-baseline list (security-critical).
func (bc *BaselineCollector) LearnFromFinding(orgID, hostID string, findingContext map[string]any, expiresAt *time.Time) error {
	if bc == nil || findingContext == nil {
		return nil
	}

	signalType, _ := findingContext["signal_type"].(string)
	pattern, _ := findingContext["pattern"].(string)
	if signalType == "" || pattern == "" {
		log.Printf("WARN: baseline learn skipped — finding has no signal_type/pattern in context")
		return nil
	}

	// Normalize Windows backslash paths to forward-slash before storing.
	pattern = filepath.ToSlash(pattern)

	// Security gate: reject baselines for patterns that should never be suppressed.
	// Checks both hardcoded system rules and user-defined org rules.
	if IsNeverBaselinePattern(signalType, pattern, bc.neverChecker, orgID) {
		isUserDefined := bc.neverChecker != nil && bc.neverChecker.MatchesAny(orgID, signalType, pattern)
		log.Printf("WARN: baseline learn REJECTED (never-baseline, user_defined=%v): signal=%s pattern=%s", isUserDefined, signalType, pattern)
		if isUserDefined {
			return fmt.Errorf("cannot baseline %s:%s — pattern is on your organization's Never-Baseline list; remove it there first: user_defined=true", signalType, pattern)
		}
		return fmt.Errorf("cannot baseline %s:%s — pattern is on the never-baseline list (security-critical)", signalType, pattern)
	}

	// Use the ai_type from the finding context if provided.
	// Empty ai_type = agent-agnostic (applies to all agents).
	// When a specific agent is given (e.g. "claude_code"), the baseline only
	// covers that agent — other agents' baselines remain unaffected.
	aiType, _ := findingContext["ai_type"].(string)

	// Remove any existing exclusion for this pattern — user is explicitly re-allowing it
	bc.removeExclusion(orgID, hostID, aiType, signalType, pattern)

	bc.upsert(orgID, hostID, aiType, signalType, pattern, "user_confirmed", expiresAt)
	log.Printf("Baseline learned from user feedback: org=%s signal=%s pattern=%s source=user_confirmed expires=%v",
		orgID, signalType, pattern, expiresAt)
	_ = bc.reload(context.Background()) // immediately make new baseline visible in cache
	return nil
}

// DeleteBaseline removes a baseline by ID (org-scoped for safety), records an
// exclusion to prevent auto-re-creation, and reloads the cache.
func (bc *BaselineCollector) DeleteBaseline(ctx context.Context, orgID string, id int) error {
	if bc == nil {
		return fmt.Errorf("baseline collector is nil")
	}

	// Read baseline details before deleting so we can create an exclusion
	var hostID, aiType, signalType, pattern string
	err := bc.db.QueryRowContext(ctx,
		`SELECT host_id, ai_type, signal_type, pattern FROM behavioral_baselines WHERE id = $1 AND org_id = $2`,
		id, orgID).Scan(&hostID, &aiType, &signalType, &pattern)
	if err != nil {
		return fmt.Errorf("baseline %d not found for org %s", id, orgID)
	}

	// Insert exclusion (ON CONFLICT ignore — idempotent)
	_, _ = bc.db.ExecContext(ctx,
		`INSERT INTO baseline_exclusions (org_id, host_id, ai_type, signal_type, pattern, created_by)
		 VALUES ($1, $2, $3, $4, $5, 'user')
		 ON CONFLICT (org_id, host_id, ai_type, signal_type, pattern) DO NOTHING`,
		orgID, hostID, aiType, signalType, pattern)

	// Now delete the baseline
	res, err := bc.db.ExecContext(ctx,
		`DELETE FROM behavioral_baselines WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return fmt.Errorf("delete baseline: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("baseline %d not found for org %s", id, orgID)
	}
	_ = bc.reload(ctx)
	return nil
}

// SuspendBaseline sets an expiry on a baseline by ID (org-scoped). This
// temporarily disables the baseline — the detection engine will start
// flagging this behavior until the expiry passes or the baseline is
// un-suspended. Reloads the cache.
func (bc *BaselineCollector) SuspendBaseline(ctx context.Context, orgID string, id int, expiresAt time.Time) error {
	if bc == nil {
		return fmt.Errorf("baseline collector is nil")
	}
	res, err := bc.db.ExecContext(ctx,
		`UPDATE behavioral_baselines SET expires_at = $1 WHERE id = $2 AND org_id = $3`,
		expiresAt, id, orgID)
	if err != nil {
		return fmt.Errorf("suspend baseline: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("baseline %d not found for org %s", id, orgID)
	}
	_ = bc.reload(ctx)
	return nil
}

// ConfirmBaseline promotes a baseline to user_confirmed source and removes
// its expiry, making it permanent. Reloads the cache.
func (bc *BaselineCollector) ConfirmBaseline(ctx context.Context, orgID string, id int) error {
	if bc == nil {
		return fmt.Errorf("baseline collector is nil")
	}
	res, err := bc.db.ExecContext(ctx,
		`UPDATE behavioral_baselines SET source = 'user_confirmed', expires_at = NULL WHERE id = $1 AND org_id = $2`,
		id, orgID)
	if err != nil {
		return fmt.Errorf("confirm baseline: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("baseline %d not found for org %s", id, orgID)
	}
	_ = bc.reload(ctx)
	return nil
}

// ListExclusions returns all exclusion records for an org.
func (bc *BaselineCollector) ListExclusions(ctx context.Context, orgID string) ([]ExclusionEntry, error) {
	if bc == nil {
		return nil, fmt.Errorf("baseline collector is nil")
	}
	rows, err := bc.db.QueryContext(ctx,
		`SELECT id, org_id, host_id, ai_type, signal_type, pattern, created_by, created_at
		 FROM baseline_exclusions WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("query baseline_exclusions: %w", err)
	}
	defer rows.Close()

	var entries []ExclusionEntry
	for rows.Next() {
		var e ExclusionEntry
		if err := rows.Scan(&e.ID, &e.OrgID, &e.HostID, &e.AIType, &e.SignalType, &e.Pattern, &e.CreatedBy, &e.CreatedAt); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// DeleteExclusion removes an exclusion record, allowing Observe() to auto-learn the pattern again.
func (bc *BaselineCollector) DeleteExclusion(ctx context.Context, orgID string, id int) error {
	if bc == nil {
		return fmt.Errorf("baseline collector is nil")
	}
	res, err := bc.db.ExecContext(ctx,
		`DELETE FROM baseline_exclusions WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return fmt.Errorf("delete exclusion: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("exclusion %d not found for org %s", id, orgID)
	}
	_ = bc.reload(ctx)
	return nil
}

// removeExclusion deletes an exclusion for a specific pattern (called when user re-allows it).
func (bc *BaselineCollector) removeExclusion(orgID, hostID, aiType, signalType, pattern string) {
	_, _ = bc.db.Exec(
		`DELETE FROM baseline_exclusions WHERE org_id=$1 AND host_id=$2 AND ai_type=$3 AND signal_type=$4 AND pattern=$5`,
		orgID, hostID, aiType, signalType, pattern)
}

// upsert increments the hit count if the pattern exists, or inserts a new baseline entry.
// Source never downgrades from 'user_confirmed' to 'observed'.
func (bc *BaselineCollector) upsert(orgID, hostID, aiType, signalType, pattern, source string, expiresAt *time.Time) {
	now := time.Now()

	_, err := bc.db.Exec(`
		INSERT INTO behavioral_baselines (org_id, host_id, ai_type, signal_type, pattern, source, hit_count, first_seen, last_seen, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $7, $8)
		ON CONFLICT (org_id, host_id, ai_type, signal_type, pattern)
		DO UPDATE SET hit_count = behavioral_baselines.hit_count + 1,
		             last_seen = $7,
		             source = CASE WHEN behavioral_baselines.source = 'user_confirmed' THEN 'user_confirmed' ELSE EXCLUDED.source END,
		             expires_at = CASE WHEN EXCLUDED.source = 'user_confirmed' THEN $8 ELSE behavioral_baselines.expires_at END
	`, orgID, hostID, aiType, signalType, pattern, source, now, expiresAt)
	if err != nil {
		log.Printf("WARN: baseline upsert failed: %v", err)
	}
}

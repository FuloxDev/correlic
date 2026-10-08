// Package lineage provides platform-agnostic AI process lineage tracking.
//
// A process is part of an AI lineage if:
//  1. Its parent was part of an AI lineage (inheritance). This is checked
//     first: a child of an AI session always joins that session, even if its
//     own name also matches a pattern.
//  2. Its name, executable, argv[0] or an argument matches a known AI agent
//     pattern (e.g. "cursor", "claude"). Such a process opens a new AI
//     session. Arguments match on their final path component only (see
//     MatchArgToken), so "git checkout claude/feature" is not an AI process.
//
// Each AI root process gets a unique AI Session ID (UUID). All child processes
// inherit the session, enabling cross-PID event correlation. This is critical
// on Windows where ETW events are asynchronous and short-lived processes may
// exit before their events are processed.
//
// Pattern matching is whole-token based (see MatchToken); the joined command
// line is never substring-matched.
//
// This package is imported by both Linux (eBPF) and macOS (ESF/kqueue) collectors.
package lineage

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// LineageTracker tracks which PIDs are part of an "AI Lineage" and assigns
// AI Session IDs for cross-PID event correlation.
type LineageTracker struct {
	mu              sync.RWMutex
	aiPIDs          map[uint32]bool      // Set of PIDs that are confirmed AI or descendants
	graceAIPIDs     map[uint32]time.Time // Recently exited AI PIDs kept for grace period
	pidToSession    map[uint32]string    // PID → AI session UUID
	graceSession    map[uint32]string    // Exited PID → session UUID (survives grace period)
	sessionAIType   map[string]string    // Session UUID → ai_type (e.g. "claude")
	patterns        []string             // Normalized AI process name patterns
	listeners       []func(pid uint32)
	removeListeners []func(pid uint32)
	logger          *slog.Logger
}

// gracePeriod is how long exited AI PIDs remain matchable by IsAI and
// GetSessionID. This covers the race where a short-lived process (e.g. curl)
// exits before its network/file events are processed by the runner.
const gracePeriod = 10 * time.Second

// minPatternLen is the shortest pattern accepted by UpdatePatterns. Shorter
// patterns ("ai", "cc") match far too much.
const minPatternLen = 3

// UnknownAIType is the ai_type recorded for processes marked AI without a
// matching pattern (e.g. container name matches).
const UnknownAIType = "unknown"

var (
	trackerInstance *LineageTracker
	trackerOnce     sync.Once
)

// GetLineageTracker returns the singleton instance of LineageTracker.
func GetLineageTracker() *LineageTracker {
	trackerOnce.Do(func() {
		trackerInstance = newTracker()
	})
	return trackerInstance
}

func newTracker() *LineageTracker {
	return &LineageTracker{
		aiPIDs:        make(map[uint32]bool),
		graceAIPIDs:   make(map[uint32]time.Time),
		pidToSession:  make(map[uint32]string),
		graceSession:  make(map[uint32]string),
		sessionAIType: make(map[string]string),
		listeners:     make([]func(pid uint32), 0),
		logger:        slog.Default().With("component", "lineage_tracker"),
	}
}

// AddListener registers a callback to be invoked when a new AI process is detected.
func (t *LineageTracker) AddListener(cb func(pid uint32)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.listeners = append(t.listeners, cb)
}

// AddRemoveListener registers a callback to be invoked when an AI process exits.
func (t *LineageTracker) AddRemoveListener(cb func(pid uint32)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.removeListeners = append(t.removeListeners, cb)
}

// NormalizePatterns lowercases and trims patterns and drops the ones that
// cannot be used for process matching: patterns shorter than minPatternLen
// and domain-style patterns containing a dot (those belong to network rules).
// Duplicates are removed. The returned slice preserves input order.
func NormalizePatterns(raw []string) (kept []string, ignored []string) {
	seen := make(map[string]bool, len(raw))
	for _, p := range raw {
		n := strings.ToLower(strings.TrimSpace(p))
		if n == "" {
			continue
		}
		if len(n) < minPatternLen || strings.Contains(n, ".") {
			ignored = append(ignored, n)
			continue
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		kept = append(kept, n)
	}
	return kept, ignored
}

// UpdatePatterns replaces the list of known AI patterns. Patterns are
// normalized with NormalizePatterns.
func (t *LineageTracker) UpdatePatterns(newPatterns []string) {
	kept, ignored := NormalizePatterns(newPatterns)
	t.mu.Lock()
	t.patterns = kept
	t.mu.Unlock()
	if len(ignored) > 0 {
		t.logger.Info("ignoring unusable AI patterns (too short or domain-style)", "ignored", ignored)
	}
	t.logger.Info("updated AI patterns", "count", len(kept))
}

// Patterns returns a copy of the active (normalized) pattern list.
func (t *LineageTracker) Patterns() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]string(nil), t.patterns...)
}

// PatternCount returns the number of active patterns.
func (t *LineageTracker) PatternCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.patterns)
}

// MatchToken reports whether a single command-line token (a process name, an
// executable path or an argument) matches a normalized pattern.
//
// A token matches when the token equals the pattern, or any of its path
// components (split on "/" and "\") equals the pattern or starts with the
// pattern followed by one of "-", "." or "_". The comparison is
// case-insensitive. Examples with pattern "claude":
//
//	claude, Claude.exe, claude-code, /opt/claude/bin/x, @anthropic-ai/claude-code/cli.js → match
//	--claude, myclaude, optimized (pattern "zed"), diagnostic (pattern "agno") → no match
func MatchToken(token, pattern string) bool {
	if pattern == "" {
		return false
	}
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" {
		return false
	}
	if token == pattern {
		return true
	}
	for _, comp := range splitPathComponents(token) {
		if nameMatches(comp, pattern) {
			return true
		}
	}
	return false
}

// MatchArgToken reports whether a command-line argument (anything after
// argv[0]) matches pattern. Arguments name what a program acts on rather than
// the program itself, so only the final path component counts ("aider",
// "@anthropic-ai/claude-code", "claude.js"). A directory component matches
// only when the argument is an existing regular file: "node
// /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js" is an AI process,
// "git checkout claude/feature" and "ls /tmp/claude-0/x" are not.
func MatchArgToken(token, pattern string) bool {
	return matchArgTokenForPID(0, token, pattern)
}

// matchArgTokenForPID is MatchArgToken with the process id, so a relative
// script path can be resolved through /proc/<pid>/cwd on Linux.
func matchArgTokenForPID(pid uint32, token, pattern string) bool {
	if pattern == "" {
		return false
	}
	raw := strings.TrimSpace(token)
	token = strings.ToLower(raw)
	if token == "" {
		return false
	}
	if token == pattern {
		return true
	}
	comps := splitPathComponents(token)
	if len(comps) == 0 {
		return false
	}
	if nameMatches(comps[len(comps)-1], pattern) {
		return true
	}
	for _, comp := range comps[:len(comps)-1] {
		if nameMatches(comp, pattern) {
			return isRegularFile(pid, raw)
		}
	}
	return false
}

// isRegularFile reports whether path is an existing regular file. A relative
// path is resolved against the process's working directory via
// /proc/<pid>/cwd (Linux); elsewhere a relative path is not resolvable and
// does not match. It is a variable so tests can run without the filesystem.
var isRegularFile = func(pid uint32, path string) bool {
	if !filepath.IsAbs(path) {
		if pid == 0 {
			return false
		}
		path = filepath.Join("/proc", strconv.Itoa(int(pid)), "cwd", path)
	}
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// splitPathComponents splits on both path separators and drops empty parts.
func splitPathComponents(token string) []string {
	var comps []string
	start := 0
	for i := 0; i <= len(token); i++ {
		if i < len(token) && token[i] != '/' && token[i] != '\\' {
			continue
		}
		if comp := token[start:i]; comp != "" {
			comps = append(comps, comp)
		}
		start = i + 1
	}
	return comps
}

// nameMatches reports whether a single path component matches the pattern:
// equal, or pattern followed by a separator character.
func nameMatches(name, pattern string) bool {
	if name == pattern {
		return true
	}
	if len(name) > len(pattern) && strings.HasPrefix(name, pattern) {
		switch name[len(pattern)] {
		case '-', '.', '_':
			return true
		}
	}
	return false
}

// matchTokens returns the first pattern matched by any of the identity
// tokens (process name, executable path, argv[0]). Caller must hold at least
// a read lock.
func (t *LineageTracker) matchTokens(tokens []string) (string, bool) {
	for _, tok := range tokens {
		for _, p := range t.patterns {
			if MatchToken(tok, p) {
				return p, true
			}
		}
	}
	return "", false
}

// matchArgTokens returns the first pattern matched by a command-line
// argument (see MatchArgToken). Caller must hold at least a read lock.
func (t *LineageTracker) matchArgTokens(pid uint32, args []string) (string, bool) {
	for _, arg := range args {
		for _, p := range t.patterns {
			if matchArgTokenForPID(pid, arg, p) {
				return p, true
			}
		}
	}
	return "", false
}

// matchProcessLocked matches a process by identity (comm, exe, argv[0])
// first, then by its arguments. pid (0 if unknown) resolves relative script
// paths. Caller must hold at least a read lock.
func (t *LineageTracker) matchProcessLocked(pid uint32, comm, exe string, argv []string) (string, bool) {
	identity := make([]string, 0, 3)
	if comm != "" {
		identity = append(identity, comm)
	}
	if exe != "" {
		identity = append(identity, exe)
	}
	if len(argv) > 0 && argv[0] != "" {
		identity = append(identity, argv[0])
	}
	if p, ok := t.matchTokens(identity); ok {
		return p, true
	}
	if len(argv) > 1 {
		return t.matchArgTokens(pid, argv[1:])
	}
	return "", false
}

// CheckPattern reports whether s (a process name, a path, or a whitespace
// separated command line) contains a token matching a known AI pattern.
// Matching is whole-token based; see MatchToken.
func (t *LineageTracker) CheckPattern(s string) bool {
	_, ok := t.MatchString(s)
	return ok
}

// MatchString is CheckPattern that also returns the matched pattern (ai_type).
func (t *LineageTracker) MatchString(s string) (string, bool) {
	if strings.TrimSpace(s) == "" {
		return "", false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.matchTokens(strings.Fields(s))
}

// MatchProcess checks a process name, executable path and argv for an AI
// pattern and returns the matched pattern (used as ai_type). comm, exe and
// argv[0] identify the program and match on any path component; the
// remaining arguments match per MatchArgToken, with relative script paths
// resolved through the process's working directory when pid is known. The
// joined command line is never substring-matched.
func (t *LineageTracker) MatchProcess(pid uint32, comm, exe string, argv []string) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.matchProcessLocked(pid, comm, exe, argv)
}

// MatchCommand is MatchProcess without a process name or id.
func (t *LineageTracker) MatchCommand(exe string, argv []string) (string, bool) {
	return t.MatchProcess(0, "", exe, argv)
}

// RegisterProcess checks if a new process should be tracked as AI based on
// its parent and its comm. Returns true if the process is deemed "AI Context".
// See RegisterProcessWithCommand.
func (t *LineageTracker) RegisterProcess(pid, ppid uint32, comm string) bool {
	return t.RegisterProcessWithCommand(pid, ppid, comm, "", nil)
}

// RegisterProcessWithCommand checks if a new process should be tracked as AI.
// Returns true if the process is deemed "AI Context".
//
// Inheritance is checked first: a child of an AI process (active or within the
// grace period) always joins the parent's session, even if its own name also
// matches a pattern. Otherwise comm, exe and argv are matched against the
// patterns and a new AI session is created for the matching root.
func (t *LineageTracker) RegisterProcessWithCommand(pid, ppid uint32, comm, exe string, argv []string) bool {
	t.mu.RLock()
	if t.aiPIDs[pid] {
		t.mu.RUnlock()
		return true
	}
	parentSess, isInherited := t.parentSessionLocked(ppid)
	aiType := ""
	isDirectMatch := false
	if !isInherited {
		if p, ok := t.matchProcessLocked(pid, comm, exe, argv); ok {
			aiType, isDirectMatch = p, true
		}
	}
	t.mu.RUnlock()

	if !isDirectMatch && !isInherited {
		return false
	}

	t.mu.Lock()
	if !t.aiPIDs[pid] {
		t.aiPIDs[pid] = true
		if isInherited {
			if parentSess != "" {
				t.pidToSession[pid] = parentSess
			}
		} else if _, hasSession := t.pidToSession[pid]; !hasSession {
			t.newSessionLocked(pid, aiType, comm)
		}
		t.notifyAddedLocked(pid)
		t.logger.Debug("registered AI process",
			"pid", pid, "ppid", ppid, "comm", comm,
			"session", t.pidToSession[pid], "root", !isInherited)
	}
	t.mu.Unlock()

	return true
}

// parentSessionLocked reports whether ppid is in an AI lineage (active or in
// grace) and returns its session. Caller holds a read lock.
func (t *LineageTracker) parentSessionLocked(ppid uint32) (string, bool) {
	if t.aiPIDs[ppid] {
		return t.pidToSession[ppid], true
	}
	if expiresAt, ok := t.graceAIPIDs[ppid]; ok && time.Now().Before(expiresAt) {
		return t.graceSession[ppid], true
	}
	return "", false
}

// newSessionLocked creates a new session for an AI root. Caller holds the write lock.
func (t *LineageTracker) newSessionLocked(pid uint32, aiType, comm string) {
	if aiType == "" {
		aiType = UnknownAIType
	}
	sessID := uuid.New().String()
	t.pidToSession[pid] = sessID
	t.sessionAIType[sessID] = aiType
	t.logger.Info("AI session created",
		"session_id", sessID, "pid", pid, "comm", comm, "ai_type", aiType)
}

// notifyAddedLocked invokes add listeners for pid. Caller holds the write lock.
func (t *LineageTracker) notifyAddedLocked(pid uint32) {
	for _, cb := range t.listeners {
		go cb(pid)
	}
}

// MarkAI explicitly marks a PID as AI with an unknown ai_type and no parent
// information. Prefer MarkAIWithType so the session can be inherited.
func (t *LineageTracker) MarkAI(pid uint32) {
	t.MarkAIWithType(pid, 0, UnknownAIType)
}

// MarkAIWithType marks a PID as AI when the caller has determined AI status
// through means other than name matching (e.g. a container name match). If the
// parent is already in an AI session the PID inherits it; otherwise a new
// session with the given ai_type is created.
func (t *LineageTracker) MarkAIWithType(pid, ppid uint32, aiType string) {
	t.mu.Lock()
	if !t.aiPIDs[pid] {
		t.aiPIDs[pid] = true
		if _, hasSession := t.pidToSession[pid]; !hasSession {
			if parentSess, ok := t.parentSessionLocked(ppid); ok && parentSess != "" {
				t.pidToSession[pid] = parentSess
			} else {
				t.newSessionLocked(pid, aiType, "")
			}
		}
		t.notifyAddedLocked(pid)
		t.logger.Debug("marked AI process (explicit)", "pid", pid, "ppid", ppid, "ai_type", aiType)
	}
	t.mu.Unlock()
}

// IsAI checks if a given PID is part of an AI lineage.
// Also matches recently exited PIDs within the grace period so that
// late-arriving network events from short-lived processes (curl, wget)
// are still attributed to the AI lineage.
func (t *LineageTracker) IsAI(pid uint32) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.aiPIDs[pid] {
		return true
	}
	if expiresAt, ok := t.graceAIPIDs[pid]; ok {
		return time.Now().Before(expiresAt)
	}
	return false
}

// GetSessionID returns the AI Session UUID for a PID.
// Checks active sessions first, then the grace map for recently exited processes.
// Returns empty string if the PID has no session.
func (t *LineageTracker) GetSessionID(pid uint32) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if sess, ok := t.pidToSession[pid]; ok {
		return sess
	}
	if sess, ok := t.graceSession[pid]; ok {
		return sess
	}
	return ""
}

// GetSessionAIType returns the ai_type for a given session UUID.
func (t *LineageTracker) GetSessionAIType(sessionID string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sessionAIType[sessionID]
}

// GetAIType returns the ai_type (e.g. "claude", "cursor") for a PID.
// Looks up the PID's session, then the session's ai_type.
func (t *LineageTracker) GetAIType(pid uint32) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if sess, ok := t.pidToSession[pid]; ok {
		return t.sessionAIType[sess]
	}
	if sess, ok := t.graceSession[pid]; ok {
		return t.sessionAIType[sess]
	}
	return ""
}

// AIContext returns the session UUID and ai_type for a PID in one lookup.
// ok is false when the PID is not part of an AI lineage.
func (t *LineageTracker) AIContext(pid uint32) (sessionID, aiType string, ok bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if !t.aiPIDs[pid] {
		if expiresAt, inGrace := t.graceAIPIDs[pid]; !inGrace || !time.Now().Before(expiresAt) {
			return "", "", false
		}
	}
	if sess, found := t.pidToSession[pid]; found {
		return sess, t.sessionAIType[sess], true
	}
	if sess, found := t.graceSession[pid]; found {
		return sess, t.sessionAIType[sess], true
	}
	return "", "", true
}

// Annotate adds ai_session_id, is_ai and ai_type to an event context map for
// a PID in an AI lineage. It is a no-op for other PIDs.
func (t *LineageTracker) Annotate(ctx map[string]any, pid uint32) {
	sess, aiType, ok := t.AIContext(pid)
	if !ok || ctx == nil {
		return
	}
	ctx["is_ai"] = true
	if sess != "" {
		ctx["ai_session_id"] = sess
	}
	if aiType != "" {
		ctx["ai_type"] = aiType
	}
}

// HasAnyAI returns true if any AI process is currently being tracked.
// Used by macOS polling-based collectors that can't attribute events to specific PIDs.
func (t *LineageTracker) HasAnyAI() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.aiPIDs) > 0
}

// ResetForTesting resets the singleton for test isolation.
// Must only be called from tests.
func ResetForTesting() {
	trackerOnce = sync.Once{}
	trackerInstance = nil
}

// UnregisterProcess removes a PID from active tracking (called on exit).
// The PID is moved to grace period maps so late-arriving events (network
// connections from short-lived processes like curl) can still be attributed
// to the correct AI session.
func (t *LineageTracker) UnregisterProcess(pid uint32) {
	t.mu.Lock()
	wasAI := t.aiPIDs[pid]
	delete(t.aiPIDs, pid)
	if wasAI {
		t.graceAIPIDs[pid] = time.Now().Add(gracePeriod)
		// Preserve session mapping in grace map for late-arriving events.
		if sess, ok := t.pidToSession[pid]; ok {
			t.graceSession[pid] = sess
			delete(t.pidToSession, pid)
		}
	}
	// Evict expired grace entries periodically.
	if len(t.graceAIPIDs) > 100 {
		now := time.Now()
		for p, exp := range t.graceAIPIDs {
			if now.After(exp) {
				delete(t.graceAIPIDs, p)
				delete(t.graceSession, p)
			}
		}
	}
	// Copy listeners under lock, invoke outside
	var cbs []func(uint32)
	if wasAI {
		cbs = make([]func(uint32), len(t.removeListeners))
		copy(cbs, t.removeListeners)
	}
	t.mu.Unlock()

	for _, cb := range cbs {
		go cb(pid)
	}
}

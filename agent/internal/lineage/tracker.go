// Package lineage provides platform-agnostic AI process lineage tracking.
//
// A process is part of an AI lineage if:
//  1. Its name matches a known AI agent pattern (e.g. "cursor", "copilot").
//  2. Its parent was part of an AI lineage (inheritance).
//
// Each AI root process gets a unique AI Session ID (UUID). All child processes
// inherit the session, enabling cross-PID event correlation. This is critical
// on Windows where ETW events are asynchronous and short-lived processes may
// exit before their events are processed.
//
// This package is imported by both Linux (eBPF) and macOS (ESF/kqueue) collectors.
package lineage

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// LineageTracker tracks which PIDs are part of an "AI Lineage" and assigns
// AI Session IDs for cross-PID event correlation.
type LineageTracker struct {
	mu              sync.RWMutex
	aiPIDs          map[uint32]bool       // Set of PIDs that are confirmed AI or descendants
	graceAIPIDs     map[uint32]time.Time  // Recently exited AI PIDs kept for grace period
	pidToSession    map[uint32]string     // PID → AI session UUID
	graceSession    map[uint32]string     // Exited PID → session UUID (survives grace period)
	sessionAIType   map[string]string     // Session UUID → ai_type (e.g. "claude_code")
	patterns        []string              // List of AI process name patterns
	listeners       []func(pid uint32)
	removeListeners []func(pid uint32)
	logger          *slog.Logger
}

// gracePeriod is how long exited AI PIDs remain matchable by IsAI and
// GetSessionID. This covers the race where a short-lived process (e.g. curl)
// exits before its network/file events are processed by the runner.
const gracePeriod = 10 * time.Second

var (
	trackerInstance *LineageTracker
	trackerOnce     sync.Once
)

// GetLineageTracker returns the singleton instance of LineageTracker.
func GetLineageTracker() *LineageTracker {
	trackerOnce.Do(func() {
		trackerInstance = &LineageTracker{
			aiPIDs:        make(map[uint32]bool),
			graceAIPIDs:   make(map[uint32]time.Time),
			pidToSession:  make(map[uint32]string),
			graceSession:  make(map[uint32]string),
			sessionAIType: make(map[string]string),
			listeners:     make([]func(pid uint32), 0),
			logger:        slog.Default().With("component", "lineage_tracker"),
		}
	})
	return trackerInstance
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

// UpdatePatterns updates the list of known AI patterns.
// Patterns are normalized to lowercase so CheckPattern can do case-insensitive
// matching without lowercasing each pattern on every call.
func (t *LineageTracker) UpdatePatterns(newPatterns []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	normalized := make([]string, len(newPatterns))
	for i, p := range newPatterns {
		normalized[i] = strings.ToLower(p)
	}
	t.patterns = normalized
	t.logger.Info("updated AI patterns", "count", len(normalized))
}

// CheckPattern checks if the comm matches any known pattern (thread-safe).
// It returns true if the process name matches a known AI agent pattern.
func (t *LineageTracker) CheckPattern(comm string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if comm == "" {
		return false
	}
	commLower := strings.ToLower(comm)
	for _, p := range t.patterns {
		if strings.Contains(commLower, p) {
			return true
		}
	}
	return false
}

// RegisterProcess checks if a new process should be tracked as AI.
// Returns true if the process is deemed "AI Context".
//
// For AI root processes (direct pattern match), a new AI Session UUID is
// created. For inherited processes (child of AI), the parent's session is
// inherited. This enables cross-PID correlation on Windows where ETW
// events arrive asynchronously.
func (t *LineageTracker) RegisterProcess(pid, ppid uint32, comm string) bool {
	isDirectMatch := t.CheckPattern(comm)
	isInherited := false

	if !isDirectMatch {
		t.mu.RLock()
		isInherited = t.aiPIDs[ppid]
		// Also check grace period — parent may have exited but is still
		// within the 10-second window (common for short-lived shell processes).
		if !isInherited {
			if expiresAt, ok := t.graceAIPIDs[ppid]; ok {
				isInherited = time.Now().Before(expiresAt)
			}
		}
		t.mu.RUnlock()
	}

	if !isDirectMatch && !isInherited {
		return false
	}

	t.mu.Lock()
	if !t.aiPIDs[pid] {
		t.aiPIDs[pid] = true

		// Session assignment: root gets new UUID, children inherit parent's.
		if isDirectMatch {
			// Check if this PID already has a session (e.g., from scanner).
			if _, hasSession := t.pidToSession[pid]; !hasSession {
				sessID := uuid.New().String()
				t.pidToSession[pid] = sessID
				// Derive ai_type from the matching pattern for this session.
				aiType := t.matchingAIType(comm)
				t.sessionAIType[sessID] = aiType
				t.logger.Info("AI session created",
					"session_id", sessID, "pid", pid, "comm", comm, "ai_type", aiType)
			}
		} else if isInherited {
			// Inherit parent's session. Check active first, then grace.
			if parentSess, ok := t.pidToSession[ppid]; ok {
				t.pidToSession[pid] = parentSess
			} else if graceSess, ok := t.graceSession[ppid]; ok {
				t.pidToSession[pid] = graceSess
			}
		}

		for _, cb := range t.listeners {
			go cb(pid)
		}
		t.logger.Debug("registered AI process",
			"pid", pid, "ppid", ppid, "comm", comm,
			"session", t.pidToSession[pid], "root", isDirectMatch)
	}
	t.mu.Unlock()

	return true
}

// matchingAIType returns the ai_type for a comm string based on pattern matching.
// Must be called with at least a read lock held (or before lock, using CheckPattern).
func (t *LineageTracker) matchingAIType(comm string) string {
	commLower := strings.ToLower(comm)
	for _, p := range t.patterns {
		if strings.Contains(commLower, p) {
			return p // pattern itself is the ai_type (e.g., "claude", "cursor")
		}
	}
	return "unknown"
}

// MarkAI explicitly marks a PID as AI. Used when the caller has already
// determined AI status through means other than comm matching (e.g., cmdline
// pattern match for tools running under generic runtimes like node/python).
func (t *LineageTracker) MarkAI(pid uint32) {
	t.mu.Lock()
	if !t.aiPIDs[pid] {
		t.aiPIDs[pid] = true
		// Create a session if none exists (explicit marking = treat as root).
		if _, hasSession := t.pidToSession[pid]; !hasSession {
			sessID := uuid.New().String()
			t.pidToSession[pid] = sessID
			t.sessionAIType[sessID] = "unknown"
			t.logger.Info("AI session created (explicit mark)",
				"session_id", sessID, "pid", pid)
		}
		for _, cb := range t.listeners {
			go cb(pid)
		}
		t.logger.Debug("marked AI process (explicit)", "pid", pid)
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

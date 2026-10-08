package enforcer

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type BlockRule struct {
	ID         int    `json:"id"`
	SignalType string `json:"signal_type"` // process_exec | net_connect | file_open
	Pattern    string `json:"pattern"`
	KillTree   bool   `json:"kill_tree"`
	Source     string `json:"source"`
}

type BlockResult struct {
	Blocked   bool
	RuleID    int
	Success   bool
	Error     error
	LatencyUS int64
}

type Enforcer struct {
	mu            sync.RWMutex
	execRules     map[string]*BlockRule // lowercase exe basename → rule
	netRules      map[string]*BlockRule // "IP:port" or "IP" → rule
	fileRules     []*fileGlobRule       // glob patterns for file paths
	protectedPIDs map[uint32]bool       // never kill these PIDs
	enabled       bool
	logger        *slog.Logger
}

type fileGlobRule struct {
	pattern string
	rule    *BlockRule
}

func New(logger *slog.Logger, enabled bool) *Enforcer {
	e := &Enforcer{
		execRules:     make(map[string]*BlockRule),
		netRules:      make(map[string]*BlockRule),
		protectedPIDs: make(map[uint32]bool),
		enabled:       enabled,
		logger:        logger.With("component", "enforcer"),
	}
	// Always protect own process
	e.protectedPIDs[uint32(os.Getpid())] = true
	return e
}

func (e *Enforcer) SetEnabled(enabled bool) {
	e.mu.Lock()
	e.enabled = enabled
	e.mu.Unlock()
}

func (e *Enforcer) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// AddProtectedPID marks a PID as never-kill (agent self, AI roots).
func (e *Enforcer) AddProtectedPID(pid uint32) {
	e.mu.Lock()
	e.protectedPIDs[pid] = true
	e.mu.Unlock()
}

// IsProtected returns true if the PID should never be killed.
func (e *Enforcer) IsProtected(pid uint32) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.protectedPIDs[pid]
}

// ShouldBlock checks if the given signal+pattern matches any block rule.
// Must be fast (<1μs) — called in the hot path.
func (e *Enforcer) ShouldBlock(signalType, candidate string) (bool, *BlockRule) {
	if !e.IsEnabled() {
		return false, nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	switch signalType {
	case "process_exec":
		// Match by exe basename (case-insensitive)
		base := strings.ToLower(filepath.Base(candidate))
		if rule, ok := e.execRules[base]; ok {
			return true, rule
		}
		// Also try without .exe
		noExt := strings.TrimSuffix(base, ".exe")
		if rule, ok := e.execRules[noExt]; ok {
			return true, rule
		}
	case "net_connect":
		// Try exact "IP:port" match first, then IP-only
		if rule, ok := e.netRules[candidate]; ok {
			return true, rule
		}
		// Strip port and try IP-only
		if idx := strings.LastIndex(candidate, ":"); idx > 0 {
			ip := candidate[:idx]
			if rule, ok := e.netRules[ip]; ok {
				return true, rule
			}
		}
	case "file_open":
		// Glob match against file rules
		candidateLower := strings.ToLower(filepath.ToSlash(candidate))
		for _, fr := range e.fileRules {
			matched, _ := filepath.Match(strings.ToLower(fr.pattern), candidateLower)
			if matched {
				return true, fr.rule
			}
			// Also check prefix match for directory globs like "/etc/shadow/**"
			dir := strings.TrimSuffix(fr.pattern, "/**")
			// A bare "/**" would reduce to an empty prefix and match every file.
			if dir != fr.pattern && dir != "" && strings.HasPrefix(candidateLower, strings.ToLower(filepath.ToSlash(dir))) {
				return true, fr.rule
			}
		}
	}
	return false, nil
}

// Kill terminates a process by PID. Uses platform-specific implementation.
// Only the matched PID is killed unless the rule explicitly asks for the
// tree (kill_tree); in that case descendants are killed too, each one
// checked against the protected set like the root.
func (e *Enforcer) Kill(pid uint32, killTree bool) (bool, error) {
	if e.IsProtected(pid) {
		return false, fmt.Errorf("PID %d is protected", pid)
	}
	start := time.Now()
	var success bool
	var err error
	if killTree {
		success, err = KillProcessTree(pid, e.IsProtected)
	} else {
		success, err = KillProcess(pid)
	}
	latency := time.Since(start)
	if success {
		e.logger.Warn("process killed", "pid", pid, "kill_tree", killTree, "latency", latency)
	} else {
		e.logger.Error("process kill failed", "pid", pid, "error", err, "latency", latency)
	}
	return success, err
}

// UpdateRules atomically replaces all block rules.
func (e *Enforcer) UpdateRules(rules []BlockRule) {
	execRules := make(map[string]*BlockRule)
	netRules := make(map[string]*BlockRule)
	var fileRules []*fileGlobRule

	for i := range rules {
		r := &rules[i]
		switch r.SignalType {
		case "process_exec":
			key := strings.ToLower(r.Pattern)
			execRules[key] = r
		case "net_connect":
			netRules[r.Pattern] = r
		case "file_open":
			fileRules = append(fileRules, &fileGlobRule{pattern: r.Pattern, rule: r})
		}
	}

	e.mu.Lock()
	e.execRules = execRules
	e.netRules = netRules
	e.fileRules = fileRules
	e.mu.Unlock()

	e.logger.Info("block rules updated", "exec", len(execRules), "net", len(netRules), "file", len(fileRules))
}

// RuleCount returns current rule counts.
func (e *Enforcer) RuleCount() (exec, net, file int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.execRules), len(e.netRules), len(e.fileRules)
}

// VersionHash returns SHA256 of current rules for sync comparison.
func VersionHash(rules []BlockRule) string {
	h := sha256.New()
	for _, r := range rules {
		fmt.Fprintf(h, "%d:%s:%s:%v\n", r.ID, r.SignalType, r.Pattern, r.KillTree)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

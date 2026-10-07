package detection

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ChainStep is one step in an attack chain pattern.
// DetectionIDs lists the detection rule IDs that satisfy this step (OR logic).
// ContextFilter optionally requires certain keys to be present in the finding's Context.
// If a filter value is "", the key must exist and be non-empty. If non-empty, the key
// must equal that value.
type ChainStep struct {
	DetectionIDs  []string
	ContextFilter map[string]string
}

// ChainPattern defines a multi-step attack sequence that, when detected in order within
// MaxWindow, produces a synthetic chain finding.
type ChainPattern struct {
	ID              string
	Name            string
	Steps           []ChainStep
	MaxWindow       time.Duration
	Severity        string
	Confidence      float64
	MITRETechniques []string // ATT&CK technique IDs for the combined chain
}

type bufferedFinding struct {
	finding Finding
	at      time.Time
}

// ChainCorrelator buffers individual findings per host+session and emits synthetic "chain"
// findings when a complete multi-step attack pattern is detected.
//
// Chain findings use DetectionID "chain.<pattern_id>" and bypass cooldown suppression.
// A background goroutine evicts stale buffer entries every 5 minutes.
type ChainCorrelator struct {
	mu       sync.RWMutex
	patterns []ChainPattern
	buffer   map[string][]bufferedFinding // key = "host_id:session_id"
	maxAge   time.Duration
	done     chan struct{}
}

// NewChainCorrelator creates a correlator with the 11 default attack chain patterns.
func NewChainCorrelator() *ChainCorrelator {
	c := &ChainCorrelator{
		buffer: make(map[string][]bufferedFinding),
		maxAge: 30 * time.Minute,
		done:   make(chan struct{}),
		patterns: []ChainPattern{
			{
				ID:   "credential_theft",
				Name: "Credential Theft",
				Steps: []ChainStep{
					{DetectionIDs: []string{"ai.credential_access"}},
					{DetectionIDs: []string{"ai.data_exfiltration"}},
				},
				MaxWindow:       20 * time.Minute,
				Severity:        "critical",
				Confidence:      0.95,
				MITRETechniques: []string{"T1552", "T1041"},
			},
			{
				ID:   "reverse_shell_setup",
				Name: "Reverse Shell Setup",
				Steps: []ChainStep{
					{DetectionIDs: []string{"ai.unauthorized_exec"}},
					{DetectionIDs: []string{"ai.unexpected_network"}},
				},
				MaxWindow:       5 * time.Minute,
				Severity:        "critical",
				Confidence:      0.90,
				MITRETechniques: []string{"T1059", "T1071"},
			},
			{
				// lateral_movement requires the network finding to target an internal host.
				ID:   "lateral_movement",
				Name: "Lateral Movement",
				Steps: []ChainStep{
					{DetectionIDs: []string{"ai.unauthorized_exec"}},
					{
						DetectionIDs:  []string{"ai.unexpected_network"},
						ContextFilter: map[string]string{"internal_threat": ""},
					},
				},
				MaxWindow:       10 * time.Minute,
				Severity:        "high",
				Confidence:      0.85,
				MITRETechniques: []string{"T1059", "T1021"},
			},
			{
				// full_compromise: credential read → suspicious exec → exfil OR unexpected net.
				ID:   "full_compromise",
				Name: "Full Compromise",
				Steps: []ChainStep{
					{DetectionIDs: []string{"ai.credential_access"}},
					{DetectionIDs: []string{"ai.unauthorized_exec"}},
					{DetectionIDs: []string{"ai.data_exfiltration", "ai.unexpected_network"}},
				},
				MaxWindow:       30 * time.Minute,
				Severity:        "critical",
				Confidence:      0.95,
				MITRETechniques: []string{"T1552", "T1059", "T1041"},
			},
			{
				// persistence_backdoor: privilege escalation → persistence installation.
				ID:   "persistence_backdoor",
				Name: "Persistence Backdoor",
				Steps: []ChainStep{
					{DetectionIDs: []string{"ai.privilege_escalation"}},
					{DetectionIDs: []string{"ai.persistence"}},
				},
				MaxWindow:       15 * time.Minute,
				Severity:        "critical",
				Confidence:      0.95,
				MITRETechniques: []string{"T1548", "T1053", "T1546"},
			},
			{
				// supply_chain_attack: code tampering → data exfiltration or unexpected network.
				ID:   "supply_chain_attack",
				Name: "Supply Chain Attack",
				Steps: []ChainStep{
					{DetectionIDs: []string{"ai.code_tampering"}},
					{DetectionIDs: []string{"ai.data_exfiltration", "ai.unexpected_network"}},
				},
				MaxWindow:       20 * time.Minute,
				Severity:        "critical",
				Confidence:      0.90,
				MITRETechniques: []string{"T1195.002", "T1041"},
			},
			{
				// data_staging: mass file writes then exfiltration — collect-and-exfil pattern.
				ID:   "data_staging",
				Name: "Data Staging & Exfiltration",
				Steps: []ChainStep{
					{DetectionIDs: []string{"ai.excessive_writes"}},
					{DetectionIDs: []string{"ai.data_exfiltration", "ai.unexpected_network"}},
				},
				MaxWindow:       20 * time.Minute,
				Severity:        "critical",
				Confidence:      0.90,
				MITRETechniques: []string{"T1074", "T1041"},
			},
			{
				// credential_persistence: steal credentials then install persistence.
				ID:   "credential_persistence",
				Name: "Credential Theft & Persistence",
				Steps: []ChainStep{
					{DetectionIDs: []string{"ai.credential_access"}},
					{DetectionIDs: []string{"ai.persistence"}},
				},
				MaxWindow:       15 * time.Minute,
				Severity:        "critical",
				Confidence:      0.95,
				MITRETechniques: []string{"T1552", "T1546"},
			},
			{
				// privesc_credential_exfil: escalate → steal credentials → exfiltrate.
				ID:   "privesc_credential_exfil",
				Name: "Privilege Escalation to Data Theft",
				Steps: []ChainStep{
					{DetectionIDs: []string{"ai.privilege_escalation"}},
					{DetectionIDs: []string{"ai.credential_access"}},
					{DetectionIDs: []string{"ai.data_exfiltration", "ai.unexpected_network"}},
				},
				MaxWindow:       30 * time.Minute,
				Severity:        "critical",
				Confidence:      0.95,
				MITRETechniques: []string{"T1548", "T1552", "T1041"},
			},
			{
				// recon_to_escalation: discovery → privilege escalation.
				// Classic pre-attack pattern: enumerate first, then escalate.
				ID:   "recon_to_escalation",
				Name: "Reconnaissance to Privilege Escalation",
				Steps: []ChainStep{
					{DetectionIDs: []string{"ai.discovery"}},
					{DetectionIDs: []string{"ai.privilege_escalation"}},
				},
				MaxWindow:       15 * time.Minute,
				Severity:        "high",
				Confidence:      0.85,
				MITRETechniques: []string{"T1082", "T1548"},
			},
			{
				// container_breakout: container escape → persistence or credential access.
				ID:   "container_breakout",
				Name: "Container Breakout",
				Steps: []ChainStep{
					{DetectionIDs: []string{"ai.container_escape"}},
					{DetectionIDs: []string{"ai.persistence", "ai.credential_access", "ai.privilege_escalation"}},
				},
				MaxWindow:       10 * time.Minute,
				Severity:        "critical",
				Confidence:      0.95,
				MITRETechniques: []string{"T1611", "T1552", "T1546"},
			},
		},
	}
	go c.cleanupLoop()
	return c
}

// chainBufferKey returns the correlation key for a finding.
// Prefers session_id from Context (stable across processes in the same session).
// Falls back to host_id only when no session is available.
func chainBufferKey(f Finding) string {
	if f.Context != nil {
		if v, ok := f.Context["session_id"]; ok {
			if s, ok := v.(string); ok && s != "" && s != "0" {
				return f.HostID + ":" + s
			}
		}
	}
	// Fallback: use PID to avoid mixing unrelated processes into one bucket.
	if f.Context != nil {
		if v, ok := f.Context["pid"]; ok {
			return fmt.Sprintf("%s:pid:%v", f.HostID, v)
		}
	}
	return f.HostID + ":unknown"
}

// Ingest adds a finding to the correlation buffer and returns any chain findings that completed
// as a result. The new finding must satisfy the final step of a pattern for that pattern to fire.
func (c *ChainCorrelator) Ingest(f Finding) []Finding {
	key := chainBufferKey(f)

	c.mu.Lock()
	c.buffer[key] = append(c.buffer[key], bufferedFinding{finding: f, at: time.Now()})
	// Snapshot the buffer for this key to avoid holding the lock during matching.
	snapshot := make([]bufferedFinding, len(c.buffer[key]))
	copy(snapshot, c.buffer[key])
	c.mu.Unlock()

	var chainFindings []Finding
	for _, pattern := range c.patterns {
		// The new finding must match the last step for the pattern to complete.
		if !chainStepMatches(f, pattern.Steps[len(pattern.Steps)-1]) {
			continue
		}
		chain := matchChain(snapshot, pattern, f)
		if chain == nil {
			continue
		}
		cf := buildChainFinding(chain, pattern, f)
		chainFindings = append(chainFindings, cf)
		log.Printf("INFO: attack chain detected: %s (host=%s, pattern=%s, window=%v)",
			cf.ID, f.HostID, pattern.Name, f.Timestamp.Sub(chain[0].Timestamp).Round(time.Second))
	}
	return chainFindings
}

// chainStepMatches returns true if finding f satisfies chain step s.
func chainStepMatches(f Finding, s ChainStep) bool {
	matched := false
	for _, id := range s.DetectionIDs {
		if f.DetectionID == id {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}

	for k, v := range s.ContextFilter {
		actual, exists := f.Context[k]
		if !exists || actual == nil {
			return false
		}
		if v == "" {
			// Key must be present and non-empty.
			if sv, ok := actual.(string); !ok || sv == "" {
				return false
			}
		} else {
			// Key must equal the specified value.
			if fmt.Sprintf("%v", actual) != v {
				return false
			}
		}
	}
	return true
}

// matchChain searches buf for a complete sequence of findings satisfying all of pattern's steps
// in order, ending with lastFinding. Returns the matched slice (len == len(pattern.Steps)) or nil.
func matchChain(buf []bufferedFinding, p ChainPattern, lastFinding Finding) []Finding {
	n := len(p.Steps)
	if n == 0 {
		return nil
	}

	result := make([]Finding, n)
	result[n-1] = lastFinding
	upperBound := lastFinding.Timestamp

	// Walk backwards through remaining steps (n-2 down to 0), finding matches before upperBound.
	for stepIdx := n - 2; stepIdx >= 0; stepIdx-- {
		step := p.Steps[stepIdx]
		found := false

		// Scan from most-recent to oldest so we get the tightest (most recent) match.
		for i := len(buf) - 1; i >= 0; i-- {
			bf := buf[i]

			// Skip the anchor finding itself.
			if bf.finding.ID == lastFinding.ID {
				continue
			}
			// Must be strictly before the previous step.
			if !bf.finding.Timestamp.Before(upperBound) {
				continue
			}
			// The entire chain must fit within MaxWindow.
			if lastFinding.Timestamp.Sub(bf.finding.Timestamp) > p.MaxWindow {
				continue
			}
			if !chainStepMatches(bf.finding, step) {
				continue
			}

			result[stepIdx] = bf.finding
			upperBound = bf.finding.Timestamp
			found = true
			break
		}

		if !found {
			return nil
		}
	}

	// Final window check: first-to-last must be within MaxWindow.
	if lastFinding.Timestamp.Sub(result[0].Timestamp) > p.MaxWindow {
		return nil
	}

	return result
}

// buildChainFinding constructs the synthetic chain finding from the matched constituent findings.
func buildChainFinding(chain []Finding, p ChainPattern, lastFinding Finding) Finding {
	// Collect and deduplicate related event IDs from all constituent findings.
	seen := make(map[string]bool)
	var relatedEvents []string
	var stepIDs []string

	for _, f := range chain {
		stepIDs = append(stepIDs, f.ID)
		if f.AnchorEventID != "" && !seen[f.AnchorEventID] {
			seen[f.AnchorEventID] = true
			relatedEvents = append(relatedEvents, f.AnchorEventID)
		}
		for _, id := range f.RelatedEvents {
			if id != "" && !seen[id] {
				seen[id] = true
				relatedEvents = append(relatedEvents, id)
			}
		}
	}

	firstFinding := chain[0]
	windowSecs := int(lastFinding.Timestamp.Sub(firstFinding.Timestamp).Seconds())

	// Extract session for a deterministic, dedup-friendly ID.
	sessionStr := "nosession"
	if lastFinding.Context != nil {
		if v, ok := lastFinding.Context["session_id"]; ok {
			if s, ok := v.(string); ok && s != "" && s != "0" {
				sessionStr = s
			}
		}
	}

	chainID := fmt.Sprintf("chain.%s:%s:%s:%d",
		p.ID, lastFinding.HostID, sessionStr, firstFinding.Timestamp.Unix())

	ctx := map[string]any{
		"chain_pattern":     p.ID,
		"chain_name":        p.Name,
		"chain_steps":       stepIDs,
		"chain_window_secs": windowSecs,
	}
	if len(p.MITRETechniques) > 0 {
		ctx["mitre_techniques"] = p.MITRETechniques
	}

	// Propagate ai_type from constituent findings so chain findings
	// are attributed to the correct AI agent in the UI.
	for _, f := range chain {
		if f.Context != nil {
			if v, ok := f.Context["ai_type"]; ok {
				ctx["ai_type"] = v
				break
			}
		}
	}

	return Finding{
		ID:            chainID,
		DetectionID:   "chain." + p.ID,
		HostID:        lastFinding.HostID,
		Severity:      p.Severity,
		Confidence:    p.Confidence,
		Title:         "Attack chain detected: " + p.Name,
		Summary: fmt.Sprintf("Correlated %d findings matched the %s attack chain within %ds",
			len(chain), p.Name, windowSecs),
		AnchorEventID: firstFinding.AnchorEventID,
		RelatedEvents: relatedEvents,
		Status:        "pending",
		Timestamp:     lastFinding.Timestamp,
		Context:       ctx,
	}
}

// cleanup evicts buffer entries older than maxAge to prevent unbounded memory growth.
func (c *ChainCorrelator) cleanup() {
	cutoff := time.Now().Add(-c.maxAge)

	c.mu.Lock()
	defer c.mu.Unlock()

	totalBefore := 0
	totalAfter := 0
	keysRemoved := 0
	for key, entries := range c.buffer {
		totalBefore += len(entries)
		var keep []bufferedFinding
		for _, e := range entries {
			if e.at.After(cutoff) {
				keep = append(keep, e)
			}
		}
		totalAfter += len(keep)
		if len(keep) == 0 {
			delete(c.buffer, key)
			keysRemoved++
		} else {
			c.buffer[key] = keep
		}
	}
	evicted := totalBefore - totalAfter
	if evicted > 0 {
		log.Printf("chain_correlator: cleanup evicted %d stale findings, removed %d keys (active_keys=%d)",
			evicted, keysRemoved, len(c.buffer))
	}
}

// Stop signals the cleanup goroutine to exit.
func (c *ChainCorrelator) Stop() {
	close(c.done)
}

func (c *ChainCorrelator) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

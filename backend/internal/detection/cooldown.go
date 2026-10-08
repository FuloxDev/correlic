package detection

import (
	"log"
	"sync"
	"time"
)

// FindingCooldown suppresses repeat findings for the same behavior within a configurable
// time window. This prevents alert fatigue when an AI agent repeatedly triggers the same
// detection on the same target (e.g. accessing the same SSH key 3 times = 1 alert).
//
// Key: "org_id|finding ID" — the finding ID already encodes
// "org:detection_id:host_id:pattern_key", so each unique target (file, IP, domain)
// in each tenant gets its own cooldown window. Different targets under the same rule
// can all fire independently within the same window, and two orgs never share a window.
// Chain findings (DetectionID prefixed with "chain.") always bypass cooldown.
type FindingCooldown struct {
	mu        sync.Mutex
	lastEmit  map[string]time.Time
	defaults  time.Duration
	overrides map[string]time.Duration
	done      chan struct{}
}

// NewFindingCooldown creates a cooldown with a 10-minute default and per-rule overrides:
//   - ai.credential_access → 15 minutes (credential reads are high-value, longer suppression)
//   - ai.unexpected_network → 5 minutes (network events are time-sensitive, shorter suppression)
//
// A background goroutine evicts expired entries every 5 minutes.
func NewFindingCooldown() *FindingCooldown {
	c := &FindingCooldown{
		lastEmit: make(map[string]time.Time),
		defaults: 10 * time.Minute,
		overrides: map[string]time.Duration{
			"ai.credential_access":  15 * time.Minute,
			"ai.unexpected_network": 5 * time.Minute,
		},
		done: make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// ShouldEmit returns true if the finding should be emitted (not rate-limited).
// The first finding for a given behavior always emits. Repeat findings for the same exact
// target (same finding ID) within the cooldown window are suppressed.
// Chain findings always emit regardless of cooldown.
func (c *FindingCooldown) ShouldEmit(f Finding) bool {
	// Chain findings are always important — bypass cooldown.
	if len(f.DetectionID) > 6 && f.DetectionID[:6] == "chain." {
		return true
	}

	// Key on org + finding ID (org:detection_id:host_id:pattern_key).
	// Different targets (files, IPs) under the same rule each have their own window,
	// and the explicit org prefix keeps tenants apart even for findings whose ID was
	// built elsewhere without an org component.
	key := f.OrgID + "|" + f.ID
	cooldown := c.defaults
	if override, ok := c.overrides[f.DetectionID]; ok {
		cooldown = override
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	last, exists := c.lastEmit[key]
	if !exists || time.Since(last) >= cooldown {
		c.lastEmit[key] = time.Now()
		return true
	}

	log.Printf("Detection cooldown: suppressed %s on %s (last emitted %v ago, window=%v)",
		f.DetectionID, f.HostID, time.Since(last).Round(time.Second), cooldown)
	return false
}

// Cleanup removes cooldown entries that have fully expired to prevent unbounded memory growth.
func (c *FindingCooldown) Cleanup() {
	// Use the largest configured window as the eviction horizon.
	maxWindow := c.defaults
	for _, d := range c.overrides {
		if d > maxWindow {
			maxWindow = d
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for key, last := range c.lastEmit {
		if time.Since(last) > maxWindow {
			delete(c.lastEmit, key)
		}
	}
}

// Stop signals the cleanup goroutine to exit.
func (c *FindingCooldown) Stop() {
	close(c.done)
}

func (c *FindingCooldown) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.Cleanup()
		}
	}
}

package detection

import (
	"sync"
	"time"
)

// dnsEntry records a single DNS query observation.
type dnsEntry struct {
	domain string
	ts     time.Time
}

// DNSCache keeps a short-lived, per-PID record of DNS queries so that
// net_connect detection rules can correlate an IP with the domain that
// was queried moments before the connection was made.
//
// Thread-safe. Entries expire after maxAge (default 60s).
type DNSCache struct {
	mu     sync.Mutex
	byPID  map[int][]dnsEntry
	maxAge time.Duration
}

// NewDNSCache creates a DNS correlation cache with the given TTL.
func NewDNSCache(maxAge time.Duration) *DNSCache {
	return &DNSCache{
		byPID:  make(map[int][]dnsEntry),
		maxAge: maxAge,
	}
}

// Record stores a DNS query observation for a PID.
func (c *DNSCache) Record(pid int, domain string, ts time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byPID[pid] = append(c.byPID[pid], dnsEntry{domain: domain, ts: ts})

	// Lazy eviction: trim entries older than maxAge for this PID.
	cutoff := ts.Add(-c.maxAge)
	entries := c.byPID[pid]
	start := 0
	for start < len(entries) && entries[start].ts.Before(cutoff) {
		start++
	}
	if start > 0 {
		c.byPID[pid] = entries[start:]
	}
}

// Lookup returns the most recent domain queried by the given PID
// within maxAge before the reference timestamp. Returns "" if none found.
func (c *DNSCache) Lookup(pid int, before time.Time) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries := c.byPID[pid]
	if len(entries) == 0 {
		return ""
	}

	cutoff := before.Add(-c.maxAge)
	// Walk backwards to find the most recent entry within the window.
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.ts.After(cutoff) && !e.ts.After(before) {
			return e.domain
		}
	}
	return ""
}

// LookupAll returns all unique domains queried by the given PID
// within maxAge before the reference timestamp.
func (c *DNSCache) LookupAll(pid int, before time.Time) []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries := c.byPID[pid]
	if len(entries) == 0 {
		return nil
	}

	cutoff := before.Add(-c.maxAge)
	seen := make(map[string]bool)
	var result []string
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.ts.After(cutoff) && !e.ts.After(before) {
			if !seen[e.domain] {
				seen[e.domain] = true
				result = append(result, e.domain)
			}
		}
	}
	return result
}

// Cleanup removes all entries older than maxAge relative to now.
// Call periodically (e.g. every 5 minutes) to prevent unbounded growth.
func (c *DNSCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := time.Now().Add(-c.maxAge)
	for pid, entries := range c.byPID {
		start := 0
		for start < len(entries) && entries[start].ts.Before(cutoff) {
			start++
		}
		if start >= len(entries) {
			delete(c.byPID, pid)
		} else if start > 0 {
			c.byPID[pid] = entries[start:]
		}
	}
}

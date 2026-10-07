//go:build windows

package windows

import (
	"sync"
	"time"
)

// CmdlineCache stores process command lines from Windows Event Log (Event 4688)
// keyed by PID with automatic TTL expiration. The exec_runner checks this cache
// before falling back to PEB reading.
//
// Flow:
//   1. AuditSubscriber receives Event 4688 → CmdlineCache.Put(pid, cmdline)
//   2. ETW ProcessStart fires → exec_runner calls CmdlineCache.Get(pid)
//   3. If hit → use cached cmdline (100% reliable, written by kernel)
//   4. If miss → fallback to PEB read (process started before subscriber)
//   5. Entries expire after TTL (default 10s) to prevent memory leak
type CmdlineCache struct {
	mu    sync.RWMutex
	cache map[uint32]cmdlineEntry
	ttl   time.Duration
}

type cmdlineEntry struct {
	cmdline   string
	user      string
	timestamp time.Time
}

// NewCmdlineCache creates a cache with the given TTL.
// Typical TTL: 10 seconds (Event 4688 arrives within 1-5ms of process creation).
func NewCmdlineCache(ttl time.Duration) *CmdlineCache {
	c := &CmdlineCache{
		cache: make(map[uint32]cmdlineEntry),
		ttl:   ttl,
	}
	// Start cleanup goroutine
	go c.cleanupLoop()
	return c
}

// Put stores a command line for a PID. Called by the AuditSubscriber when
// Event 4688 arrives.
func (c *CmdlineCache) Put(pid uint32, cmdline, user string) {
	c.mu.Lock()
	c.cache[pid] = cmdlineEntry{
		cmdline:   cmdline,
		user:      user,
		timestamp: time.Now(),
	}
	c.mu.Unlock()
}

// Get retrieves the cached command line for a PID.
// Returns (cmdline, user, true) if found and not expired, ("", "", false) otherwise.
func (c *CmdlineCache) Get(pid uint32) (string, string, bool) {
	c.mu.RLock()
	entry, ok := c.cache[pid]
	c.mu.RUnlock()

	if !ok {
		return "", "", false
	}
	if time.Since(entry.timestamp) > c.ttl {
		// Expired — delete and return miss
		c.mu.Lock()
		delete(c.cache, pid)
		c.mu.Unlock()
		return "", "", false
	}
	return entry.cmdline, entry.user, true
}

// GetWithWait tries to get a cmdline, waiting up to maxWait for it to appear.
// This handles the case where ETW ProcessStart fires before Event 4688 arrives.
func (c *CmdlineCache) GetWithWait(pid uint32, maxWait time.Duration) (string, string, bool) {
	// Fast path — already cached
	if cmd, user, ok := c.Get(pid); ok {
		return cmd, user, true
	}

	// Wait with exponential backoff: 1ms, 2ms, 4ms, 8ms, 16ms, 32ms
	deadline := time.Now().Add(maxWait)
	wait := time.Millisecond
	for time.Now().Before(deadline) {
		time.Sleep(wait)
		if cmd, user, ok := c.Get(pid); ok {
			return cmd, user, true
		}
		wait *= 2
		if wait > 32*time.Millisecond {
			wait = 32 * time.Millisecond
		}
	}
	return "", "", false
}

// cleanupLoop removes expired entries every 30 seconds.
func (c *CmdlineCache) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for pid, entry := range c.cache {
			if now.Sub(entry.timestamp) > c.ttl {
				delete(c.cache, pid)
			}
		}
		c.mu.Unlock()
	}
}

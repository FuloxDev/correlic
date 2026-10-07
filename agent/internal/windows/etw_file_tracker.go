//go:build windows

package windows

import (
	"hash/fnv"
	"sync"
	"time"
)

// ETWFileTracker records file paths reported by ETW so the USN reconciler
// can skip events that ETW already captured. Thread-safe.
type ETWFileTracker struct {
	mu     sync.Mutex
	seen   map[uint64]time.Time // fnv64(filePath) → last-seen timestamp
	maxAge time.Duration        // entries older than this are evicted on cleanup
}

// NewETWFileTracker creates a tracker that evicts entries older than maxAge.
func NewETWFileTracker(maxAge time.Duration) *ETWFileTracker {
	return &ETWFileTracker{
		seen:   make(map[uint64]time.Time, 4096),
		maxAge: maxAge,
	}
}

// Record marks a file path as seen by ETW at the current time.
func (t *ETWFileTracker) Record(filePath string) {
	h := hashPath(filePath)
	t.mu.Lock()
	t.seen[h] = time.Now()
	t.mu.Unlock()
}

// WasSeen returns true if ETW reported this file path within the last maxAge window.
func (t *ETWFileTracker) WasSeen(filePath string) bool {
	h := hashPath(filePath)
	cutoff := time.Now().Add(-t.maxAge)
	t.mu.Lock()
	ts, ok := t.seen[h]
	t.mu.Unlock()
	return ok && ts.After(cutoff)
}

// Cleanup evicts stale entries. Call periodically to prevent unbounded growth.
func (t *ETWFileTracker) Cleanup() {
	cutoff := time.Now().Add(-t.maxAge)
	t.mu.Lock()
	for h, ts := range t.seen {
		if ts.Before(cutoff) {
			delete(t.seen, h)
		}
	}
	t.mu.Unlock()
}

func hashPath(p string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(p))
	return h.Sum64()
}

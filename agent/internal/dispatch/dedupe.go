package dispatch

import (
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
)

const (
	DefaultDedupeWindowMs = 500
)

// Deduper drops duplicate process_exec events with the same (ppid, exe_path) within a time window.
// Only the first occurrence is allowed; repeats within the window are dropped.
type Deduper interface {
	// Allow returns false if this event should be dropped as a duplicate (same ppid+exe_path seen recently).
	Allow(evt event.Event) bool
}

type dedupeKey struct {
	ppid    int
	exePath string
}

type dedupeEntry struct {
	lastSeen time.Time
}

// windowDedupe implements Deduper with a map and periodic eviction of entries older than the window.
type windowDedupe struct {
	window time.Duration
	mu     sync.Mutex
	m      map[dedupeKey]dedupeEntry
}

// NewWindowDedupe creates a Deduper that drops (ppid, exe_path) duplicates within the given window.
func NewWindowDedupe(window time.Duration) Deduper {
	if window <= 0 {
		window = DefaultDedupeWindowMs * time.Millisecond
	}
	return &windowDedupe{
		window: window,
		m:      make(map[dedupeKey]dedupeEntry),
	}
}

// DedupeWindowFromEnv returns the dedupe window from AGENT_EXEC_DEDUPE_WINDOW_MS (default 500ms). 0 = disabled.
func DedupeWindowFromEnv() time.Duration {
	if s := os.Getenv("AGENT_EXEC_DEDUPE_WINDOW_MS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			if n == 0 {
				return 0
			}
			return time.Duration(n) * time.Millisecond
		}
	}
	return DefaultDedupeWindowMs * time.Millisecond
}

// NewDedupeFromEnv returns a Deduper when AGENT_EXEC_DEDUPE_WINDOW_MS is set and > 0; otherwise nil.
func NewDedupeFromEnv() Deduper {
	w := DedupeWindowFromEnv()
	if w <= 0 {
		return nil
	}
	return NewWindowDedupe(w)
}

func (d *windowDedupe) Allow(evt event.Event) bool {
	if evt.Type != "process_exec" || evt.Actor == nil {
		return true
	}
	key := dedupeKey{ppid: evt.Actor.PPID, exePath: evt.Actor.ExePath}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	// Evict entries older than window to avoid unbounded growth
	for k, e := range d.m {
		if now.Sub(e.lastSeen) > d.window {
			delete(d.m, k)
		}
	}
	if e, ok := d.m[key]; ok && now.Sub(e.lastSeen) <= d.window {
		return false
	}
	d.m[key] = dedupeEntry{lastSeen: now}
	return true
}

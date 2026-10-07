package dispatch

import (
	"log/slog"
	"sync"
	"time"
)

const dropLogThrottle = time.Minute

// DropStats holds drop counters by reason and event type, and throttled logging.
type DropStats struct {
	mu sync.Mutex

	RateLimited    map[string]int64
	BufferFull     map[string]int64
	Deduplicated   int64
	CleanupReasons map[string]int64 // exec cleanup: reason -> count (e.g. exec_ephemeral, exec_helper_burst)

	lastLog map[string]time.Time // key "type:reason"
}

func NewDropStats() *DropStats {
	return &DropStats{
		RateLimited:    make(map[string]int64),
		BufferFull:     make(map[string]int64),
		CleanupReasons: make(map[string]int64),
		lastLog:        make(map[string]time.Time),
	}
}

func (s *DropStats) AddRateLimited(eventType string) {
	s.mu.Lock()
	s.RateLimited[eventType]++
	s.mu.Unlock()
}

func (s *DropStats) AddBufferFull(eventType string) {
	s.mu.Lock()
	s.BufferFull[eventType]++
	s.mu.Unlock()
}

func (s *DropStats) AddDeduplicated() {
	s.mu.Lock()
	s.Deduplicated++
	s.mu.Unlock()
}

// RecordDrop records a drop by reason (e.g. exec cleanup) and optionally logs. Used for exec_ephemeral, exec_helper_burst.
func (s *DropStats) RecordDrop(eventType, reason string) {
	s.mu.Lock()
	s.CleanupReasons[reason]++
	s.mu.Unlock()
	s.MaybeLogDrop(eventType, reason)
}

// MaybeLogDrop logs at most once per minute per (eventType, reason).
func (s *DropStats) MaybeLogDrop(eventType, reason string) {
	key := eventType + ":" + reason
	s.mu.Lock()
	last, ok := s.lastLog[key]
	now := time.Now()
	if !ok || now.Sub(last) >= dropLogThrottle {
		s.lastLog[key] = now
		s.mu.Unlock()
		slog.Info("agent drop", "reason", reason, "event_type", eventType)
		return
	}
	s.mu.Unlock()
}

// Snapshot returns a copy of current counters and optionally resets them for the next interval.
func (s *DropStats) Snapshot(reset bool) (rateLimited, bufferFull map[string]int64, deduplicated int64, cleanupReasons map[string]int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rateLimited = make(map[string]int64)
	bufferFull = make(map[string]int64)
	cleanupReasons = make(map[string]int64)
	for k, v := range s.RateLimited {
		rateLimited[k] = v
		if reset {
			s.RateLimited[k] = 0
		}
	}
	for k, v := range s.BufferFull {
		bufferFull[k] = v
		if reset {
			s.BufferFull[k] = 0
		}
	}
	for k, v := range s.CleanupReasons {
		cleanupReasons[k] = v
		if reset {
			s.CleanupReasons[k] = 0
		}
	}
	deduplicated = s.Deduplicated
	if reset {
		s.Deduplicated = 0
	}
	return rateLimited, bufferFull, deduplicated, cleanupReasons
}

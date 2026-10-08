package ingest

import (
	"log"
	"math/rand"
	"sync/atomic"

	"github.com/correlic/correlic-backend/internal/event"
)

// Sampler makes intelligent decisions about which events to keep vs. drop.
// All state is atomic, so it is safe for concurrent use without a mutex.
type Sampler struct {
	rules   *SamplingRules
	enabled atomic.Bool

	// Counters for metrics
	totalSeen    atomic.Int64
	totalKept    atomic.Int64
	totalDropped atomic.Int64
}

// NewSampler creates a new event sampler with the given rules.
func NewSampler(rules *SamplingRules) *Sampler {
	s := &Sampler{
		rules: rules,
	}
	s.enabled.Store(true)
	return s
}

// ShouldKeep returns true if the event should be kept (not sampled out).
func (s *Sampler) ShouldKeep(evt *event.Event) bool {
	s.totalSeen.Add(1)

	if !s.enabled.Load() {
		// Sampling disabled - keep everything
		s.totalKept.Add(1)
		return true
	}

	// ALWAYS keep events from AI processes — these are the primary data source
	// for the correlation engine and detection rules. Sampling was designed for
	// high-volume non-AI noise on busy servers, not for AI agent activity which
	// is the core product use case.
	if isAIEvent(evt) {
		s.totalKept.Add(1)
		return true
	}

	// Tier 1: Always keep critical event types
	if s.rules.IsAlwaysKeep(evt.Type) {
		s.totalKept.Add(1)
		return true
	}

	// SECURITY: Check for suspicious activity FIRST before dropping benign processes
	// This prevents malicious scripts using common utilities (cat, ls, etc.) from being dropped
	if s.rules.IsSuspicious(evt) {
		s.totalKept.Add(1)
		return true
	}

	// Tier 4: Drop known benign processes (only if NOT suspicious)
	if s.rules.IsBenignProcess(evt) {
		s.totalDropped.Add(1)
		return false
	}

	// Tier 2 & 3: Sample based on rate
	sampleRate := s.rules.GetSampleRate(evt.Type)
	if sampleRate >= 1.0 {
		s.totalKept.Add(1)
		return true
	}
	if sampleRate <= 0.0 {
		s.totalDropped.Add(1)
		return false
	}

	// Probabilistic sampling
	if rand.Float64() < sampleRate {
		s.totalKept.Add(1)
		return true
	}

	s.totalDropped.Add(1)
	return false
}

// Enable enables sampling.
func (s *Sampler) Enable() {
	s.enabled.Store(true)
	log.Printf("sampler: enabled")
}

// Disable disables sampling (keeps all events).
func (s *Sampler) Disable() {
	s.enabled.Store(false)
	log.Printf("sampler: disabled (all events kept)")
}

// IsEnabled returns true if sampling is enabled.
func (s *Sampler) IsEnabled() bool {
	return s.enabled.Load()
}

// Stats returns current sampling statistics.
func (s *Sampler) Stats() SamplerStats {
	return SamplerStats{
		TotalSeen:    s.totalSeen.Load(),
		TotalKept:    s.totalKept.Load(),
		TotalDropped: s.totalDropped.Load(),
		KeepRate:     s.keepRate(),
		DropRate:     s.dropRate(),
	}
}

// keepRate returns the percentage of events kept.
func (s *Sampler) keepRate() float64 {
	total := s.totalSeen.Load()
	if total == 0 {
		return 1.0
	}
	return float64(s.totalKept.Load()) / float64(total)
}

// dropRate returns the percentage of events dropped.
func (s *Sampler) dropRate() float64 {
	total := s.totalSeen.Load()
	if total == 0 {
		return 0.0
	}
	return float64(s.totalDropped.Load()) / float64(total)
}

// ResetStats resets all counters.
func (s *Sampler) ResetStats() {
	seen := s.totalSeen.Load()
	kept := s.totalKept.Load()
	dropped := s.totalDropped.Load()
	log.Printf("sampler: stats reset — seen=%d kept=%d dropped=%d keep_rate=%.2f%%",
		seen, kept, dropped, s.keepRate()*100)
	s.totalSeen.Store(0)
	s.totalKept.Store(0)
	s.totalDropped.Store(0)
}

// isAIEvent returns true if the event originated from an AI agent process.
// Checks for ai_session_id (set by session-tracked agents) or the legacy
// is_ai flag (set by the agent's emit sink).
func isAIEvent(evt *event.Event) bool {
	if evt.Context != nil {
		if _, ok := evt.Context["ai_session_id"]; ok {
			return true
		}
		if isAI, ok := evt.Context["is_ai"].(bool); ok && isAI {
			return true
		}
	}
	return false
}

// SamplerStats contains sampling statistics.
type SamplerStats struct {
	TotalSeen    int64
	TotalKept    int64
	TotalDropped int64
	KeepRate     float64
	DropRate     float64
}

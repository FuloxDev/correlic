// Package patterns keeps the lineage tracker's AI pattern list in sync with
// the backend (GET /api/v1/ai/patterns), with a disk cache so the agent can
// start detecting AI processes before the backend is reachable.
package patterns

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/correlic/correlic-agent/internal/lineage"
)

// DefaultRefreshInterval is how often the pattern list is re-fetched.
const DefaultRefreshInterval = 5 * time.Minute

// CacheFileName is the cache file inside the state directory.
const CacheFileName = "ai_patterns.json"

// Fetcher fetches the pattern list from the backend.
type Fetcher interface {
	GetAIPatterns(ctx context.Context) ([]string, error)
}

// Manager loads, refreshes and caches AI patterns.
type Manager struct {
	fetch       Fetcher
	tracker     *lineage.LineageTracker
	cachePath   string
	logger      *slog.Logger
	interval    time.Duration
	retryDelays []time.Duration
	ready       chan struct{}
}

type cacheFile struct {
	Patterns []string  `json:"patterns"`
	SavedAt  time.Time `json:"saved_at"`
}

// New creates a Manager. cachePath may be empty to disable the disk cache.
func New(fetch Fetcher, tracker *lineage.LineageTracker, cachePath string, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	if tracker == nil {
		tracker = lineage.GetLineageTracker()
	}
	return &Manager{
		fetch:       fetch,
		tracker:     tracker,
		cachePath:   cachePath,
		logger:      logger.With("component", "ai_patterns"),
		interval:    DefaultRefreshInterval,
		retryDelays: []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second},
		ready:       make(chan struct{}),
	}
}

// Ready is closed once the initial fetch cycle has completed (successfully or
// after exhausting retries). Startup scans should wait on it so they run with
// the freshest pattern list available.
func (m *Manager) Ready() <-chan struct{} {
	return m.ready
}

// LoadCache applies the cached pattern list to the tracker, if present.
// Returns the number of cached patterns.
func (m *Manager) LoadCache() int {
	if m.cachePath == "" {
		return 0
	}
	data, err := os.ReadFile(m.cachePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			m.logger.Warn("failed to read AI pattern cache", "path", m.cachePath, "error", err)
		}
		return 0
	}
	var cf cacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		m.logger.Warn("corrupt AI pattern cache, ignoring", "path", m.cachePath, "error", err)
		return 0
	}
	if len(cf.Patterns) == 0 {
		return 0
	}
	m.tracker.UpdatePatterns(cf.Patterns)
	m.logger.Info("loaded AI patterns from cache", "count", len(cf.Patterns), "saved_at", cf.SavedAt.Format(time.RFC3339))
	return len(cf.Patterns)
}

// Run performs the initial fetch (with bounded, ctx-aware retries), closes
// Ready, then refreshes on a ticker until ctx is done. Call LoadCache first.
func (m *Manager) Run(ctx context.Context) {
	m.initialFetch(ctx)
	close(m.ready)
	m.warnIfEmpty()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Refresh(ctx); err != nil {
				m.logger.Warn("AI pattern refresh failed; keeping current list",
					"error", err, "active", m.tracker.PatternCount())
				m.warnIfEmpty()
			}
		}
	}
}

func (m *Manager) initialFetch(ctx context.Context) {
	var lastErr error
	for attempt := 0; ; attempt++ {
		lastErr = m.Refresh(ctx)
		if lastErr == nil {
			return
		}
		if attempt >= len(m.retryDelays) {
			break
		}
		delay := m.retryDelays[attempt]
		m.logger.Warn("failed to fetch AI patterns, retrying",
			"attempt", attempt+1, "max_attempts", len(m.retryDelays)+1, "retry_in", delay, "error", lastErr)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
	m.logger.Warn("failed to fetch AI patterns after retries; will retry in the background",
		"error", lastErr, "retry_in", m.interval, "active", m.tracker.PatternCount())
}

// Refresh fetches the pattern list once, applies it and updates the cache.
func (m *Manager) Refresh(ctx context.Context) error {
	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := m.fetch.GetAIPatterns(fetchCtx)
	if err != nil {
		return err
	}
	m.tracker.UpdatePatterns(raw)
	m.logger.Info("loaded AI patterns from backend", "count", len(raw), "active", m.tracker.PatternCount())
	m.saveCache(raw)
	return nil
}

func (m *Manager) warnIfEmpty() {
	if m.tracker.PatternCount() == 0 {
		m.logger.Warn("running with an empty AI pattern list: no AI processes will be detected until patterns are fetched",
			"endpoint", "GET /api/v1/ai/patterns", "retry_in", m.interval)
	}
}

func (m *Manager) saveCache(raw []string) {
	if m.cachePath == "" || len(raw) == 0 {
		return
	}
	data, err := json.MarshalIndent(cacheFile{Patterns: raw, SavedAt: time.Now().UTC()}, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(m.cachePath), 0700); err != nil {
		m.logger.Warn("failed to create AI pattern cache dir", "path", m.cachePath, "error", err)
		return
	}
	tmp := m.cachePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		m.logger.Warn("failed to write AI pattern cache", "path", m.cachePath, "error", err)
		return
	}
	if err := os.Rename(tmp, m.cachePath); err != nil {
		m.logger.Warn("failed to replace AI pattern cache", "path", m.cachePath, "error", err)
		_ = os.Remove(tmp)
	}
}

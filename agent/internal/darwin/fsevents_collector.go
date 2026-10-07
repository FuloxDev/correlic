//go:build darwin

package darwin

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// FileEvent is emitted when a watched file or directory is accessed.
type FileEvent struct {
	Path      string
	Timestamp time.Time
}

// FSEventsCollector monitors sensitive directories for file access using polling.
// MVP approach: poll target directories for mtime changes.
// Phase 2 (ESF) will replace this with real-time ES_EVENT_TYPE_NOTIFY_OPEN.
type FSEventsCollector struct {
	watchPaths []string
	events     chan FileEvent
	interval   time.Duration
	logger     *slog.Logger

	// Track last-seen modification times to detect changes.
	lastSeen map[string]time.Time
}

// DefaultWatchPaths returns the default credential directories to monitor on macOS.
func DefaultWatchPaths() []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/root"
	}
	return []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".kube"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".azure"),
		filepath.Join(home, ".gcloud"),
		filepath.Join(home, ".config", "gcloud"),
		filepath.Join(home, "Library", "Keychains"),
	}
}

// NewFSEventsCollector creates a new file system monitoring collector.
func NewFSEventsCollector(logger *slog.Logger, watchPaths []string, interval time.Duration) *FSEventsCollector {
	if logger == nil {
		logger = slog.Default()
	}
	if len(watchPaths) == 0 {
		watchPaths = DefaultWatchPaths()
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &FSEventsCollector{
		watchPaths: watchPaths,
		events:     make(chan FileEvent, 1024),
		interval:   interval,
		logger:     logger,
		lastSeen:   make(map[string]time.Time),
	}
}

// Events returns the channel of file events.
func (c *FSEventsCollector) Events() <-chan FileEvent {
	return c.events
}

// Start runs the polling loop. Blocks until ctx is cancelled.
func (c *FSEventsCollector) Start(ctx context.Context) {
	c.logger.Info("FSEvents collector started", "paths", c.watchPaths, "interval", c.interval)

	// Initial scan to populate lastSeen (don't emit events for existing state).
	c.scanAll(false)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("FSEvents collector stopping")
			close(c.events)
			return
		case <-ticker.C:
			c.scanAll(true)
		}
	}
}

func (c *FSEventsCollector) scanAll(emit bool) {
	for _, dir := range c.watchPaths {
		c.scanDir(dir, emit)
	}
}

func (c *FSEventsCollector) scanDir(dir string, emit bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Directory may not exist (e.g. no .aws configured) — that's fine.
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fullPath := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		mtime := info.ModTime()
		prev, seen := c.lastSeen[fullPath]
		c.lastSeen[fullPath] = mtime

		if emit && (!seen || mtime.After(prev)) {
			c.events <- FileEvent{
				Path:      fullPath,
				Timestamp: mtime,
			}
		}
	}
}

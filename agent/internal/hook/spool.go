package hook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/transport"
)

const (
	// SpoolMaxFiles bounds the spool; the oldest files are dropped beyond it.
	SpoolMaxFiles = 500
	// spoolDrainBatch is the most spooled events sent per invocation batch
	// (the backend accepts up to 500 per request).
	spoolDrainBatch = 100
	// spoolMaxAge drops events the backend would reject as too old (7 days).
	spoolMaxAge = 6 * 24 * time.Hour
	spoolDir    = "spool"
)

// Spool keeps undelivered events on disk so the next invocation can retry.
type Spool struct {
	Dir    string
	Logger *slog.Logger
}

// NewSpool returns the spool under cacheDir.
func NewSpool(cacheDir string, logger *slog.Logger) *Spool {
	return &Spool{Dir: filepath.Join(cacheDir, spoolDir), Logger: logger}
}

// Add writes one event to the spool, dropping the oldest files beyond
// SpoolMaxFiles.
func (s *Spool) Add(evt event.Event) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%020d-%s.json", evt.Timestamp.UnixNano(), shortID(evt.ID))
	if err := os.WriteFile(filepath.Join(s.Dir, name), data, 0o600); err != nil {
		return err
	}
	names, err := s.list()
	if err != nil {
		return nil
	}
	for len(names) > SpoolMaxFiles {
		_ = os.Remove(filepath.Join(s.Dir, names[0]))
		names = names[1:]
	}
	return nil
}

// Len returns the number of spooled files.
func (s *Spool) Len() int {
	names, _ := s.list()
	return len(names)
}

// Sender delivers canonical events (the transport in production).
type Sender interface {
	SendCanonicalEvents(ctx context.Context, events []event.Event) error
}

// Drain sends spooled events oldest-first in batches until the spool is empty,
// ctx expires, or a delivery fails. Delivered and permanently rejected
// batches are removed; a transient failure keeps the files for next time.
// Returns the number of events delivered.
func (s *Spool) Drain(ctx context.Context, sender Sender, now time.Time) int {
	names, err := s.list()
	if err != nil || len(names) == 0 {
		return 0
	}
	sent := 0
	for len(names) > 0 && ctx.Err() == nil {
		n := min(spoolDrainBatch, len(names))
		batch := names[:n]
		names = names[n:]

		var events []event.Event
		var files []string // batch entries actually sent
		for _, name := range batch {
			raw, err := os.ReadFile(filepath.Join(s.Dir, name))
			if err != nil {
				continue
			}
			var evt event.Event
			if err := json.Unmarshal(raw, &evt); err != nil || now.Sub(evt.Timestamp) > spoolMaxAge {
				_ = os.Remove(filepath.Join(s.Dir, name)) // corrupt or too old
				continue
			}
			events = append(events, evt)
			files = append(files, name)
		}
		if len(events) == 0 {
			continue
		}
		err := sender.SendCanonicalEvents(ctx, events)
		switch {
		case err == nil:
			sent += len(events)
		case transport.IsAuthError(err) || transport.IsPermanent(err):
			s.Logger.Warn("spool: backend rejected spooled events; dropping", "count", len(events), "error", err)
		default:
			s.Logger.Debug("spool: delivery failed; keeping", "count", len(events), "error", err)
			return sent
		}
		for _, name := range files {
			_ = os.Remove(filepath.Join(s.Dir, name))
		}
	}
	return sent
}

func (s *Spool) list() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

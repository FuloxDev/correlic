package approvals

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/model"
	"github.com/correlic/correlic-agent/internal/notify"
	"github.com/correlic/correlic-agent/internal/transport"
)

type Watcher struct {
	Transport transport.Transport
	AgentID   string
	Interval  time.Duration
	UIURL     string

	seen map[string]struct{}
}

func NewWatcher(t transport.Transport, agentID string, interval time.Duration, uiURL string) *Watcher {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &Watcher{
		Transport: t,
		AgentID:   agentID,
		Interval:  interval,
		UIURL:     strings.TrimSpace(uiURL),
		seen:      make(map[string]struct{}),
	}
}

func (w *Watcher) Start(ctx context.Context) {
	if w.Transport == nil || w.AgentID == "" {
		slog.Warn("approvals watcher disabled (missing dependencies)")
		return
	}
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.pollOnce(ctx)
		}
	}
}

func (w *Watcher) pollOnce(ctx context.Context) {
	approvals, err := w.Transport.ListApprovals(ctx, "pending", w.AgentID, 50)
	if err != nil {
		slog.Debug("approvals poll failed", "error", err)
		return
	}
	for _, a := range approvals {
		if a.ID == "" {
			continue
		}
		if _, ok := w.seen[a.ID]; ok {
			continue
		}
		w.seen[a.ID] = struct{}{}
		msg := approvalSummary(a)
		if w.UIURL != "" {
			msg += "\nOpen: " + w.UIURL
		}
		notify.Local("Correlic: approval required", msg)
	}
}

func approvalSummary(a model.Approval) string {
	// Best-effort: show kind and a small subject snippet.
	if len(a.Subject) > 0 {
		var m map[string]any
		if err := json.Unmarshal(a.Subject, &m); err == nil {
			if ru, ok := m["remote_url"].(string); ok && ru != "" {
				return a.Kind + ": " + ru
			}
			if rid, ok := m["repo_id"].(string); ok && rid != "" {
				return a.Kind + ": " + rid
			}
		}
	}
	return a.Kind
}


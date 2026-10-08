package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/correlic/correlic-backend/internal/correlation"
	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/process"
)

func execClassFromContext(ctx map[string]any) string {
	if ctx == nil {
		return ""
	}
	v, ok := ctx["exec_class"]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

const defaultTimelineWindowSeconds = 90

// TimelineHandler returns a time-windowed CorrelatedContext around an anchor event.
// GET /timeline?event_id=...&window_seconds=...
// No auth. Deterministic JSON output.
func TimelineHandler(builder *correlation.Builder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			MethodNotAllowed(w, http.MethodGet)
			return
		}

		eventID := r.URL.Query().Get("event_id")
		if eventID == "" {
			http.Error(w, `missing query parameter "event_id"`, http.StatusBadRequest)
			return
		}

		windowSeconds := defaultTimelineWindowSeconds
		if s := r.URL.Query().Get("window_seconds"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 0 {
				http.Error(w, `"window_seconds" must be a non-negative integer`, http.StatusBadRequest)
				return
			}
			windowSeconds = n
		}

		window := time.Duration(windowSeconds) * time.Second
		ctx := r.Context()
		cc, err := builder.Build(ctx, eventID, window)
		if err != nil {
			if err == correlation.ErrAnchorNotFound {
				http.Error(w, "anchor event not found", http.StatusNotFound)
				return
			}
			InternalErr(w, "build timeline", err)
			return
		}

		// De-emphasize non-primary process_exec in timeline (exec normalization).
		for i := range cc.Events {
			e := &cc.Events[i]
			if e.Type == "process_exec" && execClassFromContext(e.Context) != "primary" {
				e.Style = "muted"
			}
		}

		// Lifecycle enrichment: for each process_exec, attach duration_ms, exited, and derived annotations.
		lifecycles := process.BuildLifecyclesFromEvents(cc.Events)
		byPID := process.LifecycleViewByPID(lifecycles)
		byAnn := process.LifecycleAnnotationsByPID(lifecycles)
		for i := range cc.Events {
			e := &cc.Events[i]
			if e.Type != "process_exec" || e.Process == nil {
				continue
			}
			if v, ok := byPID[e.Process.PID]; ok {
				e.Lifecycle = &event.LifecycleInfo{DurationMs: v.DurationMs, Exited: v.Exited}
			}
			if ann := byAnn[e.Process.PID]; ann != nil {
				if e.Context == nil {
					e.Context = make(map[string]any)
				}
				e.Context["lifecycle_class"] = ann.Class
				if ann.ShortLived {
					e.Context["short_lived"] = true
				}
				if ann.Daemonized {
					e.Context["daemonized"] = true
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(cc)
	})
}

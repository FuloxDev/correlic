package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
)

// BlockEventsHandler manages block event queries and agent reporting.
type BlockEventsHandler struct {
	store     *storage.BlockEventStore
	ruleStore *storage.BlockRuleStore
}

func NewBlockEventsHandler(store *storage.BlockEventStore, ruleStore *storage.BlockRuleStore) *BlockEventsHandler {
	return &BlockEventsHandler{store: store, ruleStore: ruleStore}
}

// ListBlockEvents handles GET /api/v1/block-events
// Query params: host_id, since (RFC3339), limit (int, default 100)
func (h *BlockEventsHandler) ListBlockEvents(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	hostID := r.URL.Query().Get("host_id")

	since := time.Now().Add(-24 * time.Hour)
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}

	events, err := h.store.List(r.Context(), orgID, hostID, since, limit)
	if err != nil {
		log.Printf("block-events list error: %v", err)
		Internal(w)
		return
	}
	if events == nil {
		events = []storage.BlockEvent{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

// BlockEventStatsResponse wraps stats with per-rule counts.
type BlockEventStatsResponse struct {
	storage.BlockEventStats
	ByRule map[int]int64 `json:"by_rule"`
}

// GetBlockEventStats handles GET /api/v1/block-events/stats
// Query param: since (RFC3339, default 24h)
func (h *BlockEventsHandler) GetBlockEventStats(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	since := time.Now().Add(-24 * time.Hour)
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	stats, err := h.store.Stats(r.Context(), orgID, since)
	if err != nil {
		log.Printf("block-events stats error: %v", err)
		Internal(w)
		return
	}

	byRule, err := h.store.CountByRule(r.Context(), orgID, since)
	if err != nil {
		log.Printf("block-events count-by-rule error: %v", err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(BlockEventStatsResponse{
		BlockEventStats: stats,
		ByRule:          byRule,
	})
}

// ReportBlockEvents handles POST /api/v1/agent/block-events
// Agent reports block actions in batch.
func (h *BlockEventsHandler) ReportBlockEvents(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	var body struct {
		Events []storage.BlockEvent `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid JSON body")
		return
	}

	// Stamp orgID from auth context onto all events.
	for i := range body.Events {
		body.Events[i].OrgID = orgID
	}

	if err := h.store.InsertBatch(r.Context(), body.Events); err != nil {
		log.Printf("block-events report error: %v", err)
		Internal(w)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"accepted": len(body.Events)})
}

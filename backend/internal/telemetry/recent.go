package telemetry

import (
	"encoding/json"
	"net/http"
	"strconv"

	apierrors "github.com/correlic/correlic-backend/internal/api"
	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
)

type RecentHandler struct {
	store storage.TelemetryStore
}

func NewRecentHandler(store storage.TelemetryStore) *RecentHandler {
	return &RecentHandler{store: store}
}

func (h *RecentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apierrors.MethodNotAllowed(w, http.MethodGet)
		return
	}

	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		apierrors.Unauthorized(w, "missing org context")
		return
	}

	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		apierrors.BadRequest(w, "agent_id is required")
		return
	}

	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			apierrors.BadRequest(w, "invalid limit")
			return
		}
		limit = n
	}
	if limit > 1000 {
		limit = 1000
	}

	events, err := h.store.ListRecent(orgID, agentID, limit)
	if err != nil {
		apierrors.Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

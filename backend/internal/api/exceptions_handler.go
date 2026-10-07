package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
)

// ExceptionsHandler handles CRUD for per-rule detection exceptions.
type ExceptionsHandler struct {
	store *storage.RuleExceptionStore
}

func NewExceptionsHandler(store *storage.RuleExceptionStore) *ExceptionsHandler {
	return &ExceptionsHandler{store: store}
}

// ListExceptions handles GET /api/v1/exceptions
func (h *ExceptionsHandler) ListExceptions(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	exceptions := h.store.List(orgID)
	if exceptions == nil {
		exceptions = []storage.RuleException{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exceptions)
}

// CreateException handles POST /api/v1/exceptions
// Body: { "detection_id": "ai.credential_access", "host_id": "*", "context_key": "", "context_value": "", "reason": "..." }
func (h *ExceptionsHandler) CreateException(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	var body struct {
		DetectionID  string `json:"detection_id"`
		HostID       string `json:"host_id"`
		ContextKey   string `json:"context_key"`
		ContextValue string `json:"context_value"`
		MatchMode    string `json:"match_mode"`
		Reason       string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid JSON body")
		return
	}
	if body.DetectionID == "" {
		BadRequest(w, "detection_id is required")
		return
	}
	if body.HostID == "" {
		body.HostID = "*"
	}
	if body.MatchMode == "" {
		body.MatchMode = "exact"
	}
	if body.MatchMode != "exact" && body.MatchMode != "prefix" {
		BadRequest(w, "match_mode must be 'exact' or 'prefix'")
		return
	}

	exc := storage.RuleException{
		OrgID:        orgID,
		DetectionID:  body.DetectionID,
		HostID:       body.HostID,
		ContextKey:   body.ContextKey,
		ContextValue: body.ContextValue,
		MatchMode:    body.MatchMode,
		Reason:       body.Reason,
	}

	id, err := h.store.Insert(r.Context(), exc)
	if err != nil {
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
}

// DeleteException handles DELETE /api/v1/exceptions/{id}
func (h *ExceptionsHandler) DeleteException(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// Extract ID from URL path: /api/v1/exceptions/42
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	rawID := parts[len(parts)-1]
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		BadRequest(w, "invalid exception id")
		return
	}

	if err := h.store.Delete(r.Context(), orgID, id); err != nil {
		NotFound(w, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/storage"
)

// NeverBaselinesHandler manages the org-scoped never-baseline list.
type NeverBaselinesHandler struct {
	store *storage.NeverBaselineStore
}

func NewNeverBaselinesHandler(store *storage.NeverBaselineStore) *NeverBaselinesHandler {
	return &NeverBaselinesHandler{store: store}
}

// NeverBaselineResponse is a merged view of system + user entries.
type NeverBaselineResponse struct {
	ID          int    `json:"id"`
	SignalType  string `json:"signal_type"`
	Pattern     string `json:"pattern"`
	Category    string `json:"category,omitempty"`
	Description string `json:"description"`
	Source      string `json:"source"` // "system" or "user"
	CreatedBy   string `json:"created_by,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// ListNeverBaselines handles GET /api/v1/baselines/never-baselines
// Returns system-defined rules merged with org-specific user-defined rules.
func (h *NeverBaselinesHandler) ListNeverBaselines(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	var out []NeverBaselineResponse

	// System-defined (hardcoded) entries — visible to all orgs, not deletable.
	for _, e := range detection.SystemNeverBaselineEntries() {
		out = append(out, NeverBaselineResponse{
			ID:         0,
			SignalType: e.SignalType,
			Pattern:    e.Pattern,
			Category:   e.Category,
			Source:     "system",
		})
	}

	// User-defined org-scoped entries.
	entries, err := h.store.List(r.Context(), orgID)
	if err != nil {
		log.Printf("never-baselines list error: %v", err)
		Internal(w)
		return
	}
	for _, e := range entries {
		out = append(out, NeverBaselineResponse{
			ID:          e.ID,
			SignalType:  e.SignalType,
			Pattern:     e.Pattern,
			Description: e.Description,
			Source:      "user",
			CreatedBy:   e.CreatedBy,
			CreatedAt:   e.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	if out == nil {
		out = []NeverBaselineResponse{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// CreateNeverBaseline handles POST /api/v1/baselines/never-baselines
// Returns 409 with conflict details if existing baselines match the pattern.
func (h *NeverBaselinesHandler) CreateNeverBaseline(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	var body struct {
		SignalType  string `json:"signal_type"`
		Pattern     string `json:"pattern"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid JSON body")
		return
	}
	if body.SignalType == "" || body.Pattern == "" {
		BadRequest(w, "signal_type and pattern are required")
		return
	}

	// Reject if pattern is already on the system never-baseline list.
	if detection.IsNeverBaselinePattern(body.SignalType, body.Pattern, nil, "") {
		BadRequest(w, "this pattern is already covered by a built-in system rule")
		return
	}

	_, actorID, _ := middleware.ActorFromContext(r.Context())
	createdBy := actorID
	if createdBy == "" {
		createdBy = "user"
	}

	entry, err := h.store.Add(r.Context(), orgID, body.SignalType, body.Pattern, body.Description, createdBy)
	if err != nil {
		var conflictErr storage.ErrPatternAlreadyBaselined
		if errors.As(err, &conflictErr) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]any{
				"conflict":     true,
				"baseline_ids": conflictErr.BaselineIDs,
				"message":      err.Error(),
			})
			return
		}
		log.Printf("never-baselines create error: %v", err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(NeverBaselineResponse{
		ID:          entry.ID,
		SignalType:  entry.SignalType,
		Pattern:     entry.Pattern,
		Description: entry.Description,
		Source:      "user",
		CreatedBy:   entry.CreatedBy,
		CreatedAt:   entry.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// DeleteNeverBaseline handles DELETE /api/v1/baselines/never-baselines/{id}
// System entries (id=0) cannot be deleted.
func (h *NeverBaselinesHandler) DeleteNeverBaseline(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	rawID := parts[len(parts)-1]
	id, err := strconv.Atoi(rawID)
	if err != nil || id <= 0 {
		BadRequest(w, "invalid id — system rules cannot be deleted")
		return
	}

	if err := h.store.Delete(r.Context(), orgID, id); err != nil {
		log.Printf("never-baselines delete error: %v", err)
		NotFound(w, "never-baseline entry not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
)

// RuleSettingsHandler handles CRUD for per-org detection rule threshold settings.
type RuleSettingsHandler struct {
	store *storage.RuleSettingsStore
}

func NewRuleSettingsHandler(store *storage.RuleSettingsStore) *RuleSettingsHandler {
	return &RuleSettingsHandler{store: store}
}

// ListSettings handles GET /api/v1/detection/settings
// Returns all custom settings for the org.
func (h *RuleSettingsHandler) ListSettings(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	settings := h.store.ListForOrg(orgID)
	if settings == nil {
		settings = []storage.RuleSetting{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(settings)
}

// UpsertSetting handles PUT /api/v1/detection/settings/{rule_id}
// Body: {"key": "project_file_count", "value": "50"}
func (h *RuleSettingsHandler) UpsertSetting(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// Extract rule_id from URL: /api/v1/detection/settings/{rule_id}
	ruleID := extractLastPathSegment(r.URL.Path)
	if ruleID == "" || ruleID == "settings" {
		BadRequest(w, "rule_id is required in path")
		return
	}

	var body struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid JSON body")
		return
	}
	if body.Key == "" || body.Value == "" {
		BadRequest(w, "key and value are required")
		return
	}

	if err := h.store.Upsert(r.Context(), orgID, ruleID, body.Key, body.Value); err != nil {
		Internal(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeleteSetting handles DELETE /api/v1/detection/settings/{rule_id}/{key}
// Resets the setting to its default value.
func (h *RuleSettingsHandler) DeleteSetting(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// URL: /api/v1/detection/settings/{rule_id}/{key}
	// Trim trailing slash and split from the right.
	trimmed := strings.TrimSuffix(r.URL.Path, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		BadRequest(w, "rule_id and key are required in path")
		return
	}
	key := parts[len(parts)-1]
	ruleID := parts[len(parts)-2]
	if ruleID == "settings" || key == "" {
		BadRequest(w, "rule_id and key are required in path")
		return
	}

	if err := h.store.Delete(r.Context(), orgID, ruleID, key); err != nil {
		NotFound(w, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func extractLastPathSegment(path string) string {
	trimmed := strings.TrimSuffix(path, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

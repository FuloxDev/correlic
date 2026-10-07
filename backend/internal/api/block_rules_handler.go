package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
)

// BlockRulesHandler manages the org-scoped block rules.
type BlockRulesHandler struct {
	store *storage.BlockRuleStore
}

func NewBlockRulesHandler(store *storage.BlockRuleStore) *BlockRulesHandler {
	return &BlockRulesHandler{store: store}
}

// ListBlockRules handles GET /api/v1/block-rules
func (h *BlockRulesHandler) ListBlockRules(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	rules, err := h.store.List(r.Context(), orgID)
	if err != nil {
		log.Printf("block-rules list error: %v", err)
		Internal(w)
		return
	}

	// Optional filter by signal_type.
	if st := r.URL.Query().Get("signal_type"); st != "" {
		var filtered []storage.BlockRule
		for _, rule := range rules {
			if rule.SignalType == st {
				filtered = append(filtered, rule)
			}
		}
		rules = filtered
	}

	if rules == nil {
		rules = []storage.BlockRule{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

// CreateBlockRule handles POST /api/v1/block-rules
func (h *BlockRulesHandler) CreateBlockRule(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	var body struct {
		SignalType  string `json:"signal_type"`
		Pattern     string `json:"pattern"`
		Description string `json:"description"`
		KillTree    bool   `json:"kill_tree"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid JSON body")
		return
	}
	if body.SignalType == "" || body.Pattern == "" {
		BadRequest(w, "signal_type and pattern are required")
		return
	}

	_, actorID, _ := middleware.ActorFromContext(r.Context())
	createdBy := actorID
	if createdBy == "" {
		createdBy = "user"
	}

	rule, err := h.store.Add(r.Context(), orgID, body.SignalType, body.Pattern, body.Description, body.KillTree, createdBy)
	if err != nil {
		log.Printf("block-rules create error: %v", err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rule)
}

// UpdateBlockRule handles PUT /api/v1/block-rules/{id}
func (h *BlockRulesHandler) UpdateBlockRule(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	rawID := parts[len(parts)-1]
	id, err := strconv.Atoi(rawID)
	if err != nil || id <= 0 {
		BadRequest(w, "invalid id")
		return
	}

	var body struct {
		Enabled     *bool   `json:"enabled"`
		Description *string `json:"description"`
		KillTree    *bool   `json:"kill_tree"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid JSON body")
		return
	}

	if body.Enabled != nil {
		if err := h.store.Toggle(r.Context(), orgID, id, *body.Enabled); err != nil {
			log.Printf("block-rules toggle error: %v", err)
			NotFound(w, "block rule not found")
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeleteBlockRule handles DELETE /api/v1/block-rules/{id}
func (h *BlockRulesHandler) DeleteBlockRule(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	rawID := parts[len(parts)-1]
	id, err := strconv.Atoi(rawID)
	if err != nil || id <= 0 {
		BadRequest(w, "invalid id")
		return
	}

	// Check that the rule is user-created before deleting.
	rules, err := h.store.List(r.Context(), orgID)
	if err != nil {
		log.Printf("block-rules delete lookup error: %v", err)
		Internal(w)
		return
	}
	for _, rule := range rules {
		if rule.ID == id {
			if rule.Source == "system" {
				Forbidden(w, "system rules cannot be deleted")
				return
			}
			break
		}
	}

	if err := h.store.Delete(r.Context(), orgID, id); err != nil {
		log.Printf("block-rules delete error: %v", err)
		NotFound(w, "block rule not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

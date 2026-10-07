package api

import (
	"encoding/json"
	"net/http"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
)

// AgentBlockRulesHandler serves block rules to agents via polling.
type AgentBlockRulesHandler struct {
	store *storage.BlockRuleStore
}

func NewAgentBlockRulesHandler(store *storage.BlockRuleStore) *AgentBlockRulesHandler {
	return &AgentBlockRulesHandler{store: store}
}

type agentBlockRulesResponse struct {
	Version string              `json:"version"`
	Rules   []storage.BlockRule `json:"rules"`
}

// GetBlockRules handles GET /api/v1/agent/block-rules
// Returns only enabled rules for the org. Supports If-None-Match for 304 responses.
func (h *AgentBlockRulesHandler) GetBlockRules(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	version := h.store.VersionHash(orgID)

	// If the agent already has this version, return 304 Not Modified.
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" && ifNoneMatch == version {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	rules, err := h.store.ListEnabled(r.Context(), orgID)
	if err != nil {
		Internal(w)
		return
	}
	if rules == nil {
		rules = []storage.BlockRule{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", version)
	json.NewEncoder(w).Encode(agentBlockRulesResponse{
		Version: version,
		Rules:   rules,
	})
}

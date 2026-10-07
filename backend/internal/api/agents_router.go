package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/service"
	"github.com/correlic/correlic-backend/internal/storage"
)

// AgentsRouter handles /agents/{agent_id} and /agents/{agent_id}/identity.
type AgentsRouter struct {
	inventory     *service.AgentInventoryService
	identityStore storage.AgentIdentityStore
}

func NewAgentsRouter(inventory *service.AgentInventoryService, identityStore storage.AgentIdentityStore) *AgentsRouter {
	return &AgentsRouter{inventory: inventory, identityStore: identityStore}
}

func (h *AgentsRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		MethodNotAllowed(w, http.MethodGet)
		return
	}

	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	// /agents/{id}
	if len(parts) == 3 && parts[2] != "" {
		agentID := parts[2]
		a, err := h.inventory.GetAgent(orgID, agentID)
		if err != nil {
			Internal(w)
			return
		}
		if a == nil {
			NotFound(w, "agent not found")
			return
		}
		resp := model.AgentDTO{
			AgentID:     a.AgentID,
			Hostname:    a.Hostname,
			OS:          a.OS,
			Profile:     a.Profile,
			Version:     a.Version,
			State:       a.State,
			Liveness:    service.ComputeLiveness(a.LastSeenAt),
			FirstSeenAt: a.FirstSeenAt,
			LastSeenAt:  a.LastSeenAt,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// /agents/{id}/identity
	if len(parts) == 4 && parts[2] != "" && parts[3] == "identity" {
		if h.identityStore == nil {
			NotImplemented(w, "identity graph not enabled")
			return
		}
		agentID := parts[2]
		kind := strings.TrimSpace(r.URL.Query().Get("kind"))
		limit := 500
		if s := strings.TrimSpace(r.URL.Query().Get("limit")); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				limit = n
			}
		}
		items, err := h.identityStore.ListByAgent(orgID, agentID, kind, limit)
		if err != nil {
			Internal(w)
			return
		}
		byKind := make(map[string][]storage.AgentIdentityRecord)
		for _, it := range items {
			byKind[it.Kind] = append(byKind[it.Kind], it)
		}
		out := map[string]any{
			"agent_id": agentID,
			"kind":     kind,
			"items":    items,
			"by_kind":  byKind,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
		return
	}

	BadRequest(w, "invalid agent path")
}

package api

import (
	"encoding/json"
	"net/http"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/service"
)

// ListAgentsHandler is the handler for listing agents
type ListAgentsHandler struct {
	service *service.AgentInventoryService
}

// NewListAgentsHandler creates a new list agents handler
func NewListAgentsHandler(s *service.AgentInventoryService) *ListAgentsHandler {
	return &ListAgentsHandler{service: s}
}

// ServeHTTP handles list agents requests
func (h *ListAgentsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		MethodNotAllowed(w, http.MethodGet)
		return
	}

	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// For members, filter by their user_id (admins see all)
	var userID *string
	actorType, actorID, hasActor := middleware.ActorFromContext(r.Context())
	actorRole, hasRole := middleware.ActorRoleFromContext(r.Context())

	if hasActor && actorType == "user_session" && hasRole && actorRole == "member" {
		// Member users only see their own agents
		userID = &actorID
	} else if hasActor && actorType == "api_key" && hasRole && actorRole == "member" {
		// API keys with member role also filtered
		userID = &actorID
	}
	// Admins (or no role) see all agents (userID remains nil)

	agents, err := h.service.ListAgents(orgID, userID)
	if err != nil {
		Internal(w)
		return
	}

	var response []model.AgentDTO
	for _, a := range agents {
		dto := model.AgentDTO{
			AgentID:     a.AgentID,
			Hostname:    a.Hostname,
			OS:          a.OS,
			Profile:     a.Profile,
			Version:     a.Version,
			State:       a.State,
			FirstSeenAt: a.FirstSeenAt,
			LastSeenAt:  a.LastSeenAt,
		}
		if a.UserID != "" {
			dto.UserID = &a.UserID
		}
		response = append(response, dto)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

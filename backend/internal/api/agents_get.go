package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/service"
)

// GetAgentHandler is the handler for getting an agent
type GetAgentHandler struct {
	service *service.AgentInventoryService
}

// NewGetAgentHandler creates a new get agent handler
func NewGetAgentHandler(s *service.AgentInventoryService) *GetAgentHandler {
	return &GetAgentHandler{service: s}
}

// ServeHTTP handles get agent requests
func (h *GetAgentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		MethodNotAllowed(w, http.MethodGet)
		return
	}

	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// get the agent ID from the path
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 3 || parts[2] == "" {
		BadRequest(w, "invalid agent id")
		return
	}

	agentID := parts[2]

	// get the agent from the service
	a, err := h.service.GetAgent(orgID, agentID)
	if err != nil {
		Internal(w)
		return
	}
	if a == nil {
		NotFound(w, "agent not found")
		return
	}

	// create the response
	response := model.AgentDTO{
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
	if a.UserID != "" {
		response.UserID = &a.UserID
	}

	// set the content type and encode the response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

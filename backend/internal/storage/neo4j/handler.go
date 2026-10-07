package neo4j

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Handler provides HTTP handlers for graph queries.
type Handler struct {
	store *GraphStore
}

// NewHandler creates a new graph query handler.
func NewHandler(store *GraphStore) *Handler {
	return &Handler{store: store}
}

// RegisterRoutes registers graph query routes with the mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Attack chain and investigation queries
	mux.HandleFunc("GET /api/v1/graph/attack-chain", h.GetAttackChain)
	mux.HandleFunc("GET /api/v1/graph/process-tree", h.GetProcessTree)
	mux.HandleFunc("GET /api/v1/graph/related-events", h.GetRelatedEvents)
	mux.HandleFunc("GET /api/v1/graph/lateral-movement", h.GetLateralMovement)
	mux.HandleFunc("GET /api/v1/graph/session-activity", h.GetSessionActivity)
	mux.HandleFunc("GET /api/v1/graph/container-activity", h.GetContainerActivity)

	// LLM-specific endpoints
	mux.HandleFunc("POST /api/v1/graph/query", h.NaturalLanguageQuery)
}

// GetAttackChain returns the attack chain for a given event or process.
// Query params: event_id OR (pid + host_id), max_depth, time_window
func (h *Handler) GetAttackChain(w http.ResponseWriter, r *http.Request) {
	q := AttackChainQuery{
		StartEventID: r.URL.Query().Get("event_id"),
		HostID:       r.URL.Query().Get("host_id"),
		MaxDepth:     10,
	}

	if pidStr := r.URL.Query().Get("pid"); pidStr != "" {
		pid, err := strconv.ParseInt(pidStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid pid", http.StatusBadRequest)
			return
		}
		q.StartPID = pid
	}

	if depthStr := r.URL.Query().Get("max_depth"); depthStr != "" {
		depth, err := strconv.Atoi(depthStr)
		if err == nil && depth > 0 && depth <= 20 {
			q.MaxDepth = depth
		}
	}

	if windowStr := r.URL.Query().Get("time_window"); windowStr != "" {
		window, err := time.ParseDuration(windowStr)
		if err == nil {
			q.TimeWindow = window
		}
	}

	result, err := h.store.QueryAttackChain(r.Context(), q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeGraphJSON(w, result)
}

// GetProcessTree returns the process tree for a given process.
// Query params: pid, host_id
func (h *Handler) GetProcessTree(w http.ResponseWriter, r *http.Request) {
	pidStr := r.URL.Query().Get("pid")
	hostID := r.URL.Query().Get("host_id")

	if pidStr == "" || hostID == "" {
		http.Error(w, "pid and host_id required", http.StatusBadRequest)
		return
	}

	pid, err := strconv.ParseInt(pidStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid pid", http.StatusBadRequest)
		return
	}

	result, err := h.store.GetProcessTree(r.Context(), pid, hostID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeGraphJSON(w, result)
}

// GetRelatedEvents returns events related to a file path or IP.
// Query params: file_path OR ip, host_id, limit
func (h *Handler) GetRelatedEvents(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("file_path")
	ip := r.URL.Query().Get("ip")
	hostID := r.URL.Query().Get("host_id")

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	result, err := h.store.FindRelatedEvents(r.Context(), filePath, ip, hostID, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeGraphJSON(w, result)
}

// GetLateralMovement detects lateral movement patterns.
// Query params: host_id, since (duration like "24h")
func (h *Handler) GetLateralMovement(w http.ResponseWriter, r *http.Request) {
	hostID := r.URL.Query().Get("host_id")
	if hostID == "" {
		http.Error(w, "host_id required", http.StatusBadRequest)
		return
	}

	since := time.Now().Add(-24 * time.Hour) // Default: last 24 hours
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if duration, err := time.ParseDuration(sinceStr); err == nil {
			since = time.Now().Add(-duration)
		}
	}

	result, err := h.store.GetLateralMovement(r.Context(), hostID, since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeGraphJSON(w, result)
}

// GetSessionActivity returns all activity for a login session.
// Query params: session_id, host_id
func (h *Handler) GetSessionActivity(w http.ResponseWriter, r *http.Request) {
	sessionStr := r.URL.Query().Get("session_id")
	hostID := r.URL.Query().Get("host_id")

	if sessionStr == "" || hostID == "" {
		http.Error(w, "session_id and host_id required", http.StatusBadRequest)
		return
	}

	sessionID, err := strconv.ParseInt(sessionStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid session_id", http.StatusBadRequest)
		return
	}

	result, err := h.store.GetSessionActivity(r.Context(), sessionID, hostID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeGraphJSON(w, result)
}

// GetContainerActivity returns all activity within a container.
// Query params: container_id
func (h *Handler) GetContainerActivity(w http.ResponseWriter, r *http.Request) {
	containerID := r.URL.Query().Get("container_id")
	if containerID == "" {
		http.Error(w, "container_id required", http.StatusBadRequest)
		return
	}

	result, err := h.store.GetContainerActivity(r.Context(), containerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeGraphJSON(w, result)
}

// NaturalLanguageQuery accepts a natural language query for LLM processing.
// This endpoint is designed to be called by an LLM to translate queries.
func (h *Handler) NaturalLanguageQuery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query   string            `json:"query"`
		Context map[string]string `json:"context,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// For now, return a structured response that an LLM can use
	// In the future, this could integrate directly with an LLM
	response := map[string]any{
		"query_received": req.Query,
		"available_endpoints": []map[string]string{
			{"path": "/api/v1/graph/attack-chain", "description": "Find all connected events from a starting point"},
			{"path": "/api/v1/graph/process-tree", "description": "Get parent-child process relationships"},
			{"path": "/api/v1/graph/related-events", "description": "Find events by file path or IP address"},
			{"path": "/api/v1/graph/lateral-movement", "description": "Detect network + spawn patterns"},
			{"path": "/api/v1/graph/session-activity", "description": "All events in a session"},
			{"path": "/api/v1/graph/container-activity", "description": "All events in a container"},
		},
		"hint": "Parse the query and call the appropriate endpoint with parameters",
	}

	writeGraphJSON(w, response)
}

// getOrgID gets organization ID from request context or header.
func getOrgID(r *http.Request) uuid.UUID {
	if orgID, ok := r.Context().Value("org_id").(uuid.UUID); ok {
		return orgID
	}
	if orgIDStr := r.Header.Get("X-Org-ID"); orgIDStr != "" {
		if id, err := uuid.Parse(orgIDStr); err == nil {
			return id
		}
	}
	return uuid.Nil
}

func writeGraphJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

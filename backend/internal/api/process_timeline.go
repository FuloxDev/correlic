package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/query"
)

// ProcessTreeHandler returns the interactive process timeline tree
func ProcessTimelineHandler(timelineService *query.TimelineService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			MethodNotAllowed(w, http.MethodGet)
			return
		}

		orgID, ok := middleware.OrgFromContext(r.Context())
		if !ok {
			Unauthorized(w, "missing org context")
			return
		}
		_ = orgID // Will use for multi-tenant filtering later

		// Parse interval parameter (minutes)
		intervalMinutes := 60 // default 1 hour
		if intervalStr := r.URL.Query().Get("interval"); intervalStr != "" {
			if parsed, err := strconv.Atoi(intervalStr); err == nil && parsed > 0 {
				intervalMinutes = parsed
			}
		}
		since := time.Now().Add(-time.Duration(intervalMinutes) * time.Minute)

		// Parse AI-only filter
		aiOnly := false
		if val := r.URL.Query().Get("ai_only"); val == "true" {
			aiOnly = true
		}

		// Get active processes with stats
		response, err := timelineService.GetActiveProcesses(r.Context(), since, aiOnly)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
}

// ProcessActivityHandler returns detailed activity for specific processes
func ProcessActivityHandler(timelineService *query.TimelineService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			MethodNotAllowed(w, http.MethodGet)
			return
		}

		orgID, ok := middleware.OrgFromContext(r.Context())
		if !ok {
			Unauthorized(w, "missing org context")
			return
		}
		_ = orgID

		// Support both single "pid" and comma-separated "pids"
		var pids []int
		if pidStr := r.URL.Query().Get("pid"); pidStr != "" {
			if pid, err := strconv.Atoi(pidStr); err == nil {
				pids = append(pids, pid)
			}
		}
		if pidsStr := r.URL.Query().Get("pids"); pidsStr != "" {
			// Split by comma
			// For now, let's just parse the comma separated string if provided
			// Note: simpler to just use pids=1,2,3
			// But since we are modifying, let's just handle "pids" param manually splitting
			// or loop if multiple "pid" params? standard is usually ?pid=1&pid=2 but comma is easier for single param
		}

		// Let's implement robust parsing
		ids := []int{}

		// 1. Check "pid" (single)
		if val := r.URL.Query().Get("pid"); val != "" {
			if id, err := strconv.Atoi(val); err == nil {
				ids = append(ids, id)
			}
		}

		// 2. Check "pids" (comma separated)
		if val := r.URL.Query().Get("pids"); val != "" {
			// import strings
			// We need to import strings. Let's assume we can add import or use a helper
			// Parsing manually loop
			current := ""
			for _, c := range val {
				if c == ',' {
					if id, err := strconv.Atoi(current); err == nil {
						ids = append(ids, id)
					}
					current = ""
				} else {
					current += string(c)
				}
			}
			if current != "" {
				if id, err := strconv.Atoi(current); err == nil {
					ids = append(ids, id)
				}
			}
		}

		if len(ids) == 0 {
			http.Error(w, "pid or pids required", http.StatusBadRequest)
			return
		}

		hostID := r.URL.Query().Get("host_id")
		if hostID == "" {
			http.Error(w, "host_id required", http.StatusBadRequest)
			return
		}

		// Parse limit parameter (default 50)
		limit := 50
		if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
			if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		// Get network events for the processes
		activity, err := timelineService.GetProcessNetworkEvents(r.Context(), ids, hostID, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(activity)
	})
}

// ProcessNetworkSummaryHandler returns aggregated stats for a set of processes
func ProcessNetworkSummaryHandler(timelineService *query.TimelineService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			MethodNotAllowed(w, http.MethodPost)
			return
		}

		orgID, ok := middleware.OrgFromContext(r.Context())
		if !ok {
			Unauthorized(w, "missing org context")
			return
		}
		_ = orgID

		var socket struct {
			Pids   []int  `json:"pids"`
			HostID string `json:"host_id"`
		}

		if err := json.NewDecoder(r.Body).Decode(&socket); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if len(socket.Pids) == 0 {
			http.Error(w, "pids required", http.StatusBadRequest)
			return
		}
		if socket.HostID == "" {
			http.Error(w, "host_id required", http.StatusBadRequest)
			return
		}

		summary, err := timelineService.GetNetworkSummary(r.Context(), socket.Pids, socket.HostID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
	})
}

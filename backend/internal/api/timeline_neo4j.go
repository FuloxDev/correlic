package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/correlic/correlic-backend/internal/query"
)

// TimelineNeo4jHandler provides fast timeline queries using Neo4j.
func TimelineNeo4jHandler(timelineService *query.TimelineService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		eventID := r.URL.Query().Get("event_id")
		if eventID == "" {
			http.Error(w, "event_id required", http.StatusBadRequest)
			return
		}

		windowMinutes := 5
		if w := r.URL.Query().Get("window"); w != "" {
			if parsed, err := strconv.Atoi(w); err == nil && parsed > 0 {
				windowMinutes = parsed
			}
		}

		timeline, err := timelineService.GetTimeline(r.Context(), eventID, windowMinutes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(timeline)
	})
}

// ProcessTreeHandler returns process hierarchy using Neo4j.
func ProcessTreeHandler(timelineService *query.TimelineService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		pidStr := r.URL.Query().Get("pid")
		if pidStr == "" {
			http.Error(w, "pid required", http.StatusBadRequest)
			return
		}

		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			http.Error(w, "invalid pid", http.StatusBadRequest)
			return
		}

		hostID := r.URL.Query().Get("host_id")
		if hostID == "" {
			http.Error(w, "host_id required", http.StatusBadRequest)
			return
		}

		maxDepth := 5
		if d := r.URL.Query().Get("max_depth"); d != "" {
			if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 {
				maxDepth = parsed
			}
		}

		tree, err := timelineService.GetProcessTree(r.Context(), pid, hostID, maxDepth)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tree)
	})
}

// AttackPathHandler finds attack chains using Neo4j.
func AttackPathHandler(timelineService *query.TimelineService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		eventID := r.URL.Query().Get("event_id")
		if eventID == "" {
			http.Error(w, "event_id required", http.StatusBadRequest)
			return
		}

		path, err := timelineService.GetAttackPath(r.Context(), eventID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(path)
	})
}

// InvestigationHandler provides specialized investigation queries.
func InvestigationHandler(invService *query.InvestigationService) http.Handler {
	mux := http.NewServeMux()

	// Docker containers
	mux.HandleFunc("/docker/containers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		hoursStr := r.URL.Query().Get("hours")
		hours := 24
		if hoursStr != "" {
			if parsed, err := strconv.Atoi(hoursStr); err == nil && parsed > 0 {
				hours = parsed
			}
		}

		since := time.Now().Add(-time.Duration(hours) * time.Hour)
		containers, err := invService.FindDockerContainers(r.Context(), since)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(containers)
	})

	// File execution trace
	mux.HandleFunc("/file/trace", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		filePath := r.URL.Query().Get("path")
		if filePath == "" {
			http.Error(w, "path required", http.StatusBadRequest)
			return
		}

		chain, err := invService.TraceFileExecution(r.Context(), filePath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(chain)
	})

	// Port listeners
	mux.HandleFunc("/network/listeners", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		portStr := r.URL.Query().Get("port")
		if portStr == "" {
			http.Error(w, "port required", http.StatusBadRequest)
			return
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			http.Error(w, "invalid port", http.StatusBadRequest)
			return
		}

		processes, err := invService.FindPortListeners(r.Context(), port)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(processes)
	})

	return mux
}

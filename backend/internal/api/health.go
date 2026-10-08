package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

// HealthResponse is the GET /health response body.
type HealthResponse struct {
	Status string `json:"status"`
	// Detection reports whether the rule engine evaluates ingested events. It no longer
	// depends on Neo4j: AI attribution comes from event tags + the attribution cache.
	Detection string `json:"detection"` // "enabled" | "disabled"
	// DetectionGraph reports whether Neo4j look-back context is available to the rules.
	DetectionGraph string `json:"detection_graph"` // "enabled" | "disabled"
}

func enabledString(on bool) string {
	if on {
		return "enabled"
	}
	return "disabled"
}

// HealthHandler returns a handler with system component status.
// detectionEnabled is true when a detection engine is wired into ingest;
// graphEnabled is true when the Neo4j graph querier is available.
func HealthHandler(detectionEnabled, graphEnabled bool) http.HandlerFunc {
	resp := HealthResponse{
		Status:         "ok",
		Detection:      enabledString(detectionEnabled),
		DetectionGraph: enabledString(graphEnabled),
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			MethodNotAllowed(w, http.MethodGet)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// ReadinessResponse is the GET /readiness response body.
type ReadinessResponse struct {
	Status   string `json:"status"`
	Postgres string `json:"postgres"`
}

// ReadinessHandler returns a handler that checks backend dependencies.
// It pings PostgreSQL with a 3-second timeout and reports connectivity.
func ReadinessHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			MethodNotAllowed(w, http.MethodGet)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		w.Header().Set("Content-Type", "application/json")

		if err := db.PingContext(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(ReadinessResponse{
				Status:   "degraded",
				Postgres: "unavailable",
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(ReadinessResponse{
			Status:   "ok",
			Postgres: "ok",
		})
	}
}

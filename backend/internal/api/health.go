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
	Status          string `json:"status"`
	DetectionGraph  string `json:"detection_graph"` // "enabled" | "disabled"
}

// HealthHandler returns a handler with system component status.
// graphEnabled should be true if the Neo4j graph querier is available.
func HealthHandler(graphEnabled bool) http.HandlerFunc {
	graphStatus := "enabled"
	if !graphEnabled {
		graphStatus = "disabled"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			MethodNotAllowed(w, http.MethodGet)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(HealthResponse{
			Status:         "ok",
			DetectionGraph: graphStatus,
		})
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

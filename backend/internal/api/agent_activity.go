package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/query"
)

// AgentActivityHandler returns the agent activity stream — a human-readable,
// significance-scored feed of what each AI agent is doing. The source is the
// Neo4j timeline service when the graph is configured, else the PostgreSQL
// stream built from the agent's AI session tags.
//
// GET /agents/activity?interval=30&min_significance=2
//
// Parameters:
//   - interval: time window in minutes (default: 30, max: 10080)
//   - min_significance: minimum significance score 1-5 (default: 2)
func AgentActivityHandler(source query.AgentActivitySource) http.Handler {
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
		// Parse interval parameter (minutes), capped at one week.
		intervalMinutes := 30 // default 30 minutes
		if intervalStr := r.URL.Query().Get("interval"); intervalStr != "" {
			if parsed, err := strconv.Atoi(intervalStr); err == nil && parsed > 0 {
				intervalMinutes = min(parsed, 7*24*60)
			}
		}
		since := time.Now().Add(-time.Duration(intervalMinutes) * time.Minute)

		// Parse minimum significance filter (default: 2 = hide noise)
		minSignificance := 2
		if sigStr := r.URL.Query().Get("min_significance"); sigStr != "" {
			if parsed, err := strconv.Atoi(sigStr); err == nil && parsed >= 1 && parsed <= 5 {
				minSignificance = parsed
			}
		}

		response, err := source.GetAgentActivityStream(r.Context(), orgID, since, minSignificance)
		if err != nil {
			InternalErr(w, "agent activity query", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
}

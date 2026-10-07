package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/correlic/correlic-backend/internal/process"
	"github.com/correlic/correlic-backend/internal/query"
	"github.com/correlic/correlic-backend/internal/storage/eventstore"
)

// ProcessLifecyclesResponse is the response for GET /process/lifecycles.
type ProcessLifecyclesResponse struct {
	HostID     string               `json:"host_id"`
	Since      string               `json:"since"`
	Until      string               `json:"until"`
	Lifecycles []*process.Lifecycle `json:"lifecycles"`
}

// ProcessLifecyclesHandler handles GET /process/lifecycles?host_id=...&since=...&until=...
// Uses same parseTimeRange as query handlers. Returns lifecycles derived from process_exec and process_exit.
func ProcessLifecyclesHandler(store eventstore.EventStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			MethodNotAllowed(w, http.MethodGet)
			return
		}
		hostID, since, until, err := parseTimeRange(r)
		if err != nil {
			if errors.Is(err, ErrQueryMissingHostID) || errors.Is(err, ErrQueryMissingSince) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		lifecycles, err := process.GetProcessLifecycles(r.Context(), store, hostID, since, until)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if lifecycles == nil {
			lifecycles = []*process.Lifecycle{}
		}
		for _, lc := range lifecycles {
			lc.ExePath = query.SanitizeExePathForResponse(lc.ExePath)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(ProcessLifecyclesResponse{
			HostID:     hostID,
			Since:      since.UTC().Format(time.RFC3339),
			Until:      until.UTC().Format(time.RFC3339),
			Lifecycles: lifecycles,
		})
	})
}

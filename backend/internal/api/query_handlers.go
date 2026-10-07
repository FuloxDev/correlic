package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/correlic/correlic-backend/internal/query"
)

// parseTimeRange reads host_id, since, and until from query params.
// since can be ISO8601, unix timestamp (seconds), or a relative duration (e.g. -10m, -1h). until is optional (default: now).
func parseTimeRange(r *http.Request) (hostID string, since, until time.Time, err error) {
	hostID = r.URL.Query().Get("host_id")
	if hostID == "" {
		return "", time.Time{}, time.Time{}, ErrQueryMissingHostID
	}
	sinceStr := r.URL.Query().Get("since")
	if sinceStr == "" {
		return "", time.Time{}, time.Time{}, ErrQueryMissingSince
	}
	since, err = parseTimeParam(sinceStr)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	untilStr := r.URL.Query().Get("until")
	if untilStr == "" {
		until = time.Now().UTC()
		return hostID, since, until, nil
	}
	until, err = parseTimeParam(untilStr)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	return hostID, since, until, nil
}

// parseTimeParam parses since/until: relative duration (-10m, -1h), unix seconds, or RFC3339.
func parseTimeParam(s string) (time.Time, error) {
	if d, err := time.ParseDuration(s); err == nil && d <= 0 {
		return time.Now().UTC().Add(d), nil
	}
	if unix, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(unix, 0).UTC(), nil
	}
	return time.Parse(time.RFC3339, s)
}

// Sentinel errors for query param validation (return 400).
var (
	ErrQueryMissingHostID = errors.New("missing query parameter \"host_id\"")
	ErrQueryMissingSince  = errors.New("missing query parameter \"since\"")
)

// QueryContainersHandler handles GET /query/containers?host_id=...&since=...&until=...
func QueryContainersHandler(svc *query.Service) http.Handler {
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
		rows, _, err := svc.ListContainerStarts(r.Context(), hostID, since, until)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
	})
}

// QueryPortsHandler handles GET /query/ports?host_id=...&since=...&until=...
func QueryPortsHandler(svc *query.Service) http.Handler {
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
		rows, _, err := svc.ListOpenPorts(r.Context(), hostID, since, until)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
	})
}

// QueryConnectionsHandler handles GET /query/connections?host_id=...&since=...&until=...
func QueryConnectionsHandler(svc *query.Service) http.Handler {
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
		rows, _, err := svc.ListExternalConnections(r.Context(), hostID, since, until)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
	})
}

// QueryInboundHandler handles GET /query/inbound?host_id=...&since=...&until=... (net_accept events).
func QueryInboundHandler(svc *query.Service) http.Handler {
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
		rows, _, err := svc.ListInboundConnections(r.Context(), hostID, since, until)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
	})
}

// QueryProcessesHandler handles GET /query/processes?host_id=...&since=...&until=...&pattern=...
func QueryProcessesHandler(svc *query.Service) http.Handler {
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
		pattern := r.URL.Query().Get("pattern")
		rows, _, err := svc.ListProcessesByExecutable(r.Context(), hostID, since, until, pattern)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
	})
}

// ErrQueryMissingDiffParam is returned when a required diff query parameter is missing.
var ErrQueryMissingDiffParam = errors.New("missing required diff query parameter")

// DiffResponse is the JSON response for GET /diff.
type DiffResponse struct {
	Type          string      `json:"type"`
	BaseWindow    TimeWindow  `json:"base_window"`
	CompareWindow TimeWindow  `json:"compare_window"`
	Added         interface{} `json:"added"`
	Removed       interface{} `json:"removed"`
}

// TimeWindow is since/until for a diff window.
type TimeWindow struct {
	Since string `json:"since"`
	Until string `json:"until"`
}

// parseDiffParams reads host_id, base_since, base_until, compare_since, compare_until, type from query params. All required.
func parseDiffParams(r *http.Request) (hostID string, baseSince, baseUntil, compareSince, compareUntil time.Time, diffType string, err error) {
	q := r.URL.Query()
	hostID = q.Get("host_id")
	if hostID == "" {
		return "", time.Time{}, time.Time{}, time.Time{}, time.Time{}, "", ErrQueryMissingHostID
	}
	for _, name := range []string{"base_since", "base_until", "compare_since", "compare_until", "type"} {
		if q.Get(name) == "" {
			return "", time.Time{}, time.Time{}, time.Time{}, time.Time{}, "", ErrQueryMissingDiffParam
		}
	}
	baseSince, err = parseTimeParam(q.Get("base_since"))
	if err != nil {
		return "", time.Time{}, time.Time{}, time.Time{}, time.Time{}, "", err
	}
	baseUntil, err = parseTimeParam(q.Get("base_until"))
	if err != nil {
		return "", time.Time{}, time.Time{}, time.Time{}, time.Time{}, "", err
	}
	compareSince, err = parseTimeParam(q.Get("compare_since"))
	if err != nil {
		return "", time.Time{}, time.Time{}, time.Time{}, time.Time{}, "", err
	}
	compareUntil, err = parseTimeParam(q.Get("compare_until"))
	if err != nil {
		return "", time.Time{}, time.Time{}, time.Time{}, time.Time{}, "", err
	}
	if !baseSince.Before(baseUntil) {
		return "", time.Time{}, time.Time{}, time.Time{}, time.Time{}, "", errors.New("base_since must be before base_until")
	}
	if !compareSince.Before(compareUntil) {
		return "", time.Time{}, time.Time{}, time.Time{}, time.Time{}, "", errors.New("compare_since must be before compare_until")
	}
	diffType = q.Get("type")
	switch diffType {
	case "processes", "connections", "ports":
		// ok
	default:
		return "", time.Time{}, time.Time{}, time.Time{}, time.Time{}, "", errors.New("type must be processes, connections, or ports")
	}
	return hostID, baseSince, baseUntil, compareSince, compareUntil, diffType, nil
}

// DiffHandler handles GET /diff?host_id=...&base_since=...&base_until=...&compare_since=...&compare_until=...&type=processes|connections|ports
func DiffHandler(svc *query.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			MethodNotAllowed(w, http.MethodGet)
			return
		}
		hostID, baseSince, baseUntil, compareSince, compareUntil, diffType, err := parseDiffParams(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ctx := r.Context()
		baseW := TimeWindow{Since: baseSince.UTC().Format(time.RFC3339), Until: baseUntil.UTC().Format(time.RFC3339)}
		compareW := TimeWindow{Since: compareSince.UTC().Format(time.RFC3339), Until: compareUntil.UTC().Format(time.RFC3339)}

		switch diffType {
		case "processes":
			res, err := svc.DiffProcessesByExecutable(ctx, hostID, baseSince, baseUntil, compareSince, compareUntil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(DiffResponse{Type: "processes", BaseWindow: baseW, CompareWindow: compareW, Added: res.Added, Removed: res.Removed})
			return
		case "connections":
			res, err := svc.DiffExternalConnections(ctx, hostID, baseSince, baseUntil, compareSince, compareUntil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(DiffResponse{Type: "connections", BaseWindow: baseW, CompareWindow: compareW, Added: res.Added, Removed: res.Removed})
			return
		case "ports":
			res, err := svc.DiffOpenPorts(ctx, hostID, baseSince, baseUntil, compareSince, compareUntil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(DiffResponse{Type: "ports", BaseWindow: baseW, CompareWindow: compareW, Added: res.Added, Removed: res.Removed})
			return
		}
	})
}

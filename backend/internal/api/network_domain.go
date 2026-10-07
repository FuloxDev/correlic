package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/storage"
)

// NetworkDomainHandler provides a drilldown view for a single domain.
// It is meant to power “click domain → show evidence” without client-side scanning.
type NetworkDomainHandler struct {
	store storage.TelemetryStore
}

func NewNetworkDomainHandler(store storage.TelemetryStore) *NetworkDomainHandler {
	return &NetworkDomainHandler{store: store}
}

type NetworkDomainResponse struct {
	Window struct {
		Since string `json:"since"`
		Until string `json:"until"`
	} `json:"window"`

	Domain string `json:"domain"`

	Counts struct {
		DNSQueries    int `json:"dns_queries"`
		SuspiciousDNS int `json:"suspicious_dns"`
		PIDs          int `json:"pids"`
		Connections   int `json:"connections"`
	} `json:"counts"`

	TopPIDs []struct {
		PID   int    `json:"pid"`
		Comm  string `json:"comm,omitempty"`
		Count int    `json:"count"`
	} `json:"top_pids,omitempty"`

	Evidence []model.TelemetryEvent `json:"evidence"`
}

func (h *NetworkDomainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}
	if r.Method != http.MethodGet {
		MethodNotAllowed(w, http.MethodGet)
		return
	}
	if h.store == nil {
		NotImplemented(w, "telemetry store not enabled")
		return
	}

	q := r.URL.Query()
	agentID := q.Get("agent_id")
	domain := strings.TrimSpace(q.Get("domain"))
	sinceStr := q.Get("since")
	untilStr := q.Get("until")
	limitStr := q.Get("limit")

	if domain == "" {
		BadRequest(w, "missing domain")
		return
	}

	limit := 400
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		limit = 1000
	}

	// Default window: last 60 minutes.
	now := time.Now().UTC()
	since := now.Add(-60 * time.Minute)
	until := now
	if sinceStr != "" {
		t, err := parseRFC3339(sinceStr)
		if err != nil {
			BadRequest(w, "invalid since (expected RFC3339)")
			return
		}
		since = t
	}
	if untilStr != "" {
		t, err := parseRFC3339(untilStr)
		if err != nil {
			BadRequest(w, "invalid until (expected RFC3339)")
			return
		}
		until = t
	}
	if !until.After(since) {
		BadRequest(w, "until must be after since")
		return
	}

	// Pull DNS queries and filter by domain.
	dnsEvents, _ := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
		AgentID:   agentID,
		EventType: "dns_query",
		Since:     since,
		Until:     until,
		Limit:     2000,
		Offset:    0,
	})

	target := strings.ToLower(domain)
	suspicious := 0

	type pidInfo struct {
		pid   int
		comm  string
		count int
		ts    []time.Time
	}
	byPID := make(map[int]*pidInfo, 32)
	filteredDNS := make([]model.TelemetryEvent, 0, 128)

	for _, ev := range dnsEvents {
		var p map[string]any
		_ = json.Unmarshal(ev.Payload, &p)
		d := strings.ToLower(strings.TrimSpace(asString(p["domain"], p["query"], p["name"])))
		if d == "" || d != target {
			continue
		}
		filteredDNS = append(filteredDNS, ev)
		if asBool(p["suspicious"], p["is_suspicious"]) {
			suspicious++
		}
		pid := intFromAny(p["pid"])
		if pid <= 0 {
			continue
		}
		info := byPID[pid]
		if info == nil {
			info = &pidInfo{pid: pid}
			info.comm = strings.TrimSpace(asString(p["comm"]))
			byPID[pid] = info
		}
		info.count++
		info.ts = append(info.ts, ev.Timestamp)
		if info.comm == "" {
			info.comm = strings.TrimSpace(asString(p["comm"]))
		}
	}

	// Rank PIDs by DNS query count; cap to top 5 for connection correlation.
	pids := make([]*pidInfo, 0, len(byPID))
	for _, v := range byPID {
		pids = append(pids, v)
		sort.Slice(v.ts, func(i, j int) bool { return v.ts[i].Before(v.ts[j]) })
	}
	sort.Slice(pids, func(i, j int) bool {
		if pids[i].count == pids[j].count {
			return pids[i].pid < pids[j].pid
		}
		return pids[i].count > pids[j].count
	})
	if len(pids) > 5 {
		pids = pids[:5]
	}

	// Correlate connections: for each PID, fetch net_connect and keep those close in time to DNS events.
	filteredConn := make([]model.TelemetryEvent, 0, 128)
	for _, pi := range pids {
		conn, _ := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
			AgentID:   agentID,
			EventType: "net_connect",
			Since:     since,
			Until:     until,
			PID:       int64(pi.pid),
			Limit:     400,
			Offset:    0,
		})
		for _, ev := range conn {
			if isCloseToAny(ev.Timestamp, pi.ts, 30*time.Second) {
				filteredConn = append(filteredConn, ev)
			}
		}
	}

	// Combine evidence (dns + correlated conns), sort asc, and cap to limit.
	evidence := make([]model.TelemetryEvent, 0, len(filteredDNS)+len(filteredConn))
	evidence = append(evidence, filteredDNS...)
	evidence = append(evidence, filteredConn...)
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].Timestamp.Before(evidence[j].Timestamp) })
	if len(evidence) > limit {
		evidence = evidence[len(evidence)-limit:]
	}

	out := NetworkDomainResponse{}
	out.Window.Since = since.Format(time.RFC3339Nano)
	out.Window.Until = until.Format(time.RFC3339Nano)
	out.Domain = domain
	out.Counts.DNSQueries = len(filteredDNS)
	out.Counts.SuspiciousDNS = suspicious
	out.Counts.PIDs = len(byPID)
	out.Counts.Connections = len(filteredConn)
	out.Evidence = evidence

	for _, pi := range pids {
		out.TopPIDs = append(out.TopPIDs, struct {
			PID   int    `json:"pid"`
			Comm  string `json:"comm,omitempty"`
			Count int    `json:"count"`
		}{
			PID:   pi.pid,
			Comm:  pi.comm,
			Count: pi.count,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func isCloseToAny(t time.Time, sorted []time.Time, window time.Duration) bool {
	if len(sorted) == 0 {
		return false
	}
	// Binary search for insertion point.
	i := sort.Search(len(sorted), func(i int) bool { return !sorted[i].Before(t) })
	check := func(idx int) bool {
		if idx < 0 || idx >= len(sorted) {
			return false
		}
		d := t.Sub(sorted[idx])
		if d < 0 {
			d = -d
		}
		return d <= window
	}
	return check(i) || check(i-1)
}

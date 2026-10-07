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

// NetworkDestinationHandler provides a drilldown for a destination IP (optionally port).
// This is intentionally simple: it filters net_connect events by dst_ip (+ optional dst_port).
type NetworkDestinationHandler struct {
	store storage.TelemetryStore
}

func NewNetworkDestinationHandler(store storage.TelemetryStore) *NetworkDestinationHandler {
	return &NetworkDestinationHandler{store: store}
}

type NetworkDestinationResponse struct {
	Window struct {
		Since string `json:"since"`
		Until string `json:"until"`
	} `json:"window"`

	DstIP   string `json:"dst_ip"`
	DstPort int    `json:"dst_port,omitempty"`

	Counts struct {
		Connections int `json:"connections"`
		PIDs        int `json:"pids"`
	} `json:"counts"`

	TopPIDs []struct {
		PID   int    `json:"pid"`
		Comm  string `json:"comm,omitempty"`
		Count int    `json:"count"`
	} `json:"top_pids,omitempty"`

	Org string `json:"org,omitempty"`

	ObservedDomains []struct {
		Domain string `json:"domain"`
		Count  int    `json:"count"`
	} `json:"observed_domains,omitempty"`

	Evidence []model.TelemetryEvent `json:"evidence"`
}

func (h *NetworkDestinationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	dst := strings.TrimSpace(q.Get("dst"))
	sinceStr := q.Get("since")
	untilStr := q.Get("until")
	limitStr := q.Get("limit")

	if dst == "" {
		BadRequest(w, "missing dst")
		return
	}

	dstIP, dstPort := splitIPPort(dst)
	if dstIP == "" {
		BadRequest(w, "invalid dst")
		return
	}

	limit := 400
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 2000 {
		limit = 2000
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

	// Pull recent net_connect events (bounded) and filter.
	raw, _ := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
		AgentID:   agentID,
		EventType: "net_connect",
		Since:     since,
		Until:     until,
		Limit:     2000,
		Offset:    0,
	})

	type pidInfo struct {
		pid   int
		comm  string
		count int
	}
	byPID := make(map[int]*pidInfo, 64)
	evidence := make([]model.TelemetryEvent, 0, 256)
	pidsSet := make(map[int]struct{}, 64)

	for _, ev := range raw {
		var p map[string]any
		_ = json.Unmarshal(ev.Payload, &p)
		ip := strings.TrimSpace(asString(p["dst_ip"], p["remote_ip"]))
		if ip == "" || ip != dstIP {
			continue
		}
		if dstPort > 0 {
			pp := intFromAny(p["dst_port"], p["remote_port"])
			if pp != dstPort {
				continue
			}
		}
		evidence = append(evidence, ev)

		pid := intFromAny(p["pid"])
		if pid <= 0 {
			continue
		}
		pidsSet[pid] = struct{}{}
		info := byPID[pid]
		if info == nil {
			info = &pidInfo{pid: pid, comm: strings.TrimSpace(asString(p["comm"]))}
			byPID[pid] = info
		}
		info.count++
		if info.comm == "" {
			info.comm = strings.TrimSpace(asString(p["comm"]))
		}
	}

	// Sort evidence oldest->newest for reading.
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].Timestamp.Before(evidence[j].Timestamp) })
	if len(evidence) > limit {
		evidence = evidence[len(evidence)-limit:]
	}

	// Best-effort observed domains: correlate recent dns_query events (same PID, shortly before connect).
	domainCounts := make(map[string]int, 32)
	if len(pidsSet) > 0 {
		dns, _ := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
			AgentID:   agentID,
			EventType: "dns_query",
			Since:     since,
			Until:     until,
			Limit:     2000,
			Offset:    0,
		})
		byPIDDNS := make(map[int][]dnsObservation, 64)
		for _, ev := range dns {
			var p map[string]any
			_ = json.Unmarshal(ev.Payload, &p)
			pid := intFromAny(p["pid"])
			if pid <= 0 {
				continue
			}
			if _, ok := pidsSet[pid]; !ok {
				continue
			}
			d := strings.TrimSpace(asString(p["domain"], p["query"], p["name"]))
			if d == "" {
				continue
			}
			byPIDDNS[pid] = append(byPIDDNS[pid], dnsObservation{ts: ev.Timestamp, domain: d})
		}
		for pid := range byPIDDNS {
			sort.Slice(byPIDDNS[pid], func(i, j int) bool { return byPIDDNS[pid][i].ts.Before(byPIDDNS[pid][j].ts) })
		}
		for _, ev := range evidence {
			var p map[string]any
			_ = json.Unmarshal(ev.Payload, &p)
			pid := intFromAny(p["pid"])
			if pid <= 0 {
				continue
			}
			if dom := lastDomainBefore(byPIDDNS[pid], ev.Timestamp, 60*time.Second); dom != "" {
				domainCounts[dom]++
			}
		}
	}

	// Build top pids.
	pids := make([]*pidInfo, 0, len(byPID))
	for _, v := range byPID {
		pids = append(pids, v)
	}
	sort.Slice(pids, func(i, j int) bool {
		if pids[i].count == pids[j].count {
			return pids[i].pid < pids[j].pid
		}
		return pids[i].count > pids[j].count
	})
	if len(pids) > 10 {
		pids = pids[:10]
	}

	out := NetworkDestinationResponse{}
	out.Window.Since = since.Format(time.RFC3339Nano)
	out.Window.Until = until.Format(time.RFC3339Nano)
	out.DstIP = dstIP
	out.DstPort = dstPort
	out.Counts.Connections = len(evidence)
	out.Counts.PIDs = len(byPID)
	out.Evidence = evidence

	// Org enrichment removed (was in ip_enrich.go)

	if len(domainCounts) > 0 {
		type pair struct {
			d string
			c int
		}
		ps := make([]pair, 0, len(domainCounts))
		for d, c := range domainCounts {
			ps = append(ps, pair{d: d, c: c})
		}
		sort.Slice(ps, func(i, j int) bool {
			if ps[i].c == ps[j].c {
				return ps[i].d < ps[j].d
			}
			return ps[i].c > ps[j].c
		})
		if len(ps) > 10 {
			ps = ps[:10]
		}
		for _, p := range ps {
			out.ObservedDomains = append(out.ObservedDomains, struct {
				Domain string `json:"domain"`
				Count  int    `json:"count"`
			}{Domain: p.d, Count: p.c})
		}
	}

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

func splitIPPort(dst string) (ip string, port int) {
	dst = strings.TrimSpace(dst)
	if dst == "" {
		return "", 0
	}
	// Prefer dst like "1.2.3.4:443".
	i := strings.LastIndex(dst, ":")
	if i > 0 && i < len(dst)-1 {
		tail := dst[i+1:]
		ok := true
		for _, r := range tail {
			if r < '0' || r > '9' {
				ok = false
				break
			}
		}
		if ok {
			p, err := strconv.Atoi(tail)
			if err == nil && p > 0 && p <= 65535 {
				return dst[:i], p
			}
		}
	}
	// Otherwise treat as plain IP.
	return dst, 0
}

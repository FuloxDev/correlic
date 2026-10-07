package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
)

// NetworkSummaryHandler provides pre-aggregated network view data for the UI.
// This avoids doing heavy aggregation client-side.
type NetworkSummaryHandler struct {
	store storage.TelemetryStore
}

func NewNetworkSummaryHandler(store storage.TelemetryStore) *NetworkSummaryHandler {
	return &NetworkSummaryHandler{store: store}
}

type NetworkSummaryResponse struct {
	Window struct {
		Since string `json:"since"`
		Until string `json:"until"`
	} `json:"window"`

	Counts struct {
		DNSQueries      int `json:"dns_queries"`
		NetConnections  int `json:"net_connections"`
		SuspiciousDNS   int `json:"suspicious_dns"`
		UniqueDomains   int `json:"unique_domains"`
		UniqueDestAddrs int `json:"unique_dest_addrs"`
	} `json:"counts"`

	TopDomains []struct {
		Domain string `json:"domain"`
		Count  int    `json:"count"`
	} `json:"top_domains"`

	TopDestinations []struct {
		Dst   string `json:"dst"` // "ip:port" best-effort
		Count int    `json:"count"`
	} `json:"top_destinations"`
}

func (h *NetworkSummaryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	agentID := r.URL.Query().Get("agent_id")
	sinceStr := r.URL.Query().Get("since")
	untilStr := r.URL.Query().Get("until")

	// Default window: last 15 minutes.
	now := time.Now().UTC()
	since := now.Add(-15 * time.Minute)
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

	// Fetch events in-window (bounded).
	// We keep this modest; it’s a UI summary endpoint, not a full export.
	dnsEvents, _ := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
		AgentID:   agentID,
		EventType: "dns_query",
		Since:     since,
		Until:     until,
		Limit:     500,
		Offset:    0,
	})
	connEvents, _ := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
		AgentID:   agentID,
		EventType: "net_connect",
		Since:     since,
		Until:     until,
		Limit:     500,
		Offset:    0,
	})

	domainCounts := make(map[string]int, 256)
	suspiciousDNS := 0
	for _, ev := range dnsEvents {
		var p map[string]any
		_ = json.Unmarshal(ev.Payload, &p)
		d := strings.TrimSpace(asString(p["domain"], p["query"], p["name"]))
		if d == "" {
			continue
		}
		domainCounts[d]++
		if asBool(p["suspicious"], p["is_suspicious"]) {
			suspiciousDNS++
		}
	}

	dstCounts := make(map[string]int, 256)
	for _, ev := range connEvents {
		var p map[string]any
		_ = json.Unmarshal(ev.Payload, &p)
		ip := strings.TrimSpace(asString(p["dst_ip"], p["remote_ip"]))
		port := strings.TrimSpace(asString(p["dst_port"], p["remote_port"]))
		dst := strings.TrimSpace(asString(p["dst_addr"], p["remote_addr"]))
		if ip != "" && port != "" {
			dst = ip + ":" + port
		} else if ip != "" && port == "" {
			dst = ip
		}
		if dst == "" {
			continue
		}
		dstCounts[dst]++
	}

	out := NetworkSummaryResponse{}
	out.Window.Since = since.Format(time.RFC3339Nano)
	out.Window.Until = until.Format(time.RFC3339Nano)
	out.Counts.DNSQueries = len(dnsEvents)
	out.Counts.NetConnections = len(connEvents)
	out.Counts.SuspiciousDNS = suspiciousDNS
	out.Counts.UniqueDomains = len(domainCounts)
	out.Counts.UniqueDestAddrs = len(dstCounts)

	out.TopDomains = topN(domainCounts, 10, func(k string, v int) struct {
		Domain string `json:"domain"`
		Count  int    `json:"count"`
	} {
		return struct {
			Domain string `json:"domain"`
			Count  int    `json:"count"`
		}{Domain: k, Count: v}
	})

	out.TopDestinations = topN(dstCounts, 10, func(k string, v int) struct {
		Dst   string `json:"dst"`
		Count int    `json:"count"`
	} {
		return struct {
			Dst   string `json:"dst"`
			Count int    `json:"count"`
		}{Dst: k, Count: v}
	})

	// Sanity: keep build happy that model is used (it is in type signatures of ListFiltered results).
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func parseRFC3339(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

func asString(vs ...any) string {
	for _, v := range vs {
		switch t := v.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				return t
			}
		case float64:
			// JSON numbers
			if t == float64(int64(t)) {
				return strconv.FormatInt(int64(t), 10)
			}
			return strconv.FormatFloat(t, 'f', -1, 64)
		case int:
			return strconv.Itoa(t)
		case int64:
			return strconv.FormatInt(t, 10)
		}
	}
	return ""
}

func asBool(vs ...any) bool {
	for _, v := range vs {
		switch t := v.(type) {
		case bool:
			return t
		case string:
			s := strings.ToLower(strings.TrimSpace(t))
			if s == "true" || s == "1" || s == "yes" {
				return true
			}
		}
	}
	return false
}

func topN[T any](m map[string]int, n int, build func(k string, v int) T) []T {
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{k: k, v: v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v == items[j].v {
			return items[i].k < items[j].k
		}
		return items[i].v > items[j].v
	})
	if n <= 0 {
		n = 10
	}
	if len(items) > n {
		items = items[:n]
	}
	out := make([]T, 0, len(items))
	for _, it := range items {
		out = append(out, build(it.k, it.v))
	}
	return out
}

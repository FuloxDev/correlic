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

// PortsSummaryHandler provides a ports-centric summary for the UI.
// Primary source is agent-emitted `port_lifecycle` summary; fallback to `net_bind` events.
type PortsSummaryHandler struct {
	store storage.TelemetryStore
}

func NewPortsSummaryHandler(store storage.TelemetryStore) *PortsSummaryHandler {
	return &PortsSummaryHandler{store: store}
}

type PortsSummaryResponse struct {
	Window struct {
		Since string `json:"since"`
		Until string `json:"until"`
	} `json:"window"`

	Counts struct {
		OpenServices int `json:"open_services"`
		Exposed      int `json:"exposed"`
	} `json:"counts"`

	Services []PortServiceEntry `json:"services"`
}

type PortServiceEntry struct {
	Key       string   `json:"key"` // comm:port
	Port      int      `json:"port"`
	Comm      string   `json:"comm"`
	PComm     string   `json:"pcomm,omitempty"`
	Addresses []string `json:"addresses"`
	Instances []struct {
		PID int `json:"pid"`
		UID int `json:"uid,omitempty"`
	} `json:"instances,omitempty"`
	Risk    string `json:"risk"`
	Exposed bool   `json:"exposed"`
	IsAI    bool   `json:"is_ai"`
	AIType  string `json:"ai_type,omitempty"`
}

func (h *PortsSummaryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
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

	// Try to get latest `port_lifecycle` summary within window.
	lifecycle, _ := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
		AgentID:   agentID,
		EventType: "port_lifecycle",
		Since:     since,
		Until:     until,
		Limit:     500,
		Offset:    0,
	})

	type portRow struct {
		Port    int
		Comm    string
		PComm   string
		Addr    string
		PID     int
		UID     int
		Risk    string
		Exposed bool
		IsAI    bool
		AIType  string
	}
	rows := make([]portRow, 0, 128)

	// Find newest summary.
	var summaryPayload map[string]any
	var summaryTS time.Time
	for _, ev := range lifecycle {
		var p map[string]any
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			continue
		}
		if strings.TrimSpace(asString(p["event"])) != "summary" {
			continue
		}
		// Use event_ts ordering from DB results (already DESC); but we still take max timestamp to be safe.
		if ev.Timestamp.After(summaryTS) {
			summaryTS = ev.Timestamp
			summaryPayload = p
		}
	}

	if summaryPayload != nil {
		portsAny, ok := summaryPayload["ports"]
		if arr, okArr := portsAny.([]any); ok && okArr {
			for _, item := range arr {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				port := intFromAny(m["port"])
				addr := strings.TrimSpace(asString(m["bind_addr"]))
				comm := strings.TrimSpace(asString(m["comm"]))
				pcomm := strings.TrimSpace(asString(m["pcomm"]))
				pid := intFromAny(m["pid"])
				uid := intFromAny(m["uid"])
				if port <= 0 || addr == "" {
					continue
				}
				exposed := asBool(m["is_exposed"]) || addr == "0.0.0.0" || addr == "::"
				rows = append(rows, portRow{
					Port:    port,
					Comm:    comm,
					PComm:   pcomm,
					Addr:    addr,
					PID:     pid,
					UID:     uid,
					Risk:    strings.TrimSpace(asString(m["risk"])),
					Exposed: exposed,
					IsAI:    asBool(m["is_ai"]),
					AIType:  strings.TrimSpace(asString(m["ai_type"])),
				})
			}
		}
	}

	// Fallback: if no summary was found (agent not emitting), use net_bind events.
	if len(rows) == 0 {
		binds, _ := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
			AgentID:   agentID,
			EventType: "net_bind",
			Since:     since,
			Until:     until,
			Limit:     500,
			Offset:    0,
		})
		for _, ev := range binds {
			var p map[string]any
			_ = json.Unmarshal(ev.Payload, &p)
			port := intFromAny(p["bind_port"], p["port"])
			addr := strings.TrimSpace(asString(p["bind_addr"], p["addr"]))
			comm := strings.TrimSpace(asString(p["comm"]))
			pcomm := strings.TrimSpace(asString(p["pcomm"]))
			pid := intFromAny(p["pid"])
			uid := intFromAny(p["uid"])
			if port <= 0 || addr == "" {
				continue
			}
			exposed := asBool(p["is_exposed"]) || addr == "0.0.0.0" || addr == "::"
			rows = append(rows, portRow{
				Port:    port,
				Comm:    comm,
				PComm:   pcomm,
				Addr:    addr,
				PID:     pid,
				UID:     uid,
				Risk:    strings.TrimSpace(asString(p["risk"])),
				Exposed: exposed,
				IsAI:    asBool(p["is_ai"]),
				AIType:  strings.TrimSpace(asString(p["ai_type"])),
			})
		}
	}

	// Aggregate into services.
	type svc struct {
		Key       string
		Port      int
		Comm      string
		PComm     string
		Addresses map[string]struct{}
		Instances map[int]int // pid -> uid
		Risk      string
		Exposed   bool
		IsAI      bool
		AIType    string
	}
	byKey := make(map[string]*svc, 128)
	for _, r := range rows {
		key := r.Comm + ":" + strconvItoa(r.Port)
		s := byKey[key]
		if s == nil {
			s = &svc{
				Key:       key,
				Port:      r.Port,
				Comm:      r.Comm,
				PComm:     r.PComm,
				Addresses: make(map[string]struct{}),
				Instances: make(map[int]int),
				Risk:      r.Risk,
				Exposed:   r.Exposed,
			}
			byKey[key] = s
		}
		s.Addresses[r.Addr] = struct{}{}
		if r.PID > 0 {
			if _, exists := s.Instances[r.PID]; !exists {
				s.Instances[r.PID] = r.UID
			}
		}
		if s.PComm == "" && r.PComm != "" {
			s.PComm = r.PComm
		}
		if s.Risk == "" && r.Risk != "" {
			s.Risk = r.Risk
		}
		s.Exposed = s.Exposed || r.Exposed
		if r.IsAI {
			s.IsAI = true
		}
		if s.AIType == "" && r.AIType != "" {
			s.AIType = r.AIType
		}
	}

	out := PortsSummaryResponse{}
	out.Window.Since = since.Format(time.RFC3339Nano)
	out.Window.Until = until.Format(time.RFC3339Nano)
	out.Counts.OpenServices = len(byKey)

	services := make([]*svc, 0, len(byKey))
	for _, v := range byKey {
		services = append(services, v)
		if v.Exposed {
			out.Counts.Exposed++
		}
	}
	sort.Slice(services, func(i, j int) bool {
		if services[i].Port == services[j].Port {
			return services[i].Comm < services[j].Comm
		}
		return services[i].Port < services[j].Port
	})

	out.Services = make([]PortServiceEntry, 0, len(services))
	for _, s := range services {
		addrs := make([]string, 0, len(s.Addresses))
		for a := range s.Addresses {
			addrs = append(addrs, a)
		}
		sort.Strings(addrs)

		instances := make([]struct {
			PID int `json:"pid"`
			UID int `json:"uid,omitempty"`
		}, 0, len(s.Instances))
		for pid, uid := range s.Instances {
			instances = append(instances, struct {
				PID int `json:"pid"`
				UID int `json:"uid,omitempty"`
			}{PID: pid, UID: uid})
		}
		sort.Slice(instances, func(i, j int) bool { return instances[i].PID < instances[j].PID })

		out.Services = append(out.Services, PortServiceEntry{
			Key:       s.Key,
			Port:      s.Port,
			Comm:      s.Comm,
			PComm:     s.PComm,
			Addresses: addrs,
			Instances: instances,
			Risk:      s.Risk,
			Exposed:   s.Exposed,
			IsAI:      s.IsAI,
			AIType:    s.AIType,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func intFromAny(vs ...any) int {
	for _, v := range vs {
		switch t := v.(type) {
		case float64:
			return int(t)
		case int:
			return t
		case int64:
			return int(t)
		case string:
			tt := strings.TrimSpace(t)
			if tt == "" {
				continue
			}
			if n, err := strconv.Atoi(tt); err == nil {
				return n
			}
		}
	}
	return 0
}

func strconvItoa(n int) string {
	return strconv.Itoa(n)
}

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

// PortsServiceHandler provides a drilldown view for a single service (comm+port+pid)
// to power UI timelines without big client-side scans.
type PortsServiceHandler struct {
	store storage.TelemetryStore
}

func NewPortsServiceHandler(store storage.TelemetryStore) *PortsServiceHandler {
	return &PortsServiceHandler{store: store}
}

type PortsServiceResponse struct {
	Window struct {
		Since string `json:"since"`
		Until string `json:"until"`
	} `json:"window"`

	Service struct {
		Port      int      `json:"port"`
		Comm      string   `json:"comm"`
		PComm     string   `json:"pcomm,omitempty"`
		PID       int      `json:"pid"`
		UID       int      `json:"uid,omitempty"`
		Addresses []string `json:"addresses"`
		Risk      string   `json:"risk,omitempty"`
		Exposed   bool     `json:"exposed"`
	} `json:"service"`

	Reasons []string               `json:"reasons,omitempty"`
	Events  []model.TelemetryEvent `json:"events"`
}

func (h *PortsServiceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	comm := strings.TrimSpace(q.Get("comm"))
	pidStr := strings.TrimSpace(q.Get("pid"))
	portStr := strings.TrimSpace(q.Get("port"))
	sinceStr := q.Get("since")
	untilStr := q.Get("until")
	limitStr := q.Get("limit")

	var port int
	if portStr != "" {
		n, err := strconv.Atoi(portStr)
		if err != nil || n <= 0 || n > 65535 {
			BadRequest(w, "invalid port")
			return
		}
		port = n
	}
	if port == 0 {
		BadRequest(w, "missing port")
		return
	}

	var pid int
	if pidStr != "" {
		n, err := strconv.Atoi(pidStr)
		if err != nil || n <= 0 {
			BadRequest(w, "invalid pid")
			return
		}
		pid = n
	}

	limit := 500
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		limit = 1000
	}

	// Default window: last 24 hours.
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

	// If pid is not supplied, resolve from port_lifecycle/net_bind within window.
	var resolved struct {
		pid       int
		uid       int
		comm      string
		pcomm     string
		risk      string
		exposed   bool
		addresses map[string]struct{}
	}
	resolved.addresses = make(map[string]struct{}, 8)
	if pid > 0 {
		resolved.pid = pid
		resolved.comm = comm
	} else {
		resolveLimit := 1500
		lifecycle, _ := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
			AgentID:   agentID,
			EventType: "port_lifecycle",
			Since:     since,
			Until:     until,
			Limit:     resolveLimit,
			Offset:    0,
		})
		binds, _ := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
			AgentID:   agentID,
			EventType: "net_bind",
			Since:     since,
			Until:     until,
			Limit:     resolveLimit,
			Offset:    0,
		})

		bestTS := time.Time{}
		consider := func(ev model.TelemetryEvent, p map[string]any) {
			gotPort := intFromAny(p["port"], p["bind_port"])
			if gotPort != port {
				return
			}
			gotComm := strings.TrimSpace(asString(p["comm"]))
			if comm != "" && !strings.EqualFold(gotComm, comm) {
				return
			}
			addr := strings.TrimSpace(asString(p["bind_addr"], p["addr"]))
			if addr != "" {
				resolved.addresses[addr] = struct{}{}
			}

			if ev.Timestamp.After(bestTS) {
				bestTS = ev.Timestamp
				resolved.pid = intFromAny(p["pid"])
				resolved.uid = intFromAny(p["uid"])
				resolved.comm = gotComm
				resolved.pcomm = strings.TrimSpace(asString(p["pcomm"]))
				resolved.risk = strings.TrimSpace(asString(p["risk"]))
				resolved.exposed = asBool(p["is_exposed"]) || addr == "0.0.0.0" || addr == "::"
			}
		}

		for _, ev := range lifecycle {
			var p map[string]any
			_ = json.Unmarshal(ev.Payload, &p)
			evt := strings.TrimSpace(asString(p["event"]))
			if evt != "" && evt != "opened" && evt != "summary" {
				continue
			}
			consider(ev, p)
		}
		for _, ev := range binds {
			var p map[string]any
			_ = json.Unmarshal(ev.Payload, &p)
			consider(ev, p)
		}

		if resolved.pid <= 0 {
			NotFound(w, "service not found in window")
			return
		}
	}

	// Fetch PID-scoped events for the timeline.
	pidEvents, err := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
		AgentID: agentID,
		Since:   since,
		Until:   until,
		PID:     int64(resolved.pid),
		Limit:   limit,
		Offset:  0,
	})
	if err != nil {
		Internal(w)
		return
	}

	// Enrich addresses from any in-window net_bind / port_lifecycle events we saw for this pid+port.
	extraBinds, _ := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
		AgentID:   agentID,
		EventType: "net_bind",
		Since:     since,
		Until:     until,
		PID:       int64(resolved.pid),
		Limit:     200,
		Offset:    0,
	})
	for _, ev := range extraBinds {
		var p map[string]any
		_ = json.Unmarshal(ev.Payload, &p)
		if intFromAny(p["bind_port"], p["port"]) != port {
			continue
		}
		addr := strings.TrimSpace(asString(p["bind_addr"], p["addr"]))
		if addr != "" {
			resolved.addresses[addr] = struct{}{}
		}
		if asBool(p["is_exposed"]) || addr == "0.0.0.0" || addr == "::" {
			resolved.exposed = true
		}
		if resolved.risk == "" {
			resolved.risk = strings.TrimSpace(asString(p["risk"]))
		}
		if resolved.comm == "" {
			resolved.comm = strings.TrimSpace(asString(p["comm"]))
		}
		if resolved.pcomm == "" {
			resolved.pcomm = strings.TrimSpace(asString(p["pcomm"]))
		}
	}

	addrs := make([]string, 0, len(resolved.addresses))
	for a := range resolved.addresses {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)

	reasons := make([]string, 0, 4)
	if resolved.exposed {
		reasons = append(reasons, "Bound on a wildcard/public interface (0.0.0.0 / ::)")
	}
	if port == 22 || port == 23 || port == 3389 {
		reasons = append(reasons, "Common remote-access port")
	}
	if port == 80 || port == 443 {
		reasons = append(reasons, "HTTP service port")
	}
	if resolved.risk != "" && resolved.risk != "expected" {
		reasons = append(reasons, "Agent flagged this bind as "+resolved.risk)
	}

	// Return ascending time for timeline rendering.
	sort.Slice(pidEvents, func(i, j int) bool {
		return pidEvents[i].Timestamp.Before(pidEvents[j].Timestamp)
	})

	out := PortsServiceResponse{}
	out.Window.Since = since.Format(time.RFC3339Nano)
	out.Window.Until = until.Format(time.RFC3339Nano)
	out.Service.Port = port
	out.Service.Comm = resolved.comm
	out.Service.PComm = resolved.pcomm
	out.Service.PID = resolved.pid
	out.Service.UID = resolved.uid
	out.Service.Addresses = addrs
	out.Service.Risk = resolved.risk
	out.Service.Exposed = resolved.exposed
	out.Reasons = reasons
	out.Events = pidEvents

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

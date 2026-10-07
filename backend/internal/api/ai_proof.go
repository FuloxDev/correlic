package api

import (
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/storage"
)

// AIProofHandler returns a shareable, evidence-backed report over a time window.
// It is the backend source of truth for AI Proof (UI + future MCP tooling).
type AIProofHandler struct {
	store storage.TelemetryStore
}

func NewAIProofHandler(store storage.TelemetryStore) *AIProofHandler {
	return &AIProofHandler{store: store}
}

type AIProofResponse struct {
	GeneratedAt string `json:"generated_at"`
	Window      struct {
		Since            string `json:"since"`
		Until            string `json:"until"`
		AgentID          string `json:"agent_id,omitempty"`
		IncludeNonAI     bool   `json:"include_non_ai"`
		IncludeLocalhost bool   `json:"include_localhost,omitempty"`
		IncludePrivate   bool   `json:"include_private,omitempty"`
		IncludeExternal  bool   `json:"include_external,omitempty"`
	} `json:"window"`

	Summary struct {
		TotalEvidenceEvents int `json:"total_evidence_events"`
		SecretsTouched      int `json:"secrets_touched"`
		DNSQueries          int `json:"dns_queries"`
		SuspiciousDNS       int `json:"suspicious_dns"`
		NetConnections      int `json:"net_connections"`
		ExternalConnections int `json:"external_connections"`
		ExposedBinds        int `json:"exposed_binds"`
		ProcessExecs        int `json:"process_execs"`
	} `json:"summary"`

	Risk struct {
		Score   int      `json:"score"`
		Level   string   `json:"level"`
		Reasons []string `json:"reasons,omitempty"`
	} `json:"risk"`

	Previous *struct {
		Window struct {
			Since string `json:"since"`
			Until string `json:"until"`
		} `json:"window"`
		Summary struct {
			SecretsTouched      int `json:"secrets_touched"`
			DNSQueries          int `json:"dns_queries"`
			SuspiciousDNS       int `json:"suspicious_dns"`
			NetConnections      int `json:"net_connections"`
			ExternalConnections int `json:"external_connections"`
			ExposedBinds        int `json:"exposed_binds"`
			ProcessExecs        int `json:"process_execs"`
		} `json:"summary"`
		Risk struct {
			Score int `json:"score"`
		} `json:"risk"`
	} `json:"previous,omitempty"`

	Delta *struct {
		Summary struct {
			SecretsTouched      int `json:"secrets_touched"`
			DNSQueries          int `json:"dns_queries"`
			SuspiciousDNS       int `json:"suspicious_dns"`
			NetConnections      int `json:"net_connections"`
			ExternalConnections int `json:"external_connections"`
			ExposedBinds        int `json:"exposed_binds"`
			ProcessExecs        int `json:"process_execs"`
		} `json:"summary"`
		Risk struct {
			Score int `json:"score"`
		} `json:"risk"`
	} `json:"delta,omitempty"`

	TopDomains []struct {
		Domain      string `json:"domain"`
		Count       int    `json:"count"`
		Allowlisted bool   `json:"allowlisted,omitempty"`
	} `json:"top_domains"`

	TopDestinations []struct {
		Dst         string `json:"dst"`
		Count       int    `json:"count"`
		External    bool   `json:"external,omitempty"`
		Allowlisted bool   `json:"allowlisted,omitempty"`
	} `json:"top_destinations"`

	ExternalIPs []struct {
		IP          string `json:"ip"`
		Connections int    `json:"connections"`
		Ports       int    `json:"ports"`
		Org         string `json:"org,omitempty"`
		Domains     []struct {
			Domain      string `json:"domain"`
			Count       int    `json:"count"`
			Allowlisted bool   `json:"allowlisted,omitempty"`
		} `json:"domains,omitempty"`
	} `json:"external_ips,omitempty"`
	// Total unique external IPs in window (list above is top 25 by connection count).
	ExternalIPsTotal int `json:"external_ips_total,omitempty"`

	Findings struct {
		Secrets      []AIProofResponseFindingsSecrets      `json:"secrets"`
		ExposedPorts []AIProofResponseFindingsExposedPorts `json:"exposed_ports"`
		Execs        []AIProofResponseFindingsExecs        `json:"execs"`
	} `json:"findings"`

	// Evidence is a bounded list of raw events for drilldown.
	Evidence []model.TelemetryEvent `json:"evidence"`

	// AttributionWarning is set when AI-only view includes events that match AI by process name
	// but have no executable path or run from an untrusted path (e.g. /tmp). Possible impersonation.
	AttributionWarning string `json:"attribution_warning,omitempty"`
}

func parseBoolDefault(s string, defaultVal bool) bool {
	if s == "" {
		return defaultVal
	}
	return strings.EqualFold(s, "true") || s == "1" || strings.EqualFold(s, "yes")
}

func (h *AIProofHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	includeNonAI := strings.EqualFold(r.URL.Query().Get("include_non_ai"), "true") ||
		r.URL.Query().Get("include_non_ai") == "1" ||
		strings.EqualFold(r.URL.Query().Get("include_non_ai"), "yes")

	includeLocalhost := parseBoolDefault(r.URL.Query().Get("include_localhost"), true)
	includePrivate := parseBoolDefault(r.URL.Query().Get("include_private"), true)
	includeExternal := parseBoolDefault(r.URL.Query().Get("include_external"), true)

	sinceStr := r.URL.Query().Get("since")
	untilStr := r.URL.Query().Get("until")
	now := time.Now().UTC()
	since := now.Add(-1 * time.Hour)
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

	out := AIProofResponse{}
	out.GeneratedAt = time.Now().UTC().Format(time.RFC3339Nano)
	out.Window.Since = since.Format(time.RFC3339Nano)
	out.Window.Until = until.Format(time.RFC3339Nano)
	out.Window.AgentID = agentID
	out.Window.IncludeNonAI = includeNonAI
	out.Window.IncludeLocalhost = includeLocalhost
	out.Window.IncludePrivate = includePrivate
	out.Window.IncludeExternal = includeExternal

	allow := loadNetworkAllowlist()
	// Evidence list is not tier-capped; use a fixed high limit.
	const aiProofEvidenceLimit = 5000
	cur := computeAIProofWindow(h.store, orgID, agentID, includeNonAI, since, until, allow, aiProofEvidenceLimit, includeLocalhost, includePrivate, includeExternal)
	out.Summary.TotalEvidenceEvents = len(cur.evidence)
	out.Summary.SecretsTouched = len(cur.secrets)
	out.Summary.DNSQueries = cur.dnsQueries
	out.Summary.SuspiciousDNS = cur.suspiciousDNS
	out.Summary.NetConnections = cur.netConnections
	out.Summary.ExternalConnections = cur.externalConnections
	out.Summary.ExposedBinds = len(cur.exposedPorts)
	out.Summary.ProcessExecs = cur.execs

	out.Risk.Score = cur.riskScore
	out.Risk.Level = riskLevel(cur.riskScore)
	out.Risk.Reasons = cur.riskReasons

	out.Findings.Secrets = cur.secrets
	out.Findings.ExposedPorts = cur.exposedPorts
	out.Findings.Execs = cur.execList
	out.Evidence = cur.evidence
	out.TopDomains = cur.topDomains
	out.TopDestinations = cur.topDestinations
	out.ExternalIPs = cur.externalIPs
	out.ExternalIPsTotal = cur.externalIPsTotal

	if cur.suspiciousAttributionDetected {
		out.AttributionWarning = "Some events match AI by process name and run from /tmp, /var/tmp, or a relative path. Verify they are legitimate (possible impersonation)."
	}

	// Diff vs previous window of same duration.
	dur := until.Sub(since)
	if dur > 0 && dur <= 24*time.Hour*7 {
		prevSince := since.Add(-dur)
		prevUntil := since
		prev := computeAIProofWindow(h.store, orgID, agentID, includeNonAI, prevSince, prevUntil, allow, aiProofEvidenceLimit, includeLocalhost, includePrivate, includeExternal)

		out.Previous = &struct {
			Window struct {
				Since string `json:"since"`
				Until string `json:"until"`
			} `json:"window"`
			Summary struct {
				SecretsTouched      int `json:"secrets_touched"`
				DNSQueries          int `json:"dns_queries"`
				SuspiciousDNS       int `json:"suspicious_dns"`
				NetConnections      int `json:"net_connections"`
				ExternalConnections int `json:"external_connections"`
				ExposedBinds        int `json:"exposed_binds"`
				ProcessExecs        int `json:"process_execs"`
			} `json:"summary"`
			Risk struct {
				Score int `json:"score"`
			} `json:"risk"`
		}{}
		out.Previous.Window.Since = prevSince.Format(time.RFC3339Nano)
		out.Previous.Window.Until = prevUntil.Format(time.RFC3339Nano)
		out.Previous.Summary.SecretsTouched = len(prev.secrets)
		out.Previous.Summary.DNSQueries = prev.dnsQueries
		out.Previous.Summary.SuspiciousDNS = prev.suspiciousDNS
		out.Previous.Summary.NetConnections = prev.netConnections
		out.Previous.Summary.ExternalConnections = prev.externalConnections
		out.Previous.Summary.ExposedBinds = len(prev.exposedPorts)
		out.Previous.Summary.ProcessExecs = prev.execs
		out.Previous.Risk.Score = prev.riskScore

		out.Delta = &struct {
			Summary struct {
				SecretsTouched      int `json:"secrets_touched"`
				DNSQueries          int `json:"dns_queries"`
				SuspiciousDNS       int `json:"suspicious_dns"`
				NetConnections      int `json:"net_connections"`
				ExternalConnections int `json:"external_connections"`
				ExposedBinds        int `json:"exposed_binds"`
				ProcessExecs        int `json:"process_execs"`
			} `json:"summary"`
			Risk struct {
				Score int `json:"score"`
			} `json:"risk"`
		}{}
		out.Delta.Summary.SecretsTouched = len(cur.secrets) - len(prev.secrets)
		out.Delta.Summary.DNSQueries = cur.dnsQueries - prev.dnsQueries
		out.Delta.Summary.SuspiciousDNS = cur.suspiciousDNS - prev.suspiciousDNS
		out.Delta.Summary.NetConnections = cur.netConnections - prev.netConnections
		out.Delta.Summary.ExternalConnections = cur.externalConnections - prev.externalConnections
		out.Delta.Summary.ExposedBinds = len(cur.exposedPorts) - len(prev.exposedPorts)
		out.Delta.Summary.ProcessExecs = cur.execs - prev.execs
		out.Delta.Risk.Score = cur.riskScore - prev.riskScore
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

type aiProofComputed struct {
	secrets      []AIProofResponseFindingsSecrets
	exposedPorts []AIProofResponseFindingsExposedPorts
	execList     []AIProofResponseFindingsExecs

	dnsQueries          int
	suspiciousDNS       int
	netConnections      int
	execs               int
	externalConnections int

	topDomains []struct {
		Domain      string `json:"domain"`
		Count       int    `json:"count"`
		Allowlisted bool   `json:"allowlisted,omitempty"`
	}
	topDestinations []struct {
		Dst         string `json:"dst"`
		Count       int    `json:"count"`
		External    bool   `json:"external,omitempty"`
		Allowlisted bool   `json:"allowlisted,omitempty"`
	}

	externalIPs []struct {
		IP          string `json:"ip"`
		Connections int    `json:"connections"`
		Ports       int    `json:"ports"`
		Org         string `json:"org,omitempty"`
		Domains     []struct {
			Domain      string `json:"domain"`
			Count       int    `json:"count"`
			Allowlisted bool   `json:"allowlisted,omitempty"`
		} `json:"domains,omitempty"`
	}
	externalIPsTotal int // Total unique external IPs before cap (list is top 25)

	evidence                      []model.TelemetryEvent
	riskScore                     int
	riskReasons                   []string
	suspiciousAttributionDetected bool
}

type networkAllowlist struct {
	domainsExact  map[string]struct{}
	domainsSuffix []string            // stored as ".example.com" and "example.com"
	ipExact       map[string]struct{} // ip
	ipPortExact   map[string]struct{} // ip:port
	cidrs         []*net.IPNet
}

type networkAllowlistPolicy struct {
	Domains      []string `json:"domains"`
	Destinations []string `json:"destinations"`
}

func loadNetworkAllowlist() networkAllowlist {
	// Built-in "expected" domains to reduce noise.
	builtinDomains := []string{
		"github.com",
		"api.github.com",
		"gitlab.com",
		"registry.npmjs.org",
		"npmjs.com",
		"pypi.org",
		"files.pythonhosted.org",
		"crates.io",
		"go.dev",
		"proxy.golang.org",
	}
	pol := networkAllowlistPolicy{Domains: builtinDomains}

	out := networkAllowlist{
		domainsExact: make(map[string]struct{}, 64),
		ipExact:      make(map[string]struct{}, 64),
		ipPortExact:  make(map[string]struct{}, 64),
	}
	for _, d := range pol.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			base := strings.TrimPrefix(d, "*.")
			base = strings.TrimSpace(base)
			if base == "" {
				continue
			}
			out.domainsSuffix = append(out.domainsSuffix, "."+base)
			out.domainsSuffix = append(out.domainsSuffix, base)
			continue
		}
		out.domainsExact[d] = struct{}{}
	}
	for _, dst := range pol.Destinations {
		dst = strings.TrimSpace(dst)
		if dst == "" {
			continue
		}
		if strings.Contains(dst, "/") {
			_, ipnet, err := net.ParseCIDR(dst)
			if err == nil && ipnet != nil {
				out.cidrs = append(out.cidrs, ipnet)
			}
			continue
		}
		host, port := splitHostPortLoose(dst)
		if port != "" {
			out.ipPortExact[host+":"+port] = struct{}{}
		} else {
			out.ipExact[host] = struct{}{}
		}
	}
	return out
}

func (a networkAllowlist) domainAllowed(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return false
	}
	if _, ok := a.domainsExact[d]; ok {
		return true
	}
	for _, suf := range a.domainsSuffix {
		if suf == d || strings.HasSuffix(d, suf) {
			return true
		}
	}
	return false
}

func (a networkAllowlist) dstAllowed(dst string) bool {
	host, port := splitHostPortLoose(dst)
	if host == "" {
		return false
	}
	if port != "" {
		if _, ok := a.ipPortExact[host+":"+port]; ok {
			return true
		}
	}
	if _, ok := a.ipExact[host]; ok {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, c := range a.cidrs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

// destKind classifies a connection destination for filtering.
const (
	destLocalhost = "localhost"
	destPrivate   = "private"
	destExternal  = "external"
)

func classifyDest(host string) string {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return destExternal
	}
	if ip.IsLoopback() {
		return destLocalhost
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return destPrivate
	}
	return destExternal
}

// computeAIProofWindow aggregates telemetry in [since, until]. When includeNonAI is true
// ("All processes"), every event in the window is counted; when false, only AI-attributed events are.
// Destination filters (includeLocalhost, includePrivate, includeExternal) apply to net_connect and net_bind.
func computeAIProofWindow(store storage.TelemetryStore, orgID, agentID string, includeNonAI bool, since, until time.Time, allow networkAllowlist, evidenceLimit int, includeLocalhost, includePrivate, includeExternal bool) aiProofComputed {
	aiPIDs := map[int64]struct{}{}
	if !includeNonAI {
		aiPIDs = buildAIPIDSet(store, orgID, agentID, since, until)
	}

	out := aiProofComputed{}
	out.secrets = make([]AIProofResponseFindingsSecrets, 0)
	out.exposedPorts = make([]AIProofResponseFindingsExposedPorts, 0)
	out.execList = make([]AIProofResponseFindingsExecs, 0)

	domainCounts := make(map[string]int, 256)
	dstCounts := make(map[string]int, 256)
	dstExternal := make(map[string]bool, 256)
	dstAllow := make(map[string]bool, 256)
	domainAllow := make(map[string]bool, 256)

	dnsByPID := make(map[int][]dnsObservation, 256)

	type ipAgg struct {
		connections int
		ports       map[string]struct{}
		domains     map[string]int
	}
	ipByHost := make(map[string]*ipAgg, 256)

	// IMPORTANT: storage.ListFiltered() is clamped to 500 rows per call.
	// For stable, correct window totals we must paginate until exhausted (or a scan cap).
	pageLimit := 500
	maxScanPerType := 20000

	if evidenceLimit <= 0 {
		evidenceLimit = 200
	}
	maxEvidenceCollect := evidenceLimit * 10
	if maxEvidenceCollect < 500 {
		maxEvidenceCollect = 500
	}
	allEvidence := make([]model.TelemetryEvent, 0, maxEvidenceCollect)

	isAIEvent := func(payload map[string]any) bool {
		return eventMatchesAICandidates(payload) || payloadMatchesAIPIDs(payload, aiPIDs)
	}

	// skipDest returns true if this net_connect destination should be excluded by the include_* filters.
	skipDest := func(p map[string]any) bool {
		ip := strings.TrimSpace(asString(p["dst_ip"], p["remote_ip"]))
		dst := strings.TrimSpace(asString(p["dst_addr"], p["remote_addr"]))
		if ip != "" {
			dst = ip
		}
		host, _ := splitHostPortLoose(dst)
		if host == "" {
			return false
		}
		kind := classifyDest(host)
		switch kind {
		case destLocalhost:
			return !includeLocalhost
		case destPrivate:
			return !includePrivate
		case destExternal:
			return !includeExternal
		}
		return false
	}

	scanWithSkip := func(eventType string, skip func(ev model.TelemetryEvent, p map[string]any) bool, handle func(ev model.TelemetryEvent, payload map[string]any)) int {
		count := 0
		offset := 0
		scanned := 0
		for {
			evs, _ := store.ListFiltered(orgID, storage.TelemetryListFilter{
				AgentID:   agentID,
				EventType: eventType,
				Since:     since,
				Until:     until,
				Limit:     pageLimit,
				Offset:    offset,
			})
			if len(evs) == 0 {
				break
			}
			for _, ev := range evs {
				scanned++
				if scanned > maxScanPerType {
					return count
				}
				var p map[string]any
				_ = json.Unmarshal(ev.Payload, &p)
				if !includeNonAI && !isAIEvent(p) {
					continue
				}
				if skip != nil && skip(ev, p) {
					continue
				}
				count++
				if len(allEvidence) < maxEvidenceCollect {
					allEvidence = append(allEvidence, ev)
				}
				if handle != nil {
					handle(ev, p)
				}
			}
			if len(evs) < pageLimit {
				break
			}
			offset += len(evs)
			if offset >= maxScanPerType {
				break
			}
		}
		return count
	}
	scan := func(eventType string, handle func(ev model.TelemetryEvent, payload map[string]any)) int {
		return scanWithSkip(eventType, nil, handle)
	}

	destFilterActive := !includeLocalhost || !includePrivate || !includeExternal
	var allowedPIDs map[int64]struct{}
	if destFilterActive {
		allowedPIDs = make(map[int64]struct{}, 256)
	}
	// When destination filter is on, only include events from PIDs that had at least one connection passing the filter.
	var skipPIDs func(ev model.TelemetryEvent, p map[string]any) bool
	if destFilterActive {
		skipPIDs = func(ev model.TelemetryEvent, p map[string]any) bool {
			pid := intFromAny(p["pid"])
			if pid <= 0 {
				return true
			}
			_, ok := allowedPIDs[int64(pid)]
			return !ok
		}
	}

	runNetConnect := func() int {
		var netConnectSkip func(ev model.TelemetryEvent, p map[string]any) bool
		if destFilterActive {
			netConnectSkip = func(ev model.TelemetryEvent, p map[string]any) bool { return skipDest(p) }
		}
		return scanWithSkip("net_connect", netConnectSkip, func(ev model.TelemetryEvent, p map[string]any) {
			if destFilterActive {
				if pid := intFromAny(p["pid"]); pid > 0 {
					allowedPIDs[int64(pid)] = struct{}{}
				}
			}
			ip := strings.TrimSpace(asString(p["dst_ip"], p["remote_ip"]))
			port := strings.TrimSpace(asString(p["dst_port"], p["remote_port"]))
			dst := strings.TrimSpace(asString(p["dst_addr"], p["remote_addr"]))
			if ip != "" && port != "" {
				dst = ip + ":" + port
			} else if ip != "" {
				dst = ip
			}
			if dst == "" {
				return
			}
			dstCounts[dst]++
			host, _ := splitHostPortLoose(dst)
			ext := host != "" && !isPrivateOrLocalIP(host)
			allowed := allow.dstAllowed(dst)
			dstExternal[dst] = ext
			dstAllow[dst] = allowed
			if ext && !allowed {
				out.externalConnections++
			}
			if ext && host != "" {
				agg := ipByHost[host]
				if agg == nil {
					agg = &ipAgg{ports: make(map[string]struct{}, 8), domains: make(map[string]int, 8)}
					ipByHost[host] = agg
				}
				agg.connections++
				_, prt := splitHostPortLoose(dst)
				if prt != "" {
					agg.ports[prt] = struct{}{}
				}
				pid := intFromAny(p["pid"])
				if pid > 0 {
					if dom := lastDomainBefore(dnsByPID[pid], ev.Timestamp, 60*time.Second); dom != "" {
						agg.domains[dom]++
					}
				}
			}
		})
	}

	if destFilterActive {
		// Run net_connect first to build allowedPIDs; then other event types are restricted to those PIDs.
		netConnScanned := runNetConnect()
		if !includeNonAI {
			out.netConnections = netConnScanned
		} else {
			out.netConnections = netConnScanned
		}
	} else {
		// No destination filter: dns_query first (for dnsByPID correlation), then net_connect.
		out.dnsQueries = scan("dns_query", func(ev model.TelemetryEvent, p map[string]any) {
			d := strings.TrimSpace(asString(p["domain"], p["query"], p["name"]))
			if d == "" {
				return
			}
			domainCounts[d]++
			pid := intFromAny(p["pid"])
			if pid > 0 {
				dnsByPID[pid] = append(dnsByPID[pid], dnsObservation{ts: ev.Timestamp, domain: d})
			}
			if asBool(p["suspicious"], p["is_suspicious"]) {
				out.suspiciousDNS++
			}
			if allow.domainAllowed(d) {
				domainAllow[d] = true
			}
		})
		for pid := range dnsByPID {
			sort.Slice(dnsByPID[pid], func(i, j int) bool { return dnsByPID[pid][i].ts.Before(dnsByPID[pid][j].ts) })
		}
		if includeNonAI {
			if n, err := store.CountFiltered(orgID, storage.TelemetryListFilter{
				AgentID: agentID, EventType: "net_connect", Since: since, Until: until,
			}); err == nil {
				out.netConnections = n
			}
		}
		netConnScanned := runNetConnect()
		if !includeNonAI {
			out.netConnections = netConnScanned
		} else if out.netConnections == 0 {
			out.netConnections = netConnScanned
		}
	}

	// DNS: when destFilterActive we run after net_connect and filter by allowedPIDs.
	if destFilterActive {
		out.dnsQueries = scanWithSkip("dns_query", skipPIDs, func(ev model.TelemetryEvent, p map[string]any) {
			d := strings.TrimSpace(asString(p["domain"], p["query"], p["name"]))
			if d == "" {
				return
			}
			domainCounts[d]++
			pid := intFromAny(p["pid"])
			if pid > 0 {
				dnsByPID[pid] = append(dnsByPID[pid], dnsObservation{ts: ev.Timestamp, domain: d})
			}
			if asBool(p["suspicious"], p["is_suspicious"]) {
				out.suspiciousDNS++
			}
			if allow.domainAllowed(d) {
				domainAllow[d] = true
			}
		})
		for pid := range dnsByPID {
			sort.Slice(dnsByPID[pid], func(i, j int) bool { return dnsByPID[pid][i].ts.Before(dnsByPID[pid][j].ts) })
		}
	}

	scanWithSkip("file_open", skipPIDs, func(ev model.TelemetryEvent, p map[string]any) {
		path := strings.TrimSpace(asString(p["path"], p["file"], p["target"]))
		if path == "" {
			return
		}
		cat := strings.TrimSpace(asString(p["category"]))
		low := strings.ToLower(path)
		if isNoisySecretPath(low) {
			return
		}

		// Category can be a helpful hint, but "credential_file" is far too noisy on Linux
		// (e.g., /proc/*/loginuid). We only treat specific, high-signal categories as secrets.
		if cat != "" {
			cl := strings.ToLower(cat)
			if strings.Contains(cl, "ssh") || strings.Contains(cl, "aws") || strings.Contains(cl, "kube") || strings.Contains(cl, "gpg") {
				addSecretByPath(&out, path, cat, ev.ID, ev.Timestamp)
				return
			}
		}

		// Path-based detection: high-signal secret locations/files.
		if strings.Contains(low, "/.ssh/") ||
			strings.Contains(low, "/.aws/") ||
			strings.Contains(low, "/.kube/") ||
			strings.Contains(low, "/.gnupg/") ||
			strings.Contains(low, "/.docker/config.json") ||
			strings.Contains(low, "/.npmrc") ||
			strings.Contains(low, "/.pypirc") ||
			strings.Contains(low, "/.git-credentials") ||
			strings.Contains(low, "/.netrc") ||
			strings.Contains(low, "id_rsa") ||
			strings.Contains(low, "id_ed25519") ||
			strings.Contains(low, "/.env") {
			addSecretByPath(&out, path, cat, ev.ID, ev.Timestamp)
		}
	})

	scanWithSkip("net_bind", skipPIDs, func(ev model.TelemetryEvent, p map[string]any) {
		addr := strings.TrimSpace(asString(p["bind_addr"]))
		port := intFromAny(p["bind_port"], p["port"])
		if addr == "" || port <= 0 {
			return
		}
		exposed := asBool(p["is_exposed"]) || addr == "0.0.0.0" || addr == "::"
		if !exposed {
			return
		}
		out.exposedPorts = append(out.exposedPorts, AIProofResponseFindingsExposedPorts{
			BindAddr: addr,
			BindPort: port,
			Comm:     strings.TrimSpace(asString(p["comm"])),
			PComm:    strings.TrimSpace(asString(p["pcomm"])),
			Risk:     strings.TrimSpace(asString(p["risk"])),
			EventID:  ev.ID,
			EventTS:  ev.Timestamp.Format(time.RFC3339Nano),
		})
	})

	out.execs = scanWithSkip("process_exec", skipPIDs, func(ev model.TelemetryEvent, p map[string]any) {
		out.execList = append(out.execList, AIProofResponseFindingsExecs{
			Comm:    strings.TrimSpace(asString(p["comm"])),
			PComm:   strings.TrimSpace(asString(p["pcomm"])),
			Exe:     strings.TrimSpace(asString(p["exe"])),
			EventID: ev.ID,
			EventTS: ev.Timestamp.Format(time.RFC3339Nano),
		})
	})

	sort.Slice(out.secrets, func(i, j int) bool { return out.secrets[i].EventTS > out.secrets[j].EventTS })
	sort.Slice(out.exposedPorts, func(i, j int) bool { return out.exposedPorts[i].EventTS > out.exposedPorts[j].EventTS })
	sort.Slice(out.execList, func(i, j int) bool { return out.execList[i].EventTS > out.execList[j].EventTS })

	sort.Slice(allEvidence, func(i, j int) bool {
		return allEvidence[i].Timestamp.After(allEvidence[j].Timestamp)
	})
	if len(allEvidence) > evidenceLimit {
		allEvidence = allEvidence[:evidenceLimit]
	}
	out.evidence = allEvidence

	if !includeNonAI {
		for _, ev := range out.evidence {
			var p map[string]any
			if json.Unmarshal(ev.Payload, &p) != nil {
				continue
			}
			if IsSuspiciousAIAttribution(p) {
				out.suspiciousAttributionDetected = true
				break
			}
		}
	}

	out.topDomains = topN(domainCounts, 10, func(k string, v int) struct {
		Domain      string `json:"domain"`
		Count       int    `json:"count"`
		Allowlisted bool   `json:"allowlisted,omitempty"`
	} {
		return struct {
			Domain      string `json:"domain"`
			Count       int    `json:"count"`
			Allowlisted bool   `json:"allowlisted,omitempty"`
		}{Domain: k, Count: v, Allowlisted: domainAllow[k]}
	})
	out.topDestinations = topN(dstCounts, 10, func(k string, v int) struct {
		Dst         string `json:"dst"`
		Count       int    `json:"count"`
		External    bool   `json:"external,omitempty"`
		Allowlisted bool   `json:"allowlisted,omitempty"`
	} {
		return struct {
			Dst         string `json:"dst"`
			Count       int    `json:"count"`
			External    bool   `json:"external,omitempty"`
			Allowlisted bool   `json:"allowlisted,omitempty"`
		}{Dst: k, Count: v, External: dstExternal[k], Allowlisted: dstAllow[k]}
	})

	// Build enriched external IP list (top 25).
	type ipRow struct {
		ip          string
		connections int
		ports       int
		domains     []struct {
			domain string
			count  int
			allow  bool
		}
	}
	rows := make([]ipRow, 0, len(ipByHost))
	for ip, agg := range ipByHost {
		r := ipRow{ip: ip, connections: agg.connections, ports: len(agg.ports)}
		ds := make([]struct {
			domain string
			count  int
			allow  bool
		}, 0, len(agg.domains))
		for d, c := range agg.domains {
			ds = append(ds, struct {
				domain string
				count  int
				allow  bool
			}{domain: d, count: c, allow: domainAllow[d]})
		}
		sort.Slice(ds, func(i, j int) bool {
			if ds[i].count == ds[j].count {
				return ds[i].domain < ds[j].domain
			}
			return ds[i].count > ds[j].count
		})
		if len(ds) > 5 {
			ds = ds[:5]
		}
		r.domains = ds
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].connections == rows[j].connections {
			return rows[i].ip < rows[j].ip
		}
		return rows[i].connections > rows[j].connections
	})
	const externalIPsCap = 25
	out.externalIPsTotal = len(rows)
	if len(rows) > externalIPsCap {
		rows = rows[:externalIPsCap]
	}

	orgByIP := make(map[string]string, len(rows))

	out.externalIPs = make([]struct {
		IP          string `json:"ip"`
		Connections int    `json:"connections"`
		Ports       int    `json:"ports"`
		Org         string `json:"org,omitempty"`
		Domains     []struct {
			Domain      string `json:"domain"`
			Count       int    `json:"count"`
			Allowlisted bool   `json:"allowlisted,omitempty"`
		} `json:"domains,omitempty"`
	}, 0, len(rows))
	for _, r := range rows {
		item := struct {
			IP          string `json:"ip"`
			Connections int    `json:"connections"`
			Ports       int    `json:"ports"`
			Org         string `json:"org,omitempty"`
			Domains     []struct {
				Domain      string `json:"domain"`
				Count       int    `json:"count"`
				Allowlisted bool   `json:"allowlisted,omitempty"`
			} `json:"domains,omitempty"`
		}{
			IP:          r.ip,
			Connections: r.connections,
			Ports:       r.ports,
			Org:         orgByIP[r.ip],
		}
		for _, d := range r.domains {
			item.Domains = append(item.Domains, struct {
				Domain      string `json:"domain"`
				Count       int    `json:"count"`
				Allowlisted bool   `json:"allowlisted,omitempty"`
			}{
				Domain:      d.domain,
				Count:       d.count,
				Allowlisted: d.allow,
			})
		}
		out.externalIPs = append(out.externalIPs, item)
	}

	out.riskScore, out.riskReasons = computeRisk(out)
	return out
}

type dnsObservation struct {
	ts     time.Time
	domain string
}

func isNoisySecretPath(lowPath string) bool {
	// /proc pseudo-files are extremely noisy and not "secrets touched" in the sense users expect.
	// Especially loginuid which is read by many processes.
	if strings.HasPrefix(lowPath, "/proc/") {
		if strings.Contains(lowPath, "/loginuid") {
			return true
		}
		// Treat all /proc as noise for secrets. Real secrets should not live there.
		return true
	}
	// Similar pseudo-filesystems.
	if strings.HasPrefix(lowPath, "/sys/") || strings.HasPrefix(lowPath, "/dev/") {
		return true
	}
	// Source trees / system libs that sometimes get mislabeled as credential_file.
	if strings.Contains(lowPath, "/usr/lib/go-") && strings.Contains(lowPath, "/src/") {
		return true
	}
	return false
}

func addSecretByPath(out *aiProofComputed, path, category, eventID string, ts time.Time) {
	// Dedupe: keep the latest event per path.
	if out == nil {
		return
	}
	if outSecretIndex == nil {
		outSecretIndex = make(map[*aiProofComputed]map[string]AIProofResponseFindingsSecrets, 4)
	}
	m := outSecretIndex[out]
	if m == nil {
		m = make(map[string]AIProofResponseFindingsSecrets, 64)
		outSecretIndex[out] = m
	}
	cur, ok := m[path]
	next := AIProofResponseFindingsSecrets{
		Path:     path,
		Category: category,
		EventID:  eventID,
		EventTS:  ts.Format(time.RFC3339Nano),
	}
	if !ok || next.EventTS > cur.EventTS {
		m[path] = next
	}

	// Rebuild slice lazily: update/append by path key.
	// This keeps `out.secrets` stable for downstream usage.
	found := false
	for i := range out.secrets {
		if out.secrets[i].Path == path {
			out.secrets[i] = m[path]
			found = true
			break
		}
	}
	if !found {
		out.secrets = append(out.secrets, m[path])
	}
}

var outSecretIndex map[*aiProofComputed]map[string]AIProofResponseFindingsSecrets

func lastDomainBefore(sorted []dnsObservation, t time.Time, maxAge time.Duration) string {
	if len(sorted) == 0 {
		return ""
	}
	i := sort.Search(len(sorted), func(i int) bool { return !sorted[i].ts.Before(t) })
	for j := i - 1; j >= 0; j-- {
		dt := t.Sub(sorted[j].ts)
		if dt < 0 {
			continue
		}
		if dt > maxAge {
			break
		}
		if sorted[j].domain != "" {
			return sorted[j].domain
		}
	}
	return ""
}

func computeRisk(c aiProofComputed) (int, []string) {
	score := 0
	reasons := make([]string, 0, 6)

	if len(c.secrets) > 0 {
		score += 60
		reasons = append(reasons, "Secrets/credentials were accessed")
	}
	if len(c.exposedPorts) > 0 {
		score += 25
		reasons = append(reasons, "Exposed ports were bound on wildcard/public interfaces")
	}
	if c.suspiciousDNS > 0 {
		score += 20
		reasons = append(reasons, "Suspicious DNS queries were observed")
	}
	if c.externalConnections > 0 {
		score += 15
		reasons = append(reasons, "Non-allowlisted external connections occurred")
	}
	// Small bump for high activity (AI tool doing a lot quickly).
	if c.execs >= 50 || c.netConnections >= 200 || c.dnsQueries >= 200 {
		score += 10
		reasons = append(reasons, "High activity volume in this window")
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score, reasons
}

func riskLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 55:
		return "high"
	case score >= 30:
		return "medium"
	case score >= 10:
		return "low"
	default:
		return "none"
	}
}

func splitHostPortLoose(s string) (host string, port string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	// Attempt to split on last colon and see if tail looks like a port.
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return s, ""
	}
	h := s[:i]
	p := s[i+1:]
	if p == "" {
		return s, ""
	}
	for _, r := range p {
		if r < '0' || r > '9' {
			return s, ""
		}
	}
	return h, p
}

func isPrivateOrLocalIP(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	// Treat unique local / multicast as non-external.
	if ip.IsMulticast() {
		return true
	}
	return false
}

// These small structs exist only to make slices easier to work with above.
type AIProofResponseFindingsSecrets = struct {
	Path     string `json:"path"`
	Category string `json:"category,omitempty"`
	EventID  string `json:"event_id,omitempty"`
	EventTS  string `json:"event_ts"`
}
type AIProofResponseFindingsExposedPorts = struct {
	BindAddr string `json:"bind_addr"`
	BindPort int    `json:"bind_port"`
	Comm     string `json:"comm,omitempty"`
	PComm    string `json:"pcomm,omitempty"`
	Risk     string `json:"risk,omitempty"`
	EventID  string `json:"event_id,omitempty"`
	EventTS  string `json:"event_ts"`
}
type AIProofResponseFindingsExecs = struct {
	Comm    string `json:"comm,omitempty"`
	PComm   string `json:"pcomm,omitempty"`
	Exe     string `json:"exe,omitempty"`
	EventID string `json:"event_id,omitempty"`
	EventTS string `json:"event_ts"`
}

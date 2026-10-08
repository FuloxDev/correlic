package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/ai/intelligence"
	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/enrichment"
	"github.com/correlic/correlic-backend/internal/incident"
	"github.com/correlic/correlic-backend/internal/storage"
	neo4jstore "github.com/correlic/correlic-backend/internal/storage/neo4j"
)

// FindingsHandler handles HTTP requests for detection findings.
type FindingsHandler struct {
	store             *storage.FindingStore
	baselineCollector *detection.BaselineCollector
	incidentStore     *incident.IncidentStore
	safeDomainStore   *storage.SafeDomainStore
	neo4jClient       *neo4jstore.Client // optional, nil-safe — used for domain resolution
	patternLearner    *intelligence.PatternLearner
}

// NewFindingsHandler creates a new findings handler.
func NewFindingsHandler(store *storage.FindingStore, baselineCollector *detection.BaselineCollector, incidentStore *incident.IncidentStore) *FindingsHandler {
	return &FindingsHandler{store: store, baselineCollector: baselineCollector, incidentStore: incidentStore}
}

// SetSafeDomainStore sets the safe domain store for reconciliation.
func (h *FindingsHandler) SetSafeDomainStore(s *storage.SafeDomainStore) {
	h.safeDomainStore = s
}

// SetPatternLearner sets the AI pattern learner for recording user actions on findings.
func (h *FindingsHandler) SetPatternLearner(pl *intelligence.PatternLearner) {
	h.patternLearner = pl
}

// SetNeo4jClient sets the Neo4j client for domain resolution queries.
func (h *FindingsHandler) SetNeo4jClient(client *neo4jstore.Client) {
	h.neo4jClient = client
}

// ListFindings handles GET /api/v1/findings?host_id=X&status=Y&since=Z&limit=N
func (h *FindingsHandler) ListFindings(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	hostID := r.URL.Query().Get("host_id")
	status := r.URL.Query().Get("status") // optional: pending, allowed, dismissed, investigating

	since := time.Now().Add(-24 * time.Hour) // default: last 24 hours
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	limit := 1000
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		n := 0
		for _, c := range limitStr {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		if n > 0 && n <= 5000 {
			limit = n
		}
	}

	showSuppressed := r.URL.Query().Get("show_suppressed") == "true"

	var findings []storage.FindingRow
	var err error

	if hostID != "" {
		findings, err = h.store.ListByHost(orgID, hostID, status, since, limit, showSuppressed)
	} else {
		findings, err = h.store.ListAll(orgID, status, since, limit, showSuppressed)
	}

	if err != nil {
		log.Printf("ERROR: list findings failed: %v", err)
		Internal(w)
		return
	}
	if findings == nil {
		findings = []storage.FindingRow{}
	}

	// Also get total count (ignoring limit) for the UI badge
	totalCounts, _ := h.store.CountByStatus(orgID, since)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"findings":      findings,
		"count":         len(findings),
		"total":         totalCounts.Total,
		"total_pending": totalCounts.Pending,
	})
}

// GetFinding handles GET /api/v1/findings/{id}
func (h *FindingsHandler) GetFinding(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	rawID := r.URL.Path[len("/api/v1/findings/"):]
	findingID, err := url.PathUnescape(rawID)
	if err != nil {
		findingID = rawID
	}
	if findingID == "" {
		BadRequest(w, "finding ID required")
		return
	}

	finding, err := h.store.GetByID(orgID, findingID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			log.Printf("GetFinding 404: id=%s org=%s", findingID, orgID)
			NotFound(w, "finding not found")
			return
		}
		Internal(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(finding)
}

// ResolveFinding handles PATCH /api/v1/findings/{id}
// Body: {"status": "allowed|dismissed|investigating", "resolution": "reason text"}
// When status is "allowed", the finding's pattern is automatically added to behavioral
// baselines with source "user_confirmed", closing the user feedback loop.
func (h *FindingsHandler) ResolveFinding(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// Extract finding ID from URL path (may be URL-encoded due to slashes in IDs)
	rawID := r.URL.Path[len("/api/v1/findings/"):]
	findingID, err := url.PathUnescape(rawID)
	if err != nil {
		findingID = rawID
	}
	if findingID == "" {
		BadRequest(w, "finding ID required")
		return
	}

	var body struct {
		Status       string  `json:"status"`
		Resolution   string  `json:"resolution"`
		ExpiresIn    string  `json:"expires_in,omitempty"`    // "7d", "30d", "90d"
		ExpiresAt    *string `json:"expires_at,omitempty"`    // ISO 8601 datetime
		BaselineMode string  `json:"baseline_mode,omitempty"` // "command", "file", "both" (for ai.command_activity)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid request body")
		return
	}

	validStatuses := map[string]bool{
		"allowed":       true,
		"dismissed":     true,
		"investigating": true,
	}
	if !validStatuses[body.Status] {
		BadRequest(w, "status must be: allowed, dismissed, or investigating")
		return
	}

	// Get resolved_by from request context (set by auth middleware)
	resolvedBy := "system"
	if _, actorID, ok := middleware.ActorFromContext(r.Context()); ok && actorID != "" {
		resolvedBy = actorID
	}

	if err := h.store.UpdateStatus(orgID, findingID, body.Status, body.Resolution, resolvedBy); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			NotFound(w, "finding not found")
			return
		}
		Internal(w)
		return
	}
	log.Printf("finding status change: id=%s org=%s status=%s actor=%s", findingID, orgID, body.Status, resolvedBy)

	// Record the action for AI pattern learning (Layer 3).
	if h.patternLearner != nil {
		finding, findErr := h.store.GetByID(orgID, findingID)
		if findErr == nil && finding != nil {
			go h.patternLearner.RecordFindingAction(context.Background(), orgID, finding.Context, body.Status)
		}
	}

	// When status is "allowed", learn the pattern as a user-confirmed baseline.
	// This closes the feedback loop: user approval → baseline → future suppression.
	if body.Status == "allowed" && h.baselineCollector != nil {
		// Parse optional expiration for the baseline
		expiresAt := parseBaselineExpiry(body.ExpiresIn, body.ExpiresAt)

		finding, err := h.store.GetByID(orgID, findingID)
		if err == nil && finding != nil {
			// For ai.command_activity findings, baseline_mode controls what gets baselined:
			//   "file"    → baseline the file path (signal_type=command_file)
			//   "command" → baseline the command (signal_type=command) — default
			//   "both"    → baseline both
			baselineMode := body.BaselineMode
			if baselineMode == "" {
				baselineMode = "command" // default: baseline the command pattern
			}

			// Handle baseline_mode for command-based findings (any rule with "binary" in context)
			switch baselineMode {
			case "binary":
				// "Allow Binary" — baseline just the binary name (any invocation suppressed)
				// Check both "binary" and "comm" fields — some rules use one or the other.
				binaryName, _ := finding.Context["binary"].(string)
				if binaryName == "" {
					binaryName, _ = finding.Context["comm"].(string)
				}
				if binaryName != "" {
					binaryCtx := map[string]any{
						"signal_type": "command_binary",
						"pattern":     binaryName,
						"ai_type":     finding.Context["ai_type"],
					}
					if err := h.baselineCollector.LearnFromFinding(orgID, finding.HostID, binaryCtx, expiresAt); err != nil {
						log.Printf("WARN: binary baseline rejected for finding %s: %v", findingID, err)
					}
				}
			case "command":
				// "Allow Command" — baseline the full cmdline pattern
				if err := h.baselineCollector.LearnFromFinding(orgID, finding.HostID, finding.Context, expiresAt); err != nil {
					log.Printf("WARN: baseline rejected for finding %s: %v", findingID, err)
				}
			case "file":
				// "Allow File" — baseline the file path.
				// Use file_pattern for file-access findings (ai.file_activity etc.) so
				// IsFileBaselined() can match them. Use command_file only for command
				// findings (ai.command_activity) where "binary" is present.
				if filePath, ok := finding.Context["file_path"].(string); ok && filePath != "" {
					filePath = filepath.ToSlash(filePath)
					signalType := "file_pattern"
					if _, hasBinary := finding.Context["binary"].(string); hasBinary {
						signalType = "command_file"
					}
					fileCtx := map[string]any{
						"signal_type": signalType,
						"pattern":     filePath,
						"ai_type":     finding.Context["ai_type"],
					}
					if err := h.baselineCollector.LearnFromFinding(orgID, finding.HostID, fileCtx, expiresAt); err != nil {
						log.Printf("WARN: file baseline rejected for finding %s: %v", findingID, err)
					}
				}
			case "directory":
				// "Allow Directory" — baseline the parent directory glob.
				// Always use signal_type="file_pattern" so that IsFileBaselined() (which
				// checks file_pattern baselines) can match this directory glob against
				// ALL file-related signal types at detection time.
				if filePath, ok := finding.Context["file_path"].(string); ok && filePath != "" {
					filePath = filepath.ToSlash(filePath) // normalize Windows backslashes
					dirPath := filePath[:strings.LastIndex(filePath, "/")]
					dirCtx := map[string]any{
						"signal_type": "file_pattern",
						"pattern":     dirPath + "/**",
						"ai_type":     finding.Context["ai_type"],
					}
					if err := h.baselineCollector.LearnFromFinding(orgID, finding.HostID, dirCtx, expiresAt); err != nil {
						log.Printf("WARN: directory baseline rejected for finding %s: %v", findingID, err)
					}
				}
			default:
				// Default: baseline the finding's own signal_type + pattern
				if err := h.baselineCollector.LearnFromFinding(orgID, finding.HostID, finding.Context, expiresAt); err != nil {
					log.Printf("WARN: baseline rejected for finding %s: %v", findingID, err)
				}
			}

			// Retroactive suppression: resolve other pending findings with the
			// same baseline that was just created.
			switch {
			case baselineMode == "binary":
				if binary, ok := finding.Context["binary"].(string); ok && binary != "" {
					count, _, err := h.store.AutoResolveByBaseline(orgID, finding.HostID, "command_binary", binary)
					if err != nil {
						log.Printf("WARN: retroactive binary baseline suppression failed: %v", err)
					} else if count > 0 {
						log.Printf("Retroactive binary baseline suppression: resolved %d finding(s) for command_binary:%s", count, binary)
					}
				}
			case baselineMode == "file" && finding.Context["file_path"] != nil:
				if filePath, ok := finding.Context["file_path"].(string); ok && filePath != "" {
					filePath = filepath.ToSlash(filePath)
					// Resolve both signal types to cover file_activity and command findings
					for _, st := range []string{"file_pattern", "command_file"} {
						count, _, err := h.store.AutoResolveByBaseline(orgID, finding.HostID, st, filePath)
						if err != nil {
							log.Printf("WARN: retroactive file baseline suppression failed for %s: %v", st, err)
						} else if count > 0 {
							log.Printf("Retroactive file baseline suppression: resolved %d finding(s) for %s:%s", count, st, filePath)
						}
					}
				}
			case baselineMode == "directory":
				if filePath, ok := finding.Context["file_path"].(string); ok && filePath != "" {
					filePath = filepath.ToSlash(filePath)
					dirPath := filePath[:strings.LastIndex(filePath, "/")]
					dirPattern := dirPath + "/**"
					count, _, err := h.store.AutoResolveByBaseline(orgID, finding.HostID, "file_pattern", dirPattern)
					if err != nil {
						log.Printf("WARN: retroactive directory baseline suppression failed: %v", err)
					} else if count > 0 {
						log.Printf("Retroactive directory baseline suppression: resolved %d finding(s) for file_pattern:%s", count, dirPattern)
					}
				}
			default:
				signalType, _ := finding.Context["signal_type"].(string)
				pattern, _ := finding.Context["pattern"].(string)
				if signalType != "" && pattern != "" {
					if (signalType == "file_pattern" || signalType == "file_activity") && strings.HasSuffix(pattern, "/") && !strings.HasSuffix(pattern, "/**") {
						pattern = strings.TrimSuffix(pattern, "/") + "/**"
					}
					count, _, err := h.store.AutoResolveByBaseline(orgID, finding.HostID, signalType, pattern)
					if err != nil {
						log.Printf("WARN: retroactive baseline suppression failed for %s:%s: %v", signalType, pattern, err)
					} else if count > 0 {
						log.Printf("Retroactive baseline suppression: resolved %d finding(s) for %s:%s", count, signalType, pattern)
					}
				}
			}
		}
	}

	// Reverse cascade: if all findings in the parent incident are now resolved,
	// auto-resolve the incident too.
	if body.Status == "allowed" || body.Status == "dismissed" {
		h.maybeResolveParentIncident(r.Context(), orgID, findingID, body.Status, resolvedBy)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ok":     true,
		"id":     findingID,
		"status": body.Status,
	})
}

// maybeResolveParentIncident checks if the resolved finding belongs to an incident,
// and if all sibling findings are also resolved, auto-resolves the incident.
// Uses ReconcileStaleIncidents which is a single atomic SQL UPDATE — no race conditions.
// Note: for bulk operations (parallel PATCHes), this may not resolve the incident
// immediately since concurrent requests see each other's findings as still pending.
// The ListIncidents handler also runs ReconcileStaleIncidents as a safety net.
func (h *FindingsHandler) maybeResolveParentIncident(ctx context.Context, orgID, findingID, findingStatus, resolvedBy string) {
	if h.incidentStore == nil {
		return
	}

	// Get the finding to check if it has a parent incident.
	finding, err := h.store.GetByID(orgID, findingID)
	if err != nil || finding == nil || finding.IncidentID == nil || *finding.IncidentID == "" {
		return
	}

	// Run reconciliation for this org. The SQL atomically resolves any incident
	// where ALL findings are resolved. Safe to call from concurrent requests.
	if n, err := h.incidentStore.ReconcileStaleIncidents(ctx, orgID); err != nil {
		log.Printf("WARN: reconcile after finding resolve failed: %v", err)
	} else if n > 0 {
		log.Printf("Reconciled %d incident(s) after resolving finding %s", n, findingID)
	}
}

// ResolveDomain handles POST /api/v1/findings/{id}/resolve-domain
// Looks up the domain for a network finding's destination IP by:
// 1. Querying Neo4j for net_dns events from the same host within ±60s of the finding
// 2. Falling back to enrichment (reverse DNS + ASN lookup)
// Returns the resolved domain and enrichment data, and updates the finding context.
func (h *FindingsHandler) ResolveDomain(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// Extract finding ID from URL: /api/v1/findings/{id}/resolve-domain
	path := r.URL.Path
	path = path[len("/api/v1/findings/"):]
	path = path[:len(path)-len("/resolve-domain")]
	findingID, err := url.PathUnescape(path)
	if err != nil {
		findingID = path
	}
	if findingID == "" {
		BadRequest(w, "finding ID required")
		return
	}

	finding, err := h.store.GetByID(orgID, findingID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			NotFound(w, "finding not found")
			return
		}
		Internal(w)
		return
	}

	// Extract IP from finding context
	dstIP, _ := finding.Context["dst_ip"].(string)
	if dstIP == "" {
		BadRequest(w, "finding has no destination IP")
		return
	}

	var domains []string
	source := ""

	// Strategy 1: Query Neo4j for DNS events from the same host near the finding time
	if h.neo4jClient != nil {
		graphDomains := h.lookupDNSFromGraph(r.Context(), finding.HostID, finding.CreatedAt)
		if len(graphDomains) > 0 {
			domains = graphDomains
			source = "graph_dns"
		}
	}

	// Strategy 2: Enrichment service (reverse DNS + ASN)
	// Use GetNetInfoFresh to bypass stale empty cache entries and use longer timeout.
	info := enrichment.GlobalEnricher.GetNetInfoFresh(r.Context(), dstIP)
	log.Printf("DEBUG resolve-domain: ip=%s domain=%q asn=%q asnName=%q bgp=%q", dstIP, info.Domain, info.ASN, info.ASNName, info.BGPPrefix)

	// If graph didn't find anything, use reverse DNS (if not generic PTR)
	if len(domains) == 0 && info.Domain != "" && !isGenericPTR(info.Domain) {
		domains = []string{info.Domain}
		source = "reverse_dns"
	}

	// Strategy 3: Infer domain from ASN name for well-known providers
	if len(domains) == 0 && info.ASNName != "" {
		if inferred := inferDomainFromASN(info.ASNName); inferred != "" {
			domains = []string{inferred}
			source = "asn_inferred"
		}
	}

	// Update finding context with resolved domain if found
	if len(domains) > 0 && finding.Context != nil {
		existing, _ := finding.Context["domain"].(string)
		if existing == "" || isGenericPTR(existing) {
			finding.Context["domain"] = domains[0]
			if source == "graph_dns" {
				finding.Context["dns_domain"] = domains[0]
			}
			// Persist the updated context
			if err := h.store.UpdateContext(orgID, findingID, finding.Context); err != nil {
				log.Printf("WARN: failed to update finding context with domain: %v", err)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"finding_id":  findingID,
		"ip":          dstIP,
		"domains":     domains,
		"source":      source,
		"asn_name":    info.ASNName,
		"asn":         info.ASN,
		"bgp_prefix":  info.BGPPrefix,
		"reverse_dns": info.Domain,
	})
}

// ReconcileFindings re-checks all pending findings against current baselines and
// safe domains, auto-resolving any that should no longer be pending. This catches
// findings created before a baseline/safe-domain was added.
// POST /api/v1/findings/reconcile
func (h *FindingsHandler) ReconcileFindings(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	var totalResolved int64

	// 1. Re-check safe domains: resolve pending findings for all safe domains
	if h.safeDomainStore != nil {
		domains := h.safeDomainStore.GetCachedDomains()
		for _, d := range domains {
			count, orgIDs, err := h.store.AutoResolveBySafeDomainForOrg(orgID, d)
			if err != nil {
				log.Printf("WARN: reconcile safe domain %s: %v", d, err)
				continue
			}
			totalResolved += count
			if h.incidentStore != nil {
				for _, oid := range orgIDs {
					_, _ = h.incidentStore.ReconcileStaleIncidents(r.Context(), oid)
				}
			}
		}
	}

	// 2. Re-check baselines: fetch all pending findings and test against current baselines.
	// Collect matching IDs first, then batch-update in a single query to avoid N roundtrips.
	if h.baselineCollector != nil {
		findings, err := h.store.ListAll(orgID, "pending", time.Time{}, 2000, true)
		if err == nil {
			var matchedIDs []string
			for _, row := range findings {
				f := detection.Finding{
					ID:          row.ID,
					DetectionID: row.DetectionID,
					HostID:      row.HostID,
					Severity:    row.Severity,
					Confidence:  row.Confidence,
					Context:     row.Context,
				}
				if matched, _ := h.baselineCollector.MatchesBaseline(orgID, f); matched {
					matchedIDs = append(matchedIDs, row.ID)
				}
			}
			if len(matchedIDs) > 0 {
				n, err := h.store.BatchUpdateStatus(matchedIDs, "auto_resolved", "baseline reconciliation", "system")
				if err == nil {
					totalResolved += n
					for _, id := range matchedIDs {
						h.maybeResolveParentIncident(r.Context(), orgID, id, "auto_resolved", "system")
					}
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"reconciled": totalResolved,
	})
}

// lookupDNSFromGraph queries Neo4j for net_dns events from the same host
// within ±60s of the reference time, returning unique domain names.
func (h *FindingsHandler) lookupDNSFromGraph(ctx context.Context, hostID string, refTime time.Time) []string {
	if h.neo4jClient == nil {
		return nil
	}

	since := refTime.Add(-60 * time.Second)
	until := refTime.Add(60 * time.Second)

	query := `
		MATCH (e:Event)
		WHERE e.host_id = $host_id
		  AND e.type = 'net_dns'
		  AND e.timestamp >= datetime($since)
		  AND e.timestamp <= datetime($until)
		  AND e.target_domain IS NOT NULL
		RETURN DISTINCT e.target_domain as domain
		ORDER BY domain
		LIMIT 50
	`
	params := map[string]any{
		"host_id": hostID,
		"since":   since.Format(time.RFC3339Nano),
		"until":   until.Format(time.RFC3339Nano),
	}

	result, err := h.neo4jClient.ExecuteRead(ctx, query, params)
	if err != nil {
		log.Printf("WARN: DNS graph lookup failed: %v", err)
		return nil
	}

	var domains []string
	for _, record := range result.Records {
		if len(record.Values) > 0 {
			if domain, ok := record.Values[0].(string); ok && domain != "" {
				domains = append(domains, domain)
			}
		}
	}
	return domains
}

// isGenericPTR identifies reverse DNS names that are auto-generated and unhelpful.
func isGenericPTR(domain string) bool {
	genericSuffixes := []string{
		".bc.googleusercontent.com",
		".compute-1.amazonaws.com",
		".compute.amazonaws.com",
		".amazonaws.com",
		".cloudfront.net",
		".1e100.net",
		".akamaitechnologies.com",
		".deploy.static.akamaitechnologies.com",
	}
	for _, suffix := range genericSuffixes {
		if len(domain) > len(suffix) && domain[len(domain)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}

// inferDomainFromASN maps well-known ASN org names to their primary domain.
// Used as a last resort when reverse DNS and graph lookups both fail.
func inferDomainFromASN(asnName string) string {
	lower := strings.ToLower(asnName)
	asnDomainMap := map[string]string{
		"cloudflare":   "cloudflare.com",
		"amazon":       "amazonaws.com",
		"google":       "google.com",
		"microsoft":    "microsoft.com",
		"akamai":       "akamai.com",
		"fastly":       "fastly.com",
		"digitalocean": "digitalocean.com",
		"linode":       "linode.com",
		"vultr":        "vultr.com",
		"hetzner":      "hetzner.com",
		"ovh":          "ovh.com",
		"anthropic":    "anthropic.com",
		"openai":       "openai.com",
	}
	for keyword, domain := range asnDomainMap {
		if strings.Contains(lower, keyword) {
			return domain
		}
	}
	return ""
}

// SuppressedSummary handles GET /api/v1/findings/suppressed-summary
func (h *FindingsHandler) SuppressedSummary(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	since := time.Now().Add(-24 * time.Hour)
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	groups, err := h.store.SuppressedSummary(orgID, since)
	if err != nil {
		log.Printf("suppressed summary error: %v", err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(groups)
}

// parseBaselineExpiry computes the expiration time from either a duration string
// ("7d", "30d", "90d") or an ISO 8601 datetime string. Returns nil for permanent.
func parseBaselineExpiry(expiresIn string, expiresAtStr *string) *time.Time {
	if expiresIn != "" {
		days := 0
		for _, ch := range expiresIn {
			if ch >= '0' && ch <= '9' {
				days = days*10 + int(ch-'0')
			}
		}
		if days > 0 {
			t := time.Now().Add(time.Duration(days) * 24 * time.Hour)
			return &t
		}
	}
	if expiresAtStr != nil && *expiresAtStr != "" {
		if t, err := time.Parse(time.RFC3339, *expiresAtStr); err == nil {
			return &t
		}
	}
	return nil
}

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/detection/ai_pack"
	"github.com/correlic/correlic-backend/internal/incident"
	"github.com/correlic/correlic-backend/internal/storage"
)

// BaselinesHandler handles HTTP requests for behavioral baselines.
type BaselinesHandler struct {
	db                 *sql.DB
	baselineCollector  *detection.BaselineCollector
	safeDomainStore    *storage.SafeDomainStore
	findingStore       *storage.FindingStore
	incidentStore      *incident.IncidentStore
	neverBaselineStore *storage.NeverBaselineStore
}

// NewBaselinesHandler creates a new baselines handler.
func NewBaselinesHandler(db *sql.DB, baselineCollector *detection.BaselineCollector, safeDomainStore *storage.SafeDomainStore, findingStore *storage.FindingStore, incidentStore *incident.IncidentStore, neverBaselineStore *storage.NeverBaselineStore) *BaselinesHandler {
	return &BaselinesHandler{db: db, baselineCollector: baselineCollector, safeDomainStore: safeDomainStore, findingStore: findingStore, incidentStore: incidentStore, neverBaselineStore: neverBaselineStore}
}

// BaselineRow represents a behavioral baseline entry returned by the API.
type BaselineRow struct {
	ID             int        `json:"id"`
	HostID         string     `json:"host_id"`
	AIType         string     `json:"ai_type"`
	SignalType     string     `json:"signal_type"`
	Pattern        string     `json:"pattern"`
	Source         string     `json:"source"`
	HitCount       int        `json:"hit_count"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	SuspendedUntil *time.Time `json:"suspended_until,omitempty"`
}

// ListBaselines handles GET /api/v1/baselines?host_id=X&signal_type=Y&limit=N
func (h *BaselinesHandler) ListBaselines(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	if r.Method != http.MethodGet {
		MethodNotAllowed(w, http.MethodGet)
		return
	}

	hostID := r.URL.Query().Get("host_id")
	signalType := r.URL.Query().Get("signal_type")
	aiType := r.URL.Query().Get("ai_type")

	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	offset := 0
	if s := r.URL.Query().Get("offset"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			offset = n
		}
	}

	query := `SELECT id, host_id, ai_type, signal_type, pattern, source, hit_count, first_seen, last_seen, expires_at, suspended_until
		FROM behavioral_baselines WHERE org_id = $1`
	args := []any{orgID}
	argN := 2

	if hostID != "" {
		query += " AND host_id = $" + strconv.Itoa(argN)
		args = append(args, hostID)
		argN++
	}
	if signalType != "" {
		query += " AND signal_type = $" + strconv.Itoa(argN)
		args = append(args, signalType)
		argN++
	}
	if aiType != "" {
		query += " AND ai_type = $" + strconv.Itoa(argN)
		args = append(args, aiType)
		argN++
	}

	query += " ORDER BY hit_count DESC, last_seen DESC LIMIT $" + strconv.Itoa(argN)
	args = append(args, limit+1) // fetch one extra to detect has_more
	argN++
	query += " OFFSET $" + strconv.Itoa(argN)
	args = append(args, offset)

	rows, err := h.db.Query(query, args...)
	if err != nil {
		log.Printf("baselines list error: %v", err)
		Internal(w)
		return
	}
	defer rows.Close()

	var baselines []BaselineRow
	for rows.Next() {
		var b BaselineRow
		if err := rows.Scan(&b.ID, &b.HostID, &b.AIType, &b.SignalType, &b.Pattern, &b.Source, &b.HitCount, &b.FirstSeen, &b.LastSeen, &b.ExpiresAt, &b.SuspendedUntil); err != nil {
			log.Printf("baselines scan error: %v", err)
			continue
		}
		baselines = append(baselines, b)
	}
	if baselines == nil {
		baselines = []BaselineRow{}
	}

	hasMore := len(baselines) > limit
	if hasMore {
		baselines = baselines[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"baselines": baselines,
		"count":     len(baselines),
		"has_more":  hasMore,
	})
}

// CreateBaseline handles POST /api/v1/baselines
// Body: { host_id, signal_type, pattern, ai_type?, expires_in?: "7d"|"30d"|"90d", expires_at?: "2026-06-14T00:00:00Z" }
func (h *BaselinesHandler) CreateBaseline(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	var body struct {
		HostID     string  `json:"host_id"`
		AIType     string  `json:"ai_type"`
		SignalType string  `json:"signal_type"`
		Pattern    string  `json:"pattern"`
		ExpiresIn  string  `json:"expires_in,omitempty"`
		ExpiresAt  *string `json:"expires_at,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid JSON body")
		return
	}
	if body.SignalType == "" || body.Pattern == "" {
		BadRequest(w, "signal_type and pattern are required")
		return
	}
	body.Pattern = filepath.ToSlash(body.Pattern) // normalize Windows backslashes
	if body.HostID == "" {
		body.HostID = "*"
	}

	// Security gate: check both hardcoded system rules and user-defined org rules.
	if detection.IsNeverBaselinePattern(body.SignalType, body.Pattern, h.neverBaselineStore, orgID) {
		isUserDefined := h.neverBaselineStore != nil && h.neverBaselineStore.MatchesAny(orgID, body.SignalType, body.Pattern)
		if isUserDefined {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"error":           "cannot baseline this pattern — it is on your organization's Never-Baseline list; remove it there first",
				"is_user_defined": true,
			})
			return
		}
		BadRequest(w, "cannot baseline this pattern — it is on the never-baseline list (security-critical)")
		return
	}

	expiresAt := parseBaselineExpiry(body.ExpiresIn, body.ExpiresAt)

	ctx := map[string]any{
		"signal_type": body.SignalType,
		"pattern":     body.Pattern,
		"ai_type":     body.AIType,
	}
	if err := h.baselineCollector.LearnFromFinding(orgID, body.HostID, ctx, expiresAt); err != nil {
		log.Printf("baseline create error: %v", err)
		BadRequest(w, err.Error())
		return
	}

	resp := map[string]any{"ok": true}

	// Retroactive suppression runs in the background — it can take 5-30s for
	// large finding tables (LIKE scan + UPDATE lock). We don't block the API
	// response on it. Findings will auto-resolve within seconds.
	if h.findingStore != nil {
		findingStore := h.findingStore
		incidentStore := h.incidentStore
		go func() {
			count, orgIDs, err := findingStore.AutoResolveByBaseline(orgID, body.HostID, body.SignalType, body.Pattern)
			if err != nil {
				log.Printf("WARN: retroactive baseline suppression failed for %s:%s: %v", body.SignalType, body.Pattern, err)
			} else if count > 0 {
				log.Printf("Retroactive baseline suppression: resolved %d finding(s) for %s:%s", count, body.SignalType, body.Pattern)
				if incidentStore != nil {
					for _, oid := range orgIDs {
						if n, err := incidentStore.ReconcileStaleIncidents(context.Background(), oid); err != nil {
							log.Printf("WARN: reconcile after baseline create failed for org %s: %v", oid, err)
						} else if n > 0 {
							log.Printf("Reconciled %d incident(s) after baseline create for org %s", n, oid)
						}
					}
				}
			}
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// BaselineSummary handles GET /api/v1/baselines/summary
// Returns counts grouped by source and signal_type in a single query.
func (h *BaselinesHandler) BaselineSummary(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	if r.Method != http.MethodGet {
		MethodNotAllowed(w, http.MethodGet)
		return
	}

	query := `SELECT
		CASE WHEN source = 'user_confirmed' THEN 'manual' ELSE 'auto' END AS src,
		signal_type,
		COUNT(*) AS cnt
		FROM behavioral_baselines
		WHERE org_id = $1
		GROUP BY src, signal_type
		ORDER BY src, signal_type`

	rows, err := h.db.Query(query, orgID)
	if err != nil {
		log.Printf("baselines summary error: %v", err)
		Internal(w)
		return
	}
	defer rows.Close()

	type bucketCount struct {
		Source     string `json:"source"`
		SignalType string `json:"signal_type"`
		Count      int    `json:"count"`
	}

	var buckets []bucketCount
	autoTotal, manualTotal := 0, 0
	for rows.Next() {
		var b bucketCount
		if err := rows.Scan(&b.Source, &b.SignalType, &b.Count); err != nil {
			log.Printf("baselines summary scan error: %v", err)
			continue
		}
		buckets = append(buckets, b)
		if b.Source == "auto" {
			autoTotal += b.Count
		} else {
			manualTotal += b.Count
		}
	}
	if buckets == nil {
		buckets = []bucketCount{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"buckets":      buckets,
		"auto_total":   autoTotal,
		"manual_total": manualTotal,
		"total":        autoTotal + manualTotal,
	})
}

// DeleteBaseline handles DELETE /api/v1/baselines/{id}
func (h *BaselinesHandler) DeleteBaseline(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// Extract ID from URL path: /api/v1/baselines/42
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	rawID := parts[len(parts)-1]
	id, err := strconv.Atoi(rawID)
	if err != nil || id <= 0 {
		BadRequest(w, "invalid baseline id")
		return
	}

	if err := h.baselineCollector.DeleteBaseline(r.Context(), orgID, id); err != nil {
		log.Printf("baseline delete error: %v", err)
		NotFound(w, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SuspendBaseline handles PATCH /api/v1/baselines/{id}
// Body: { "expires_in": "7d" | "30d" | "90d" }
func (h *BaselinesHandler) SuspendBaseline(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	rawID := parts[len(parts)-1]
	id, err := strconv.Atoi(rawID)
	if err != nil || id <= 0 {
		BadRequest(w, "invalid baseline id")
		return
	}

	var body struct {
		ExpiresIn string `json:"expires_in"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid request body")
		return
	}

	var duration time.Duration
	switch body.ExpiresIn {
	case "7d":
		duration = 7 * 24 * time.Hour
	case "30d":
		duration = 30 * 24 * time.Hour
	case "90d":
		duration = 90 * 24 * time.Hour
	default:
		BadRequest(w, "expires_in must be one of: 7d, 30d, 90d")
		return
	}

	expiresAt := time.Now().Add(duration)
	if err := h.baselineCollector.SuspendBaseline(r.Context(), orgID, id, expiresAt); err != nil {
		log.Printf("baseline suspend error: %v", err)
		NotFound(w, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":              id,
		"suspended_until": expiresAt.Format(time.RFC3339),
	})
}

// ConfirmBaseline handles POST /api/v1/baselines/{id}/confirm
// Promotes a baseline to user_confirmed (permanent, no expiry).
func (h *BaselinesHandler) ConfirmBaseline(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/confirm"), "/")
	rawID := parts[len(parts)-1]
	id, err := strconv.Atoi(rawID)
	if err != nil || id <= 0 {
		BadRequest(w, "invalid baseline id")
		return
	}

	// Read baseline details before confirming so we can retroactively suppress findings.
	var hostID, signalType, baselinePattern string
	_ = h.db.QueryRow(
		`SELECT host_id, signal_type, pattern FROM behavioral_baselines WHERE id = $1 AND org_id = $2`,
		id, orgID).Scan(&hostID, &signalType, &baselinePattern)

	if err := h.baselineCollector.ConfirmBaseline(r.Context(), orgID, id); err != nil {
		log.Printf("baseline confirm error: %v", err)
		NotFound(w, err.Error())
		return
	}

	// Retroactive suppression: resolve pending findings matching this confirmed baseline.
	var retroCount int64
	if h.findingStore != nil && signalType != "" && baselinePattern != "" {
		count, orgIDs, err := h.findingStore.AutoResolveByBaseline(orgID, hostID, signalType, baselinePattern)
		if err != nil {
			log.Printf("WARN: retroactive suppression after baseline confirm failed: %v", err)
		} else if count > 0 {
			retroCount = count
			log.Printf("Retroactive baseline suppression (confirm): resolved %d finding(s) for %s:%s", count, signalType, baselinePattern)
			if h.incidentStore != nil {
				for _, oid := range orgIDs {
					if n, err := h.incidentStore.ReconcileStaleIncidents(r.Context(), oid); err != nil {
						log.Printf("WARN: reconcile after baseline confirm failed for org %s: %v", oid, err)
					} else if n > 0 {
						log.Printf("Reconciled %d incident(s) after baseline confirm for org %s", n, oid)
					}
				}
			}
		}
	}

	resp := map[string]any{
		"id":     id,
		"source": "user_confirmed",
	}
	if retroCount > 0 {
		resp["retroactive_resolved"] = retroCount
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListExclusions handles GET /api/v1/baselines/exclusions
func (h *BaselinesHandler) ListExclusions(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	if r.Method != http.MethodGet {
		MethodNotAllowed(w, http.MethodGet)
		return
	}

	entries, err := h.baselineCollector.ListExclusions(r.Context(), orgID)
	if err != nil {
		log.Printf("exclusions list error: %v", err)
		Internal(w)
		return
	}
	if entries == nil {
		entries = []detection.ExclusionEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"exclusions": entries,
		"count":      len(entries),
	})
}

// DeleteExclusion handles DELETE /api/v1/baselines/exclusions/{id}
func (h *BaselinesHandler) DeleteExclusion(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	rawID := parts[len(parts)-1]
	id, err := strconv.Atoi(rawID)
	if err != nil || id <= 0 {
		BadRequest(w, "invalid exclusion id")
		return
	}

	if err := h.baselineCollector.DeleteExclusion(r.Context(), orgID, id); err != nil {
		log.Printf("exclusion delete error: %v", err)
		NotFound(w, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SafeDomainRow represents a safe domain allowlist entry returned by the API.
type SafeDomainRow struct {
	ID          string    `json:"id"`
	Domain      string    `json:"domain"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// ListSafeDomains handles GET /api/v1/baselines/safe-domains
func (h *BaselinesHandler) ListSafeDomains(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	if r.Method != http.MethodGet {
		MethodNotAllowed(w, http.MethodGet)
		return
	}

	rows, err := h.db.Query("SELECT id, domain, description, created_at FROM safe_domains_list ORDER BY domain ASC")
	if err != nil {
		log.Printf("safe domains list error: %v", err)
		Internal(w)
		return
	}
	defer rows.Close()

	var domains []SafeDomainRow
	for rows.Next() {
		var d SafeDomainRow
		// use sql.NullString for description in case it's null
		var desc sql.NullString
		if err := rows.Scan(&d.ID, &d.Domain, &desc, &d.CreatedAt); err != nil {
			log.Printf("safe domains scan error: %v", err)
			continue
		}
		if desc.Valid {
			d.Description = desc.String
		}
		domains = append(domains, d)
	}
	if domains == nil {
		domains = []SafeDomainRow{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"domains": domains,
		"count":   len(domains),
	})
}

// AddSafeDomain handles POST /api/v1/baselines/safe-domains
func (h *BaselinesHandler) AddSafeDomain(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	var body struct {
		Domain      string `json:"domain"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid JSON body")
		return
	}
	if strings.TrimSpace(body.Domain) == "" {
		BadRequest(w, "domain is required")
		return
	}

	d, err := h.safeDomainStore.Add(r.Context(), body.Domain, body.Description)
	if err != nil {
		log.Printf("safe domain add error: %v", err)
		Internal(w)
		return
	}

	// Retroactive suppression: auto-resolve any pending findings that reference
	// this domain. This closes the gap where a finding was created before the
	// domain was added to the safe list.
	var retroCount int64
	if h.findingStore != nil {
		count, orgIDs, err := h.findingStore.AutoResolveBySafeDomain(d.Domain)
		if err != nil {
			log.Printf("WARN: retroactive safe domain suppression failed for %s: %v", d.Domain, err)
		} else if count > 0 {
			retroCount = count
			log.Printf("Retroactive safe domain suppression: resolved %d finding(s) for domain %s", count, d.Domain)
			// Cascade: reconcile incidents whose findings are now all resolved
			if h.incidentStore != nil {
				for _, orgID := range orgIDs {
					if n, err := h.incidentStore.ReconcileStaleIncidents(r.Context(), orgID); err != nil {
						log.Printf("WARN: reconcile after safe domain add failed for org %s: %v", orgID, err)
					} else if n > 0 {
						log.Printf("Reconciled %d incident(s) after safe domain add for org %s", n, orgID)
					}
				}
			}
		}
	}

	resp := map[string]any{
		"id":          d.ID,
		"domain":      d.Domain,
		"description": d.Description,
		"created_at":  d.CreatedAt,
	}
	if retroCount > 0 {
		resp["retroactive_resolved"] = retroCount
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// DeleteSafeDomain handles DELETE /api/v1/baselines/safe-domains/{id}
func (h *BaselinesHandler) DeleteSafeDomain(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	id := parts[len(parts)-1]
	if id == "" || id == "safe-domains" {
		BadRequest(w, "missing domain id")
		return
	}

	if err := h.safeDomainStore.Delete(r.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			NotFound(w, "safe domain not found")
		} else {
			log.Printf("safe domain delete error: %v", err)
			Internal(w)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// NoiseFilters returns the current noise filter configuration.
// These are binaries that are automatically suppressed from findings because
// they provide no security signal (Windows system processes, build tools, etc.).
func (h *BaselinesHandler) NoiseFilters(w http.ResponseWriter, r *http.Request) {
	keysOf := func(m map[string]bool) []string {
		seen := make(map[string]bool)
		var out []string
		for k := range m {
			// Deduplicate: only include names without .exe suffix
			name := strings.TrimSuffix(k, ".exe")
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
		return out
	}

	resp := map[string]any{
		"system_noise": keysOf(ai_pack.SystemStartupNoise),
		"build_noise":  keysOf(ai_pack.BuildToolNoise),
		"always_noise": keysOf(ai_pack.AlwaysNoise),
		"bare_noise":   keysOf(ai_pack.BareNoise),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

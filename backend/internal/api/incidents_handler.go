package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/incident"
	"github.com/correlic/correlic-backend/internal/storage"
)

// IncidentsHandler handles HTTP requests for incidents.
type IncidentsHandler struct {
	assembler            *incident.ContextAssembler
	store                *incident.IncidentStore
	findingStore         *storage.FindingStore
	baselineCollector    *detection.BaselineCollector
	summaryInvalidator   incident.SummaryInvalidator // optional, nil-safe
}

// NewIncidentsHandler creates a new incidents handler.
func NewIncidentsHandler(assembler *incident.ContextAssembler, store *incident.IncidentStore, findingStore *storage.FindingStore, baselineCollector *detection.BaselineCollector, summaryInvalidator incident.SummaryInvalidator) *IncidentsHandler {
	return &IncidentsHandler{assembler: assembler, store: store, findingStore: findingStore, baselineCollector: baselineCollector, summaryInvalidator: summaryInvalidator}
}

// ListIncidents handles GET /api/v1/incidents?status=X&severity=Y&host_id=Z&since=T&limit=N&offset=M
func (h *IncidentsHandler) ListIncidents(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	opts := incident.ListOptions{
		Status:   r.URL.Query().Get("status"),
		Severity: r.URL.Query().Get("severity"),
		HostID:   r.URL.Query().Get("host_id"),
		Category: r.URL.Query().Get("category"),
		Limit:    1000,
	}

	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			opts.Since = t
		}
	}
	if opts.Since.IsZero() {
		opts.Since = time.Now().Add(-7 * 24 * time.Hour) // default: last 7 days
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		n := 0
		for _, c := range limitStr {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		if n > 0 && n <= 5000 {
			opts.Limit = n
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		n := 0
		for _, c := range offsetStr {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		opts.Offset = n
	}

	// Reconcile stale incidents: auto-resolve any open incident whose findings
	// are all resolved. Handles bulk operations and retroactive cleanup.
	if n, err := h.store.ReconcileStaleIncidents(r.Context(), orgID); err != nil {
		log.Printf("WARN: reconcile stale incidents failed: %v", err)
	} else if n > 0 {
		log.Printf("Reconciled %d stale incident(s) for org %s", n, orgID)
	}

	incidents, err := h.store.List(r.Context(), orgID, opts)
	if err != nil {
		log.Printf("ERROR: list incidents failed: %v", err)
		Internal(w)
		return
	}
	if incidents == nil {
		incidents = []incident.Incident{}
	}

	counts, err := h.store.CountByStatus(r.Context(), orgID, opts.Since)
	if err != nil {
		log.Printf("WARN: count by status failed: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"incidents": incidents,
		"count":     len(incidents),
		"counts":    counts,
	})
}

// GetIncident handles GET /api/v1/incidents/{id}
func (h *IncidentsHandler) GetIncident(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// Extract incident ID from URL: /api/v1/incidents/{id}
	incidentID := extractIncidentID(r.URL.Path)
	if incidentID == "" {
		BadRequest(w, "incident ID required")
		return
	}

	detail, err := h.assembler.Assemble(r.Context(), orgID, incidentID)
	if err != nil {
		if errors.Is(err, incident.ErrIncidentNotFound) {
			NotFound(w, "incident not found")
			return
		}
		log.Printf("ERROR: assemble incident %s failed: %v", incidentID, err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"incident": detail,
	})
}

// UpdateIncidentStatus handles PATCH /api/v1/incidents/{id}
// Body: {"status": "investigating|resolved|dismissed|open", "resolution": "reason text"}
// When status is "resolved" or "dismissed", cascades to all constituent findings.
func (h *IncidentsHandler) UpdateIncidentStatus(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	incidentID := extractIncidentID(r.URL.Path)
	if incidentID == "" {
		BadRequest(w, "incident ID required")
		return
	}

	var body struct {
		Status     string `json:"status"`
		Resolution string `json:"resolution"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid request body")
		return
	}

	validStatuses := map[string]bool{
		"open":          true,
		"investigating": true,
		"resolved":      true,
		"dismissed":     true,
	}
	if !validStatuses[body.Status] {
		BadRequest(w, "status must be: open, investigating, resolved, or dismissed")
		return
	}

	resolvedBy := "system"
	if _, actorID, ok := middleware.ActorFromContext(r.Context()); ok && actorID != "" {
		resolvedBy = actorID
	}

	if err := h.store.UpdateStatus(r.Context(), orgID, incidentID, body.Status, body.Resolution, resolvedBy); err != nil {
		if errors.Is(err, incident.ErrIncidentNotFound) {
			NotFound(w, "incident not found")
			return
		}
		log.Printf("ERROR: update incident status failed: %v", err)
		Internal(w)
		return
	}
	log.Printf("incident status change: id=%s org=%s status=%s actor=%s", incidentID, orgID, body.Status, resolvedBy)

	// Invalidate cached AI summary (incident state changed).
	if h.summaryInvalidator != nil {
		h.summaryInvalidator.InvalidateSummary(incidentID)
	}

	// Cascade: when resolving or dismissing, auto-update all constituent findings.
	if body.Status == "resolved" || body.Status == "dismissed" {
		findingIDs, err := h.store.GetFindingIDs(r.Context(), orgID, incidentID)
		if err != nil {
			log.Printf("WARN: failed to get finding IDs for cascade: %v", err)
		} else {
			findingStatus := "dismissed"
			if body.Status == "resolved" {
				findingStatus = "allowed"
			}
			for _, fid := range findingIDs {
				if err := h.findingStore.UpdateStatus(orgID, fid, findingStatus, body.Resolution, resolvedBy); err != nil {
					if !errors.Is(err, storage.ErrNotFound) {
						log.Printf("WARN: cascade finding status update failed for %s: %v", fid, err)
					}
					continue
				}
				// Trigger baseline learning when findings are allowed (resolved incident).
				if findingStatus == "allowed" && h.baselineCollector != nil {
					finding, err := h.findingStore.GetByID(orgID, fid)
					if err == nil && finding != nil {
						if err := h.baselineCollector.LearnFromFinding(orgID, finding.HostID, finding.Context, nil); err != nil {
							log.Printf("WARN: baseline rejected for finding %s: %v", fid, err)
						}
					}
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ok":     true,
		"id":     incidentID,
		"status": body.Status,
	})
}

// GetIncidentTimeline handles GET /api/v1/incidents/{id}/timeline
func (h *IncidentsHandler) GetIncidentTimeline(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// Extract incident ID: /api/v1/incidents/{id}/timeline
	path := r.URL.Path
	path = strings.TrimSuffix(path, "/timeline")
	incidentID := extractIncidentID(path)
	if incidentID == "" {
		BadRequest(w, "incident ID required")
		return
	}

	timeline, err := h.assembler.AssembleTimeline(r.Context(), orgID, incidentID)
	if err != nil {
		if errors.Is(err, incident.ErrIncidentNotFound) {
			NotFound(w, "incident not found")
			return
		}
		log.Printf("ERROR: assemble incident timeline failed: %v", err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"timeline": timeline,
	})
}

// extractIncidentID extracts the incident ID from a URL path like /api/v1/incidents/{id}
func extractIncidentID(path string) string {
	const prefix = "/api/v1/incidents/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	id := path[len(prefix):]
	// Remove trailing slash if any.
	id = strings.TrimSuffix(id, "/")
	return id
}

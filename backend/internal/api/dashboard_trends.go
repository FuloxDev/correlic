package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/correlic/correlic-backend/internal/api/middleware"
)

// TrendPoint is a single time-bucketed data point for dashboard charts.
type TrendPoint struct {
	Timestamp          time.Time      `json:"timestamp"`
	Events             int            `json:"events"`
	Findings           int            `json:"findings"`
	Incidents          int            `json:"incidents"`
	AgentFindings      map[string]int `json:"agent_findings,omitempty"`
	FindingSeverities  map[string]int `json:"finding_severities,omitempty"`
	FindingRules       map[string]int `json:"finding_rules,omitempty"`
	IncidentSeverities map[string]int `json:"incident_severities,omitempty"`
}

// TrendsResponse is returned by GET /dashboard/trends.
type TrendsResponse struct {
	Points        []TrendPoint `json:"points"`
	BucketMinutes int          `json:"bucket_minutes"`
}

// DashboardTrendsHandler returns time-series data for dashboard sparklines and charts.
type DashboardTrendsHandler struct {
	db *sql.DB
}

func NewDashboardTrendsHandler(db *sql.DB) *DashboardTrendsHandler {
	return &DashboardTrendsHandler{db: db}
}

func (h *DashboardTrendsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}
	if r.Method != http.MethodGet {
		MethodNotAllowed(w, http.MethodGet)
		return
	}

	points := 12
	if v := r.URL.Query().Get("points"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p <= 60 {
			points = p
		}
	}

	bucketMinutes := 5
	if v := r.URL.Query().Get("interval"); v != "" {
		if b, err := strconv.Atoi(v); err == nil && b > 0 && b <= 1440 {
			bucketMinutes = b
		}
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	windowStart := now.Add(-time.Duration(points*bucketMinutes) * time.Minute)

	result := TrendsResponse{
		Points:        make([]TrendPoint, points),
		BucketMinutes: bucketMinutes,
	}

	// Initialize buckets with timestamps.
	for i := 0; i < points; i++ {
		result.Points[i].Timestamp = windowStart.Add(time.Duration(i*bucketMinutes) * time.Minute)
	}

	// Run the two consolidated queries in parallel.
	var wg sync.WaitGroup

	// Query A: basic counts (events + findings + incidents per bucket) — replaces 3 queries
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.fillBasicCounts(orgID, windowStart, now, bucketMinutes, result.Points)
	}()

	// Query B: finding details (agent + severity + rule per bucket) — replaces 3 queries
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.fillFindingDetails(orgID, windowStart, now, bucketMinutes, result.Points)
	}()

	// Query C: incident severities per bucket — kept separate (different table)
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.fillIncidentSeverities(orgID, windowStart, now, bucketMinutes, result.Points)
	}()

	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// fillBasicCounts replaces fillEventCounts + fillFindingCounts + fillIncidentCounts (3 queries → 1).
func (h *DashboardTrendsHandler) fillBasicCounts(orgID string, start, end time.Time, bucketMin int, points []TrendPoint) {
	intervalStr := strconv.Itoa(bucketMin)
	rows, err := h.db.Query(`
		WITH buckets AS (
			SELECT generate_series($1::timestamptz, $2::timestamptz, ($3 || ' minutes')::interval) AS bucket_start
		)
		SELECT 'event' AS source, b.bucket_start, COUNT(e.id) AS cnt
		FROM buckets b
		LEFT JOIN telemetry_events e
			ON e.org_id = $4::uuid
			AND e.event_ts >= b.bucket_start
			AND e.event_ts < b.bucket_start + ($3 || ' minutes')::interval
		GROUP BY b.bucket_start

		UNION ALL

		SELECT 'finding' AS source, b.bucket_start, COUNT(f.id) AS cnt
		FROM buckets b
		LEFT JOIN findings f
			ON (f.org_id = $5 OR f.org_id IS NULL OR f.org_id = '')
			AND f.created_at >= b.bucket_start
			AND f.created_at < b.bucket_start + ($3 || ' minutes')::interval
		GROUP BY b.bucket_start

		UNION ALL

		SELECT 'incident' AS source, b.bucket_start, COUNT(i.id) AS cnt
		FROM buckets b
		LEFT JOIN incidents i
			ON i.org_id = $6
			AND i.created_at >= b.bucket_start
			AND i.created_at < b.bucket_start + ($3 || ' minutes')::interval
		GROUP BY b.bucket_start

		ORDER BY source, bucket_start
	`, start, end, intervalStr, orgID, orgID, orgID)
	if err != nil {
		log.Printf("dashboard trends: basic counts error: %v", err)
		return
	}
	defer rows.Close()

	bucketDur := time.Duration(bucketMin) * time.Minute
	for rows.Next() {
		var source string
		var ts time.Time
		var cnt int
		if err := rows.Scan(&source, &ts, &cnt); err != nil {
			continue
		}
		idx := int(ts.Sub(start) / bucketDur)
		if idx < 0 || idx >= len(points) {
			continue
		}
		switch source {
		case "event":
			points[idx].Events = cnt
		case "finding":
			points[idx].Findings = cnt
		case "incident":
			points[idx].Incidents = cnt
		}
	}
}

// fillFindingDetails replaces fillAgentFindings + fillFindingSeverities + fillFindingRules (3 queries → 1).
func (h *DashboardTrendsHandler) fillFindingDetails(orgID string, start, end time.Time, bucketMin int, points []TrendPoint) {
	intervalStr := strconv.Itoa(bucketMin)
	rows, err := h.db.Query(`
		WITH buckets AS (
			SELECT generate_series($1::timestamptz, $2::timestamptz, ($3 || ' minutes')::interval) AS bucket_start
		)
		SELECT b.bucket_start,
			COALESCE(f.context->>'ai_type', 'unknown') AS agent,
			f.severity,
			f.detection_id,
			COUNT(f.id) AS cnt
		FROM buckets b
		INNER JOIN findings f
			ON (f.org_id = $4 OR f.org_id IS NULL OR f.org_id = '')
			AND f.created_at >= b.bucket_start
			AND f.created_at < b.bucket_start + ($3 || ' minutes')::interval
		GROUP BY b.bucket_start, agent, f.severity, f.detection_id
		ORDER BY b.bucket_start
	`, start, end, intervalStr, orgID)
	if err != nil {
		log.Printf("dashboard trends: finding details error: %v", err)
		return
	}
	defer rows.Close()

	bucketDur := time.Duration(bucketMin) * time.Minute
	for rows.Next() {
		var ts time.Time
		var agent, severity, detectionID string
		var cnt int
		if err := rows.Scan(&ts, &agent, &severity, &detectionID, &cnt); err != nil {
			continue
		}
		idx := int(ts.Sub(start) / bucketDur)
		if idx < 0 || idx >= len(points) {
			continue
		}

		// Populate AgentFindings
		if points[idx].AgentFindings == nil {
			points[idx].AgentFindings = make(map[string]int)
		}
		points[idx].AgentFindings[agent] += cnt

		// Populate FindingSeverities
		if points[idx].FindingSeverities == nil {
			points[idx].FindingSeverities = make(map[string]int)
		}
		points[idx].FindingSeverities[severity] += cnt

		// Populate FindingRules
		if points[idx].FindingRules == nil {
			points[idx].FindingRules = make(map[string]int)
		}
		points[idx].FindingRules[detectionID] += cnt
	}
}

// fillIncidentSeverities populates incident severity breakdown per bucket.
func (h *DashboardTrendsHandler) fillIncidentSeverities(orgID string, start, end time.Time, bucketMin int, points []TrendPoint) {
	intervalStr := strconv.Itoa(bucketMin)
	rows, err := h.db.Query(`
		WITH buckets AS (
			SELECT generate_series($1::timestamptz, $2::timestamptz, ($3 || ' minutes')::interval) AS bucket_start
		)
		SELECT b.bucket_start, i.severity, COUNT(i.id) AS cnt
		FROM buckets b
		INNER JOIN incidents i
			ON i.org_id = $4
			AND i.created_at >= b.bucket_start
			AND i.created_at < b.bucket_start + ($3 || ' minutes')::interval
		GROUP BY b.bucket_start, i.severity
		ORDER BY b.bucket_start, i.severity
	`, start, end, intervalStr, orgID)
	if err != nil {
		log.Printf("dashboard trends: incident severities error: %v", err)
		return
	}
	defer rows.Close()

	bucketDur := time.Duration(bucketMin) * time.Minute
	for rows.Next() {
		var ts time.Time
		var sev string
		var cnt int
		if err := rows.Scan(&ts, &sev, &cnt); err != nil {
			continue
		}
		idx := int(ts.Sub(start) / bucketDur)
		if idx < 0 || idx >= len(points) {
			continue
		}
		if points[idx].IncidentSeverities == nil {
			points[idx].IncidentSeverities = make(map[string]int)
		}
		points[idx].IncidentSeverities[sev] = cnt
	}
}

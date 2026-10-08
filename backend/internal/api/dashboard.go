package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/correlic/correlic-backend/internal/ai/attribution"
	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/incident"
	"github.com/correlic/correlic-backend/internal/query"
	"github.com/correlic/correlic-backend/internal/storage"
)

// AIStats contains AI agent-specific metrics
type AIStats struct {
	TotalAgents     int `json:"total_agents"`
	TotalEvents     int `json:"total_events"`
	ActiveAlerts    int `json:"active_alerts"`
	Connections     int `json:"connections"`
	SecretsAccessed int `json:"secrets_accessed"`
	PortsAccessed   int `json:"ports_accessed"`
}

// DetectionStats contains detection engine and baseline metrics.
type DetectionStats struct {
	TotalFindings         int     `json:"total_findings"`
	PendingFindings       int     `json:"pending_findings"`
	AllowedFindings       int     `json:"allowed_findings"`
	DismissedFindings     int     `json:"dismissed_findings"`
	AutoResolvedFindings  int     `json:"auto_resolved_findings"`
	InvestigatingFindings int     `json:"investigating_findings"`
	SuppressedFindings    int     `json:"suppressed_findings"`
	TotalBaselines        int     `json:"total_baselines"`
	AutoBaselines         int     `json:"auto_baselines"`
	ManualBaselines       int     `json:"manual_baselines"`
	SuppressionRate       float64 `json:"suppression_rate"`
}

// IncidentSummaryStats contains incident metrics for the dashboard.
type IncidentSummaryStats struct {
	Total         int `json:"total"`
	Open          int `json:"open"`
	Investigating int `json:"investigating"`
	Resolved      int `json:"resolved"`
	Dismissed     int `json:"dismissed"`
	AutoResolved  int `json:"auto_resolved"`
	CriticalOpen  int `json:"critical_open"`
}

// EventBreakdown contains event counts by type.
type EventBreakdown struct {
	ProcessExec int `json:"process_exec"`
	FileOpen    int `json:"file_open"`
	NetConnect  int `json:"net_connect"`
	NetDNS      int `json:"net_dns"`
	ProcessExit int `json:"process_exit"`
}

// DashboardStats represents aggregate stats for the UI dashboard
type DashboardStats struct {
	// System-wide metrics
	TotalEvents       int `json:"total_events"`
	TotalAlerts       int `json:"total_alerts"`
	CriticalAlerts    int `json:"critical_alerts"`
	HighRiskAlerts    int `json:"high_risk_alerts"`
	OpenPorts         int `json:"open_ports"`
	ActiveConnections int `json:"active_connections"`
	SecretsAccessed   int `json:"secrets_accessed"`

	// AI-specific metrics (nested for clarity)
	AI AIStats `json:"ai"`

	// Detection engine metrics
	Detection DetectionStats `json:"detection"`

	// Incident metrics
	Incidents IncidentSummaryStats `json:"incidents"`

	// Event type breakdown (time-windowed)
	Events EventBreakdown `json:"events"`
}

// DashboardHandler provides aggregate stats for the UI
type DashboardHandler struct {
	telemetryStore     storage.TelemetryStore
	agentStore         storage.AgentStore
	attributionService *attribution.Service
	timelineService    *query.TimelineService
	findingStore       *storage.FindingStore
	incidentStore      *incident.IncidentStore
	db                 *sql.DB
}

func NewDashboardHandler(
	telemetryStore storage.TelemetryStore,
	agentStore storage.AgentStore,
	attributionService *attribution.Service,
	timelineService *query.TimelineService,
	findingStore *storage.FindingStore,
	incidentStore *incident.IncidentStore,
	db *sql.DB,
) *DashboardHandler {
	return &DashboardHandler{
		telemetryStore:     telemetryStore,
		agentStore:         agentStore,
		attributionService: attributionService,
		timelineService:    timelineService,
		findingStore:       findingStore,
		incidentStore:      incidentStore,
		db:                 db,
	}
}

func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	if r.Method != http.MethodGet {
		MethodNotAllowed(w, http.MethodGet)
		return
	}

	// Parse interval parameter (minutes)
	intervalMinutes := 60 // default 1 hour
	if intervalStr := r.URL.Query().Get("interval"); intervalStr != "" {
		if parsed, err := strconv.Atoi(intervalStr); err == nil && parsed > 0 {
			intervalMinutes = parsed
		}
	}
	since := time.Now().Add(-time.Duration(intervalMinutes) * time.Minute)
	ctx := r.Context()

	stats := DashboardStats{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// ===== Group 1: Telemetry counts (single GROUP BY replaces 9 CountFiltered calls) =====
	wg.Add(1)
	go func() {
		defer wg.Done()
		if h.telemetryStore == nil {
			return
		}
		counts, total, err := h.telemetryStore.CountByEventType(orgID, since)
		if err != nil {
			log.Printf("dashboard: count by event type error: %v", err)
			return
		}
		mu.Lock()
		stats.TotalEvents = total
		stats.OpenPorts = counts["net_bind"]
		stats.ActiveConnections = counts["net_connect"]
		stats.SecretsAccessed = counts["file_open"]
		stats.Events.ProcessExec = counts["process_exec"]
		stats.Events.FileOpen = counts["file_open"]
		stats.Events.NetConnect = counts["net_connect"]
		stats.Events.NetDNS = counts["net_dns"]
		stats.Events.ProcessExit = counts["process_exit"]
		mu.Unlock()
	}()

	// ===== Group 2: AI attribution metrics =====
	var aiAgentCount int
	var aiEventCount int
	wg.Add(1)
	go func() {
		defer wg.Done()
		if h.attributionService == nil {
			return
		}
		count, err := h.attributionService.CountDistinctAgentsSince(orgID, since)
		if err == nil {
			mu.Lock()
			aiAgentCount = count
			mu.Unlock()
		}
		sessions, err := h.attributionService.ListActiveSessions(orgID, 100)
		if err == nil {
			total := 0
			for _, s := range sessions {
				if s.LastSeenAt.After(since) {
					total += s.EventCount
				}
			}
			mu.Lock()
			aiEventCount = total
			mu.Unlock()
		}
	}()

	// ===== Group 3: AI alerts + Neo4j stats =====
	var aiAlerts int
	var aiNeo4jConnections, aiNeo4jFiles, aiNeo4jPorts int
	wg.Add(1)
	go func() {
		defer wg.Done()
		if h.db != nil {
			_ = h.db.QueryRow(`
				SELECT COUNT(*) FROM findings
				WHERE (org_id = $1 OR org_id IS NULL OR org_id = '')
				AND detection_id LIKE 'ai.%'
				AND status = 'pending'
				AND created_at >= $2
			`, orgID, since).Scan(&aiAlerts)
		}
		if h.timelineService != nil {
			aiStats, err := h.timelineService.GetAIStats(ctx, orgID, since)
			if err == nil && aiStats != nil {
				aiNeo4jConnections = aiStats.Connections
				aiNeo4jFiles = aiStats.FilesAccessed
				aiNeo4jPorts = aiStats.PortsOpened
			}
		}
	}()

	// ===== Group 4: Detection metrics (findings + baselines) =====
	wg.Add(1)
	go func() {
		defer wg.Done()
		if h.findingStore != nil {
			// Use zero time: status counts must include ALL findings regardless of age
			// (a "pending" finding from 8 hours ago is still pending and must be shown)
			counts, err := h.findingStore.CountByStatus(orgID, time.Time{})
			if err == nil {
				mu.Lock()
				stats.Detection.TotalFindings = counts.Total
				stats.Detection.PendingFindings = counts.Pending
				stats.Detection.AllowedFindings = counts.Allowed
				stats.Detection.DismissedFindings = counts.Dismissed
				stats.Detection.AutoResolvedFindings = counts.AutoResolved
				stats.Detection.InvestigatingFindings = counts.Investigating
				stats.Detection.SuppressedFindings = counts.Suppressed
				if counts.Total > 0 {
					stats.Detection.SuppressionRate = float64(counts.Suppressed) / float64(counts.Total) * 100
				}
				mu.Unlock()
			}
		}
		if h.db != nil {
			var autoCount, manualCount int
			err := h.db.QueryRow(`
				SELECT
					COALESCE(SUM(CASE WHEN source = 'user_confirmed' THEN 1 ELSE 0 END), 0),
					COALESCE(SUM(CASE WHEN source != 'user_confirmed' OR source IS NULL THEN 1 ELSE 0 END), 0)
				FROM behavioral_baselines WHERE org_id = $1
			`, orgID).Scan(&manualCount, &autoCount)
			if err == nil {
				mu.Lock()
				stats.Detection.ManualBaselines = manualCount
				stats.Detection.AutoBaselines = autoCount
				stats.Detection.TotalBaselines = manualCount + autoCount
				mu.Unlock()
			} else {
				log.Printf("dashboard: baseline count error: %v", err)
			}
		}
	}()

	// ===== Group 5: Incident metrics =====
	wg.Add(1)
	go func() {
		defer wg.Done()
		if h.incidentStore == nil {
			return
		}
		// Use zero time: status counts must include ALL incidents regardless of age
		counts, err := h.incidentStore.CountByStatus(ctx, orgID, time.Time{})
		if err == nil {
			mu.Lock()
			stats.Incidents.Total = counts.Total
			stats.Incidents.Open = counts.Open
			stats.Incidents.Investigating = counts.Investigating
			stats.Incidents.Resolved = counts.Resolved
			stats.Incidents.Dismissed = counts.Dismissed
			stats.Incidents.AutoResolved = counts.AutoResolved
			mu.Unlock()
		}
		criticalIncs, err := h.incidentStore.List(ctx, orgID, incident.ListOptions{
			Status:   "open",
			Severity: "critical",
			Limit:    100,
		})
		if err == nil {
			mu.Lock()
			stats.Incidents.CriticalOpen = len(criticalIncs)
			mu.Unlock()
		}
	}()

	wg.Wait()

	// ===== Apply AI metrics with fallbacks (must run after all goroutines complete) =====
	stats.AI.TotalAgents = aiAgentCount
	stats.AI.TotalEvents = aiEventCount
	stats.AI.ActiveAlerts = aiAlerts

	// Fallback: if attribution service returned no agents, count from agents table
	if stats.AI.TotalAgents == 0 && h.agentStore != nil {
		agents, err := h.agentStore.ListAgents(orgID, nil)
		if err == nil {
			activeCount := 0
			for _, a := range agents {
				if a.State == "running" {
					activeCount++
				}
			}
			stats.AI.TotalAgents = activeCount
		}
	}

	// Fallback: if no AI events from sessions, use total telemetry events
	if stats.AI.TotalEvents == 0 {
		stats.AI.TotalEvents = stats.TotalEvents
	}

	// Apply Neo4j AI stats with telemetry fallbacks
	stats.AI.Connections = aiNeo4jConnections
	stats.AI.SecretsAccessed = aiNeo4jFiles
	stats.AI.PortsAccessed = aiNeo4jPorts
	if stats.AI.Connections == 0 {
		stats.AI.Connections = stats.ActiveConnections
	}
	if stats.AI.SecretsAccessed == 0 {
		stats.AI.SecretsAccessed = stats.SecretsAccessed
	}
	if stats.AI.PortsAccessed == 0 {
		stats.AI.PortsAccessed = stats.OpenPorts
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

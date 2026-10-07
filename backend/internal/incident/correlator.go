package incident

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/storage"
)

// SummaryInvalidator is called when an incident is created or updated,
// so cached AI summaries are marked stale.
type SummaryInvalidator interface {
	InvalidateSummary(incidentID string)
}

// DossierInvalidator is called when new findings are merged into an existing incident,
// so the pre-rendered dossier text is cleared and rebuilt on next access.
type DossierInvalidator interface {
	InvalidateDossier(incidentID string)
}

// IncidentCorrelator groups findings into incidents.
// It runs synchronously in the ingestion pipeline, after chain correlation.
// NotificationEmitter is called when an incident is created or escalated,
// so external notifications can be dispatched.
type NotificationEmitter interface {
	OnIncidentCreated(orgID string, inc Incident)
	OnIncidentEscalated(orgID string, inc Incident, oldSeverity string)
}

// Nil-safe: pass nil to disable incident correlation.
type IncidentCorrelator struct {
	store               *IncidentStore
	findingStore        *storage.FindingStore
	mergeWindow         time.Duration
	summaryInvalidator  SummaryInvalidator  // optional
	dossierInvalidator  DossierInvalidator  // optional
	notifEmitter        NotificationEmitter // optional
}

// SetSummaryInvalidator sets the summary invalidator.
// Called during wiring to avoid circular imports.
func (c *IncidentCorrelator) SetSummaryInvalidator(inv SummaryInvalidator) {
	if c == nil {
		return
	}
	c.summaryInvalidator = inv
}

// SetDossierInvalidator sets the dossier invalidator.
// Called during wiring to avoid circular imports.
func (c *IncidentCorrelator) SetDossierInvalidator(inv DossierInvalidator) {
	if c == nil {
		return
	}
	c.dossierInvalidator = inv
}

// SetNotificationEmitter sets the notification emitter.
// Called during wiring to avoid circular imports.
func (c *IncidentCorrelator) SetNotificationEmitter(em NotificationEmitter) {
	if c == nil {
		return
	}
	c.notifEmitter = em
}

// NewIncidentCorrelator creates a new incident correlator.
func NewIncidentCorrelator(store *IncidentStore, findingStore *storage.FindingStore) *IncidentCorrelator {
	return &IncidentCorrelator{
		store:        store,
		findingStore: findingStore,
		mergeWindow:  30 * time.Minute,
	}
}

// Ingest processes a finding (individual or chain) and creates/updates incidents.
// Returns the incident ID the finding was assigned to.
func (c *IncidentCorrelator) Ingest(ctx context.Context, orgID string, f detection.Finding) (string, error) {
	if c == nil {
		return "", nil
	}

	if strings.HasPrefix(f.DetectionID, "chain.") {
		return c.ingestChain(ctx, orgID, f)
	}
	return c.ingestStandalone(ctx, orgID, f)
}

// ingestChain creates a new incident from a chain finding and its constituent step findings.
func (c *IncidentCorrelator) ingestChain(ctx context.Context, orgID string, f detection.Finding) (string, error) {
	// Extract constituent finding IDs from chain context.
	var stepIDs []string
	if steps, ok := f.Context["chain_steps"]; ok {
		switch v := steps.(type) {
		case []string:
			stepIDs = v
		case []any:
			for _, s := range v {
				if str, ok := s.(string); ok {
					stepIDs = append(stepIDs, str)
				}
			}
		}
	}

	// All finding IDs: step findings + the chain finding itself.
	allFindingIDs := make([]string, 0, len(stepIDs)+1)
	allFindingIDs = append(allFindingIDs, stepIDs...)
	allFindingIDs = append(allFindingIDs, f.ID)

	// Collect MITRE techniques from chain context.
	mitre := extractMITRE(f)

	// Build context summary from all findings.
	summary := buildContextSummaryFromFinding(f)
	summary["finding_count"] = len(allFindingIDs)

	// Determine time bounds — chain finding timestamp is the end, first step is start.
	startedAt := f.Timestamp
	if windowSecs, ok := f.Context["chain_window_secs"]; ok {
		if ws, ok := windowSecs.(float64); ok && ws > 0 {
			startedAt = f.Timestamp.Add(-time.Duration(ws) * time.Second)
		} else if ws, ok := windowSecs.(int); ok && ws > 0 {
			startedAt = f.Timestamp.Add(-time.Duration(ws) * time.Second)
		}
	}

	incID := generateIncidentID(f.HostID, f.ID, startedAt)
	now := time.Now()

	category := CategoryForDetection(f.DetectionID)

	inc := Incident{
		ID:              incID,
		OrgID:           orgID,
		HostID:          f.HostID,
		Category:        category,
		Severity:        f.Severity,
		Confidence:      f.Confidence,
		Title:           f.Title,
		Summary:         f.Summary,
		MITRETechniques: mitre,
		FindingIDs:      allFindingIDs,
		ChainFindingID:  f.ID,
		StartedAt:       startedAt,
		EndedAt:         f.Timestamp,
		ContextSummary:  summary,
		Status:          "open",
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := c.store.Upsert(ctx, inc); err != nil {
		return "", fmt.Errorf("upsert chain incident: %w", err)
	}

	// Invalidate cached AI summary (incident data changed).
	if c.summaryInvalidator != nil {
		c.summaryInvalidator.InvalidateSummary(incID)
	}

	// Notify: chain incidents are always open (high priority).
	if c.notifEmitter != nil {
		c.notifEmitter.OnIncidentCreated(orgID, inc)
	}

	// Link all findings to this incident.
	for _, fid := range allFindingIDs {
		if err := c.findingStore.SetIncidentID(orgID, fid, incID); err != nil {
			log.Printf("WARN: failed to link finding %s to incident %s: %v", fid, incID, err)
		}
	}

	return incID, nil
}

// ingestStandalone creates a new seed incident or merges into an existing one.
func (c *IncidentCorrelator) ingestStandalone(ctx context.Context, orgID string, f detection.Finding) (string, error) {
	sessionID := extractSessionID(f)
	aiType := extractAIType(f)
	category := CategoryForDetection(f.DetectionID)

	// Informational detections (command_activity, file_activity) are audit-trail
	// findings that should attach to ANY open incident on the same host/session,
	// regardless of category. They never define an incident's category.
	if InformationalDetections[f.DetectionID] {
		existing, err := c.store.FindMergeCandidateAnyCategory(ctx, orgID, f.HostID, sessionID, aiType, c.mergeWindow)
		if err != nil {
			log.Printf("WARN: find merge candidate (any category) failed: %v", err)
		}
		if existing != nil {
			return c.mergeInto(ctx, orgID, existing, f)
		}
		// No incident to attach to — drop silently (informational findings
		// never create seed incidents on their own).
		return "", nil
	}

	// Try to find a merge candidate (scoped to same AI agent type + attack category).
	existing, err := c.store.FindMergeCandidate(ctx, orgID, f.HostID, sessionID, aiType, category, c.mergeWindow)
	if err != nil {
		log.Printf("WARN: find merge candidate failed: %v", err)
		// Fall through to create new incident.
	}

	if existing != nil {
		return c.mergeInto(ctx, orgID, existing, f)
	}

	return c.createSeed(ctx, orgID, f, sessionID, category)
}

// mergeInto adds a finding to an existing incident.
func (c *IncidentCorrelator) mergeInto(ctx context.Context, orgID string, existing *Incident, f detection.Finding) (string, error) {
	// Deduplicate: don't add the same finding twice.
	for _, id := range existing.FindingIDs {
		if id == f.ID {
			return existing.ID, nil
		}
	}
	existing.FindingIDs = append(existing.FindingIDs, f.ID)
	existing.EndedAt = f.Timestamp
	existing.UpdatedAt = time.Now()

	// Capture old severity before recalculation for title/escalation logic.
	oldSeverity := existing.Severity

	// Update summary (subtitle) only when severity strictly escalates, so it
	// shows what specifically triggered the escalation. Title is a stable
	// category-level description and never replaced by a finding-specific string.
	if SeverityRank[f.Severity] > SeverityRank[oldSeverity] {
		existing.Summary = f.Title
	}

	// Recalculate severity after title check so comparison uses pre-update value.
	severity, confidence := recalculateSeverity(existing, f)
	existing.Severity = severity
	existing.Confidence = confidence

	// Update MITRE techniques (union).
	newMITRE := extractMITRE(f)
	existing.MITRETechniques = unionStrings(existing.MITRETechniques, newMITRE)

	// Refresh context summary.
	if existing.ContextSummary == nil {
		existing.ContextSummary = map[string]any{}
	}
	existing.ContextSummary["finding_count"] = len(existing.FindingIDs)

	// If incident was auto_resolved and new finding is non-low, reopen.
	if existing.Status == "auto_resolved" && SeverityRank[f.Severity] > SeverityRank["low"] {
		existing.Status = "open"
	}

	if err := c.store.Update(ctx, existing); err != nil {
		return "", fmt.Errorf("update incident for merge: %w", err)
	}

	// Invalidate cached AI summary (incident data changed).
	if c.summaryInvalidator != nil {
		c.summaryInvalidator.InvalidateSummary(existing.ID)
	}

	// Invalidate pre-rendered dossier (new finding added — context is stale).
	if c.dossierInvalidator != nil {
		go c.dossierInvalidator.InvalidateDossier(existing.ID)
	}

	// Notify on severity escalation.
	if c.notifEmitter != nil && SeverityRank[existing.Severity] > SeverityRank[oldSeverity] {
		c.notifEmitter.OnIncidentEscalated(orgID, *existing, oldSeverity)
	}

	if err := c.findingStore.SetIncidentID(orgID, f.ID, existing.ID); err != nil {
		log.Printf("WARN: failed to link finding %s to incident %s: %v", f.ID, existing.ID, err)
	}

	return existing.ID, nil
}

// createSeed creates a new single-finding incident.
func (c *IncidentCorrelator) createSeed(ctx context.Context, orgID string, f detection.Finding, sessionID, category string) (string, error) {
	mitre := extractMITRE(f)
	summary := buildContextSummaryFromFinding(f)
	summary["finding_count"] = 1
	if sessionID != "" {
		summary["session_ids"] = []string{sessionID}
	}

	incID := generateIncidentID(f.HostID, f.ID, f.Timestamp)
	now := time.Now()

	status := "open"
	if SeverityRank[f.Severity] <= SeverityRank["low"] {
		status = "auto_resolved"
	}

	inc := Incident{
		ID:              incID,
		OrgID:           orgID,
		HostID:          f.HostID,
		Category:        category,
		Severity:        f.Severity,
		Confidence:      f.Confidence,
		Title:           categoryTitle(category, extractAIType(f)),
		Summary:         f.Title,
		MITRETechniques: mitre,
		FindingIDs:      []string{f.ID},
		StartedAt:       f.Timestamp,
		EndedAt:         f.Timestamp,
		ContextSummary:  summary,
		Status:          status,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := c.store.Upsert(ctx, inc); err != nil {
		return "", fmt.Errorf("upsert seed incident: %w", err)
	}

	// Invalidate cached AI summary (Upsert may replace existing incident).
	if c.summaryInvalidator != nil {
		c.summaryInvalidator.InvalidateSummary(incID)
	}

	// Notify for non-auto_resolved incidents.
	if c.notifEmitter != nil && status != "auto_resolved" {
		c.notifEmitter.OnIncidentCreated(orgID, inc)
	}

	if err := c.findingStore.SetIncidentID(orgID, f.ID, incID); err != nil {
		log.Printf("WARN: failed to link finding %s to incident %s: %v", f.ID, incID, err)
	}

	return incID, nil
}

// recalculateSeverity computes the aggregate severity and confidence for an incident
// after a new finding is added.
func recalculateSeverity(inc *Incident, newFinding detection.Finding) (string, float64) {
	maxRank := SeverityRank[inc.Severity]
	newRank := SeverityRank[newFinding.Severity]
	if newRank > maxRank {
		maxRank = newRank
	}

	// Chain amplification: if incident has a chain finding, promote by one level.
	if inc.ChainFindingID != "" && maxRank < 4 {
		maxRank++
	}

	// Weighted average confidence: new finding blended in.
	// Simple approach: running average weighted by finding count.
	n := float64(len(inc.FindingIDs))
	confidence := (inc.Confidence*(n-1) + newFinding.Confidence) / n

	return SeverityFromRank(maxRank), confidence
}

// generateIncidentID creates a deterministic incident ID.
func generateIncidentID(hostID, seedFindingID string, ts time.Time) string {
	h := sha256.Sum256([]byte(hostID + ":" + seedFindingID))
	return fmt.Sprintf("inc:%x:%d", h[:8], ts.Unix())
}

// extractAIType gets ai_type from a finding's context.
func extractAIType(f detection.Finding) string {
	if f.Context == nil {
		return ""
	}
	if v, ok := f.Context["ai_type"]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// extractSessionID gets session_id from a finding's context.
func extractSessionID(f detection.Finding) string {
	if f.Context == nil {
		return ""
	}
	if v, ok := f.Context["session_id"]; ok {
		if s, ok := v.(string); ok && s != "" && s != "0" {
			return s
		}
	}
	return ""
}

// extractMITRE gets MITRE techniques from a finding's context.
func extractMITRE(f detection.Finding) []string {
	if f.Context == nil {
		return nil
	}
	v, ok := f.Context["mitre_techniques"]
	if !ok {
		return nil
	}
	switch mt := v.(type) {
	case []string:
		return mt
	case []any:
		var result []string
		for _, s := range mt {
			if str, ok := s.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

// buildContextSummaryFromFinding creates a context summary from a single finding.
func buildContextSummaryFromFinding(f detection.Finding) map[string]any {
	summary := map[string]any{
		"detection_ids": []string{f.DetectionID},
	}
	if f.Context != nil {
		if at, ok := f.Context["ai_type"]; ok {
			if s, ok := at.(string); ok && s != "" {
				summary["ai_types"] = []string{s}
			}
		}
		if pid, ok := f.Context["pid"]; ok {
			summary["pid_count"] = 1
			summary["pids"] = []any{pid}
		}
		if sid, ok := f.Context["session_id"]; ok {
			if s, ok := sid.(string); ok && s != "" && s != "0" {
				summary["session_ids"] = []string{s}
			}
		}
	}
	return summary
}

// unionStrings returns the union of two string slices (deduped).
func unionStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		seen[s] = true
	}
	result := make([]string, 0, len(seen))
	for s := range seen {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}

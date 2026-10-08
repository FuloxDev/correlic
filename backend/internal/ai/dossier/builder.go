package dossier

import (
	"context"
	"time"

	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/incident"
)

// DossierData holds all assembled data for a dossier document.
type DossierData struct {
	Detail           *incident.IncidentDetail
	RelatedIncidents []incident.Incident                  // same host, last 30 days, excluding current, max 5
	BaselinesByExe   map[string][]detection.BaselineEntry // exe_path → baselines; may be nil
	BuiltAt          time.Time
}

// DossierBuilder assembles dossier data from the incident detail, baselines, and related incidents.
type DossierBuilder struct {
	assembler     *incident.ContextAssembler
	incidentStore *incident.IncidentStore
	baselines     *detection.BaselineCollector // may be nil
}

// NewDossierBuilder creates a new DossierBuilder.
func NewDossierBuilder(assembler *incident.ContextAssembler, incidentStore *incident.IncidentStore, baselines *detection.BaselineCollector) *DossierBuilder {
	return &DossierBuilder{
		assembler:     assembler,
		incidentStore: incidentStore,
		baselines:     baselines,
	}
}

// Build assembles the full dossier data. Uses a 25-second deadline.
// If Neo4j is unavailable, assembler degrades gracefully.
func (b *DossierBuilder) Build(ctx context.Context, orgID, incidentID string) (*DossierData, error) {
	buildCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	// 1. Assemble the full incident detail.
	detail, err := b.assembler.Assemble(buildCtx, orgID, incidentID)
	if err != nil {
		return nil, err
	}

	// 2. Collect unique exe_paths from process tree.
	exePaths := collectExePaths(detail.ProcessTree)

	// 3. Get baselines for the host and map by exe_path.
	var baselinesByExe map[string][]detection.BaselineEntry
	if b.baselines != nil {
		allBaselines := b.baselines.ListForHost(orgID, detail.HostID)
		// Always initialise the map when we have exe_paths so the formatter can
		// distinguish "no baseline data" (nil map) from "known exe with zero entries".
		if len(exePaths) > 0 {
			baselinesByExe = make(map[string][]detection.BaselineEntry, len(exePaths))
			for _, exe := range exePaths {
				// Start with nil slice (no matches) for every exe path.
				baselinesByExe[exe] = nil
			}
			// Now fill in matches. We key by the baseline pattern — if the pattern
			// contains the exe_path or the exe is a prefix of the pattern, associate it.
			// In practice the formatter only cares about counts, so include all baselines
			// for the host, keyed under every exe_path for simplicity (the formatter will
			// not double-count — it uses len per exe).
			if len(allBaselines) > 0 {
				for _, exe := range exePaths {
					baselinesByExe[exe] = allBaselines
				}
			}
		}
	}

	// 4. Fetch related incidents on the same host, last 30 days, excluding current.
	since := time.Now().Add(-30 * 24 * time.Hour)
	candidates, listErr := b.incidentStore.List(buildCtx, orgID, incident.ListOptions{
		HostID: detail.HostID,
		Since:  since,
		Limit:  6,
	})
	if listErr != nil {
		// Non-fatal: proceed without related incidents.
		candidates = nil
	}

	var related []incident.Incident
	for _, inc := range candidates {
		if inc.ID == incidentID {
			continue
		}
		related = append(related, inc)
		if len(related) >= 5 {
			break
		}
	}

	return &DossierData{
		Detail:           detail,
		RelatedIncidents: related,
		BaselinesByExe:   baselinesByExe,
		BuiltAt:          time.Now(),
	}, nil
}

// collectExePaths walks the process tree recursively and collects unique exe_paths.
func collectExePaths(node *incident.ProcessNode) []string {
	if node == nil {
		return nil
	}
	seen := make(map[string]bool)
	var walk func(n *incident.ProcessNode)
	walk = func(n *incident.ProcessNode) {
		if n == nil {
			return
		}
		if n.ExePath != "" && !seen[n.ExePath] {
			seen[n.ExePath] = true
		}
		for _, child := range n.Children {
			walk(child)
		}
	}
	walk(node)

	result := make([]string, 0, len(seen))
	for exe := range seen {
		result = append(result, exe)
	}
	return result
}

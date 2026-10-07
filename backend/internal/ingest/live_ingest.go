package ingest

import (
	"context"
	"encoding/json"
	"log"

	"github.com/correlic/correlic-backend/internal/ai/attribution"
	"github.com/correlic/correlic-backend/internal/correlation"
	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/incident"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/storage"
	"github.com/correlic/correlic-backend/internal/storage/eventstore"
)

const requiredSchemaVersion = 1

// FindingNotifier is called when a finding is stored, for in-app notification.
// Nil-safe: pass nil to disable.
type FindingNotifier interface {
	OnFindingStored(orgID string, f detection.Finding)
}

// IngestCanonicalEvents validates events, inserts into telemetry_events (raw), then into events (canonical).
// Uses ON CONFLICT DO NOTHING for events. Returns accepted and rejected counts.
// If eventBuffer is provided, events are pushed to the buffer for streaming correlation.
// If sampler is provided, events are sampled before ingestion.
// If attributionSvc is provided, events are attributed to AI agents.
// If processTreeWriter is provided (Tier 1), process_exec events are immediately written to Neo4j.
// If cooldown is provided, repeat findings for the same detection+host are rate-limited.
// If chainCorrelator is provided, correlated multi-step attack chains are detected and stored.
// If exceptionChecker is provided, findings matching a per-rule exception are suppressed.
// If ruleSettings is provided, per-org rule thresholds are passed to detection rules via EvalContext.
// If incidentCorrelator is provided, findings are grouped into incidents.
// If neverBaselineChecker is provided, findings matching user-defined never-baseline rules
// are promoted to at least medium severity so they always generate an open incident.
// cooldown, chainCorrelator, exceptionChecker, ruleSettings, incidentCorrelator, and
// neverBaselineChecker are all optional — pass nil to disable.
func IngestCanonicalEvents(
	ctx context.Context,
	telemetryStore storage.TelemetryStore,
	canonicalStore eventstore.EventStore,
	eventBuffer *correlation.EventBuffer,
	sampler *Sampler,
	attributionSvc *attribution.Service,
	processTreeWriter *correlation.ProcessTreeWriter,
	detectionEngine *detection.Engine,
	baselineCollector *detection.BaselineCollector,
	findingStore *storage.FindingStore,
	graphQuerier detection.GraphQuerier,
	safeDomainChecker detection.SafeDomainChecker,
	cooldown *detection.FindingCooldown,
	chainCorrelator *detection.ChainCorrelator,
	exceptionChecker detection.ExceptionChecker,
	ruleSettings detection.RuleSettingsReader,
	incidentCorrelator *incident.IncidentCorrelator,
	findingNotifier FindingNotifier,
	neverBaselineChecker detection.NeverBaselineChecker,
	orgID string,
	events []event.Event,
) (accepted, rejected, sampled int, err error) {
	for i := range events {
		evt := &events[i]
		if evt.SchemaVersion != requiredSchemaVersion || evt.ID == "" || evt.HostID == "" {
			rejected++
			continue
		}

		// Drop events with PID 0 — these come from eBPF hooks firing in kernel/interrupt
		// context where bpf_get_current_pid_tgid() returns 0. They have no meaningful
		// process context and pollute the process tree with junk root nodes.
		if evt.Process != nil && evt.Process.PID == 0 {
			rejected++
			continue
		}

		// Apply sampling (if enabled)
		if sampler != nil && !sampler.ShouldKeep(evt) {
			sampled++
			continue
		}

		payload, jerr := json.Marshal(evt)
		if jerr != nil {
			rejected++
			continue
		}
		te := model.TelemetryEvent{
			AgentID:   evt.HostID,
			EventType: evt.Type,
			Timestamp: evt.Timestamp,
			Payload:   payload,
		}
		if err := telemetryStore.InsertEvents(orgID, []model.TelemetryEvent{te}); err != nil {
			log.Printf("ingest: telemetry store insert failed id=%s type=%s host=%s: %v", evt.ID, evt.Type, evt.HostID, err)
			rejected++
			continue
		}
		if err := canonicalStore.AppendIdempotent(ctx, *evt); err != nil {
			log.Printf("ingest: canonical store append failed id=%s type=%s host=%s: %v", evt.ID, evt.Type, evt.HostID, err)
			rejected++
			continue
		}

		// Attribute event to AI agent (if enabled)
		// This tracks process tree correlation for AI agent counting
		if attributionSvc != nil && (evt.Type == "exec" || evt.Type == "process_exec") {
			attributionSvc.AttributeEvent(orgID, evt.HostID, te)
		}

		// Tier 1: Write process tree structure to Neo4j immediately (real-time correlation)
		if processTreeWriter != nil && (evt.Type == "process_exec" || evt.Type == "process_exit") {
			if err := processTreeWriter.IngestProcess(ctx, evt); err != nil {
				// Log but don't fail ingestion — Neo4j is secondary storage
				log.Printf("WARN: Tier 1 process tree write failed: %v", err)
			}
		}

		// Detection: evaluate rules against this event
		var findings []detection.Finding
		var emittedFindings []detection.Finding
		if detectionEngine != nil && graphQuerier != nil {
			evalCtx := &detection.EvalContext{
				Ctx:               ctx,
				Event:             evt,
				HostID:            evt.HostID,
				OrgID:             orgID,
				GraphQuery:        graphQuerier,
				SafeDomainChecker: safeDomainChecker,
				RuleSettings:      ruleSettings,
				Baselines:         baselineCollector,
			}
			findings = detectionEngine.Evaluate(evalCtx)
			if len(findings) > 0 {
				log.Printf("Detection fired: event_id=%s type=%s host=%s rules=%d", evt.ID, evt.Type, evt.HostID, len(findings))
				for _, f := range findings {
					log.Printf("Finding generated: rule=%s severity=%s confidence=%.2f host=%s title=%q", f.DetectionID, f.Severity, f.Confidence, f.HostID, f.Title)
				}
			}
			if findingStore != nil {
				stored := 0
				suppressedCount := 0
				emittedFindings = nil // reset for this event

				for _, f := range findings {
					suppressed := false

					// Suppress findings that match established baselines.
					if baselineCollector != nil {
						if matched, pattern := baselineCollector.MatchesBaseline(orgID, f); matched {
							log.Printf("Detection suppressed (baseline match: %s): %s", pattern, f.Title)
							f.Suppressed = true
							f.BaselineMatch = pattern
							suppressed = true
						}
					}

					// Suppress findings that match a per-rule exception.
					if !suppressed && exceptionChecker != nil && exceptionChecker.Matches(orgID, f) {
						log.Printf("Detection suppressed (rule exception): %s", f.Title)
						f.Suppressed = true
						suppressed = true
					}

					// Rate-limit repeat findings for the same detection+host.
					// Cooldown applies to ALL findings (suppressed and non-suppressed)
					// to keep DB counts balanced. Without this, suppressed findings
					// bypass cooldown and flood the DB while non-suppressed get dropped,
					// causing suppression_rate to skew toward 100%.
					if cooldown != nil && !cooldown.ShouldEmit(f) {
						continue
					}

					row := storage.FindingRow{
						ID:            f.ID,
						OrgID:         orgID,
						DetectionID:   f.DetectionID,
						HostID:        f.HostID,
						Severity:      f.Severity,
						Confidence:    f.Confidence,
						Title:         f.Title,
						Summary:       f.Summary,
						AnchorEvent:   f.AnchorEventID,
						RelatedEvents: f.RelatedEvents,
						Context:       f.Context,
						Status:        f.Status,
						Suppressed:    f.Suppressed,
						CreatedAt:     f.Timestamp,
					}
					if f.BaselineMatch != "" {
						row.BaselineMatch = &f.BaselineMatch
					}
					if err := findingStore.Insert(row); err != nil {
						log.Printf("WARN: finding store insert failed: %v", err)
					} else {
						stored++
						if suppressed {
							suppressedCount++
						}
						// Only emit non-suppressed findings for notifications and chain correlation.
						if !suppressed {
							emittedFindings = append(emittedFindings, f)
							if findingNotifier != nil {
								findingNotifier.OnFindingStored(orgID, f)
							}
						}
					}
				}

				// Attack chain correlation: feed emitted findings into the correlator and
				// store any chain findings that complete. Chain findings bypass cooldown.
				var allChainFindings []detection.Finding
				if chainCorrelator != nil {
					for _, f := range emittedFindings {
						chainFindings := chainCorrelator.Ingest(f)
						for _, cf := range chainFindings {
							chainRow := storage.FindingRow{
								ID:            cf.ID,
								OrgID:         orgID,
								DetectionID:   cf.DetectionID,
								HostID:        cf.HostID,
								Severity:      cf.Severity,
								Confidence:    cf.Confidence,
								Title:         cf.Title,
								Summary:       cf.Summary,
								AnchorEvent:   cf.AnchorEventID,
								RelatedEvents: cf.RelatedEvents,
								Context:       cf.Context,
								Status:        cf.Status,
								Suppressed:    cf.Suppressed,
								CreatedAt:     cf.Timestamp,
							}
							if err := findingStore.Insert(chainRow); err != nil {
								log.Printf("WARN: chain finding store insert failed: %v", err)
							} else {
								stored++
								allChainFindings = append(allChainFindings, cf)
								if findingNotifier != nil {
									findingNotifier.OnFindingStored(orgID, cf)
								}
							}
						}
					}
				}

				// Never-baseline severity floor: findings matching user-defined never-baseline
				// rules must always generate an open incident. Promote to at least "medium"
				// so the incident correlator does not auto-resolve them.
				if neverBaselineChecker != nil {
					for i := range emittedFindings {
						f := &emittedFindings[i]
						sigType, _ := f.Context["signal_type"].(string)
						pat, _ := f.Context["pattern"].(string)
						if sigType != "" && neverBaselineChecker.MatchesAny(orgID, sigType, pat) {
							f.Context["triggered_by_never_baseline"] = true
							if incident.SeverityRank[f.Severity] < incident.SeverityRank["medium"] {
								f.Severity = "medium"
							}
						}
					}
				}

				// Incident correlation: group emitted findings into incidents.
				if incidentCorrelator != nil {
					for _, f := range emittedFindings {
						if _, err := incidentCorrelator.Ingest(ctx, orgID, f); err != nil {
							log.Printf("WARN: incident correlator failed: %v", err)
						}
					}
					for _, cf := range allChainFindings {
						if _, err := incidentCorrelator.Ingest(ctx, orgID, cf); err != nil {
							log.Printf("WARN: incident correlator (chain) failed: %v", err)
						}
					}
				}

				if stored > 0 {
					log.Printf("Detection: %d finding(s) stored for event %s (type=%s, %d suppressed, %d rate-limited)",
						stored, evt.ID, evt.Type, suppressedCount, len(findings)-stored)
				}
			}
		}

		// Behavioral baseline: only observe events with no non-suppressed findings.
		// We use emittedFindings (non-suppressed) instead of raw findings because
		// informational rules (ai.file_activity, ai.command_activity) fire on nearly
		// every AI event. If those findings are already baselined/suppressed, the event
		// is behaviorally "clean" and should still be observed for baseline building.
		if baselineCollector != nil && detection.ShouldBaseline(evt, emittedFindings) {
			// Populate ai_type on event context so baselines are scoped to specific AI agents.
			// Detection rules already call IsAIProcess() per-rule, but the result isn't
			// stored on evt.Context. We do a single lookup here for baseline attribution.
			if graphQuerier != nil && evt.Process != nil && evt.Process.PID > 0 {
				if isAI, aiType, err := graphQuerier.IsAIProcess(ctx, evt.HostID, evt.Process.PID); err == nil && isAI && aiType != "" {
					if evt.Context == nil {
						evt.Context = make(map[string]interface{})
					}
					evt.Context["ai_type"] = aiType
				}
			}
			baselineCollector.Observe(orgID, evt)
		}

		// Tier 2: Push to event buffer for batched activity correlation (non-blocking)
		if eventBuffer != nil {
			if err := eventBuffer.Push(evt); err != nil {
				// Log but don't fail ingestion
				log.Printf("WARN: Tier 2 buffer push failed (buffer full?) id=%s type=%s host=%s: %v",
					evt.ID, evt.Type, evt.HostID, err)
			}
		}

		// Per-event log removed — too noisy. Batch summary is logged below.
		accepted++
	}
	return accepted, rejected, sampled, nil
}

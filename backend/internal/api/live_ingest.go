package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/correlic/correlic-backend/internal/ai/attribution"
	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/correlation"
	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/incident"
	"github.com/correlic/correlic-backend/internal/ingest"
	"github.com/correlic/correlic-backend/internal/storage"
	"github.com/correlic/correlic-backend/internal/storage/eventstore"
)

const maxIngestBodyBytes = 1 << 20 // 1MiB

// LiveIngestResponse is the 202 response body for POST /ingest/events.
type LiveIngestResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
	Sampled  int `json:"sampled"`
}

// LiveIngestHandler handles POST /ingest/events: canonical event(s) → telemetry_events + events.
type LiveIngestHandler struct {
	telemetryStore     storage.TelemetryStore
	eventStore         eventstore.EventStore
	agentCertStore     storage.AgentCertStore // optional: binds mTLS identity to host_id
	eventBuffer        *correlation.EventBuffer
	sampler            *ingest.Sampler
	attributionSvc     *attribution.Service
	processTreeWriter  *correlation.ProcessTreeWriter
	detectionEngine    *detection.Engine
	baselineCollector  *detection.BaselineCollector
	findingStore       *storage.FindingStore
	graphQuerier       detection.GraphQuerier
	attributionCache   *detection.AttributionCache
	safeDomainStore    *storage.SafeDomainStore
	exceptionStore     *storage.RuleExceptionStore
	ruleSettingsStore  *storage.RuleSettingsStore
	cooldown           *detection.FindingCooldown
	chainCorrelator    *detection.ChainCorrelator
	incidentCorrelator *incident.IncidentCorrelator
	findingNotifier    ingest.FindingNotifier
	neverBaselineStore *storage.NeverBaselineStore
}

// NewLiveIngestHandler returns a handler that requires auth (org from context).
// agentCertStore may be nil (no mTLS host binding); graphQuerier may be nil (no Neo4j);
// attributionCache should be shared process-wide so AI attribution survives across batches.
func NewLiveIngestHandler(
	telemetryStore storage.TelemetryStore,
	eventStore eventstore.EventStore,
	agentCertStore storage.AgentCertStore,
	eventBuffer *correlation.EventBuffer,
	sampler *ingest.Sampler,
	attributionSvc *attribution.Service,
	processTreeWriter *correlation.ProcessTreeWriter,
	detectionEngine *detection.Engine,
	baselineCollector *detection.BaselineCollector,
	findingStore *storage.FindingStore,
	graphQuerier detection.GraphQuerier,
	attributionCache *detection.AttributionCache,
	safeDomainStore *storage.SafeDomainStore,
	exceptionStore *storage.RuleExceptionStore,
	ruleSettingsStore *storage.RuleSettingsStore,
	cooldown *detection.FindingCooldown,
	chainCorrelator *detection.ChainCorrelator,
	incidentCorrelator *incident.IncidentCorrelator,
	findingNotifier ingest.FindingNotifier,
	neverBaselineStore *storage.NeverBaselineStore,
) *LiveIngestHandler {
	return &LiveIngestHandler{
		telemetryStore:     telemetryStore,
		eventStore:         eventStore,
		agentCertStore:     agentCertStore,
		eventBuffer:        eventBuffer,
		sampler:            sampler,
		attributionSvc:     attributionSvc,
		processTreeWriter:  processTreeWriter,
		detectionEngine:    detectionEngine,
		baselineCollector:  baselineCollector,
		findingStore:       findingStore,
		graphQuerier:       graphQuerier,
		attributionCache:   attributionCache,
		safeDomainStore:    safeDomainStore,
		exceptionStore:     exceptionStore,
		ruleSettingsStore:  ruleSettingsStore,
		cooldown:           cooldown,
		chainCorrelator:    chainCorrelator,
		incidentCorrelator: incidentCorrelator,
		findingNotifier:    findingNotifier,
		neverBaselineStore: neverBaselineStore,
	}
}

// ServeHTTP accepts JSON body: single event or array of events.
func (h *LiveIngestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		MethodNotAllowed(w, http.MethodPost)
		return
	}

	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxIngestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			log.Printf("ingest/events: body too large org=%s remote=%s", orgID, r.RemoteAddr)
			PayloadTooLarge(w, "")
			return
		}
		BadRequest(w, "invalid body")
		return
	}

	var events []event.Event
	if err := json.Unmarshal(body, &events); err != nil {
		var single event.Event
		if err2 := json.Unmarshal(body, &single); err2 != nil {
			log.Printf("ingest/events decode error: %v", err)
			BadRequest(w, "invalid JSON (expected event or array of events)")
			return
		}
		events = []event.Event{single}
	}

	if len(events) > ingest.MaxEventsPerRequest {
		log.Printf("ingest/events: batch too large org=%s events=%d max=%d", orgID, len(events), ingest.MaxEventsPerRequest)
		PayloadTooLarge(w, "too many events in one request (max 500)")
		return
	}

	// Bind the caller's identity to the host it reports for. With mTLS the cert
	// fingerprint is bound to the first host_id seen (EnsureBound creates the binding)
	// and every later batch must match it; a batch mixing hosts is rejected outright.
	if !h.enforceHostBinding(w, r, orgID, events) {
		return
	}

	// Safe domains are tenant-scoped: built-ins plus this org's own.
	var safeDomains detection.SafeDomainChecker
	if h.safeDomainStore != nil {
		safeDomains = h.safeDomainStore.ForOrg(orgID)
	}
	var exceptions detection.ExceptionChecker
	if h.exceptionStore != nil {
		exceptions = h.exceptionStore
	}
	var ruleSettings detection.RuleSettingsReader
	if h.ruleSettingsStore != nil {
		ruleSettings = h.ruleSettingsStore
	}
	var neverBaselines detection.NeverBaselineChecker
	if h.neverBaselineStore != nil {
		neverBaselines = h.neverBaselineStore
	}

	accepted, rejected, sampled, err := ingest.IngestCanonicalEvents(
		r.Context(), h.telemetryStore, h.eventStore, h.eventBuffer, h.sampler, h.attributionSvc,
		h.processTreeWriter, h.detectionEngine, h.baselineCollector, h.findingStore,
		h.graphQuerier, h.attributionCache, safeDomains, h.cooldown, h.chainCorrelator,
		exceptions, ruleSettings, h.incidentCorrelator, h.findingNotifier, neverBaselines,
		orgID, events)
	if err != nil {
		// Raw storage failed part-way: tell the agent to retry the whole batch.
		log.Printf("ingest/events error org=%s accepted=%d rejected=%d: %v", orgID, accepted, rejected, err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(LiveIngestResponse{Accepted: accepted, Rejected: rejected, Sampled: sampled})
}

// enforceHostBinding requires every event's host_id to match the agent identity bound to
// the caller's mTLS certificate (binding it on first use). It writes the error response
// and returns false when the batch must be rejected.
func (h *LiveIngestHandler) enforceHostBinding(w http.ResponseWriter, r *http.Request, orgID string, events []event.Event) bool {
	hostID := ""
	for i := range events {
		if events[i].HostID == "" {
			continue // rejected later by validation
		}
		if hostID == "" {
			hostID = events[i].HostID
			continue
		}
		if events[i].HostID != hostID {
			log.Printf("ingest/events: mixed host_ids in one batch org=%s (%s vs %s)", orgID, hostID, events[i].HostID)
			BadRequest(w, "ingest batch must contain a single host_id")
			return false
		}
	}
	if hostID == "" || h.agentCertStore == nil {
		return true
	}
	fp, ok := middleware.ClientCertFingerprintFromContext(r.Context())
	if !ok {
		return true // no mTLS identity to bind (API-key-only deployments)
	}
	if err := h.agentCertStore.EnsureBound(orgID, hostID, fp); err != nil {
		if errors.Is(err, storage.ErrAgentCertMismatch) || errors.Is(err, storage.ErrFingerprintAlreadyBound) {
			middleware.AgentCertMismatchTotal.Add(1)
			log.Printf("ingest/events: identity/host mismatch org=%s host=%s fp=%s: %v", orgID, hostID, fp, err)
			Unauthorized(w, "mTLS client cert does not match agent identity for host_id")
			return false
		}
		log.Printf("ingest/events: mTLS bind failed org=%s host=%s: %v", orgID, hostID, err)
		Internal(w)
		return false
	}
	return true
}

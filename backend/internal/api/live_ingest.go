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
}

// LiveIngestHandler handles POST /ingest/events: canonical event(s) → telemetry_events + events.
type LiveIngestHandler struct {
	telemetryStore       storage.TelemetryStore
	eventStore           eventstore.EventStore
	eventBuffer          *correlation.EventBuffer
	sampler              *ingest.Sampler
	attributionSvc       *attribution.Service
	processTreeWriter    *correlation.ProcessTreeWriter
	detectionEngine      *detection.Engine
	baselineCollector    *detection.BaselineCollector
	findingStore         *storage.FindingStore
	graphQuerier         detection.GraphQuerier
	safeDomainStore      *storage.SafeDomainStore
	exceptionStore       *storage.RuleExceptionStore
	ruleSettingsStore    *storage.RuleSettingsStore
	cooldown             *detection.FindingCooldown
	chainCorrelator      *detection.ChainCorrelator
	incidentCorrelator   *incident.IncidentCorrelator
	findingNotifier      ingest.FindingNotifier
	neverBaselineStore   *storage.NeverBaselineStore
}

// NewLiveIngestHandler returns a handler that requires auth (org from context).
func NewLiveIngestHandler(
	telemetryStore storage.TelemetryStore,
	eventStore eventstore.EventStore,
	eventBuffer *correlation.EventBuffer,
	sampler *ingest.Sampler,
	attributionSvc *attribution.Service,
	processTreeWriter *correlation.ProcessTreeWriter,
	detectionEngine *detection.Engine,
	baselineCollector *detection.BaselineCollector,
	findingStore *storage.FindingStore,
	graphQuerier detection.GraphQuerier,
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
		telemetryStore:      telemetryStore,
		eventStore:          eventStore,
		eventBuffer:         eventBuffer,
		sampler:             sampler,
		attributionSvc:      attributionSvc,
		processTreeWriter:   processTreeWriter,
		detectionEngine:     detectionEngine,
		baselineCollector:   baselineCollector,
		findingStore:        findingStore,
		graphQuerier:        graphQuerier,
		safeDomainStore:     safeDomainStore,
		exceptionStore:      exceptionStore,
		ruleSettingsStore:   ruleSettingsStore,
		cooldown:            cooldown,
		chainCorrelator:     chainCorrelator,
		incidentCorrelator:  incidentCorrelator,
		findingNotifier:     findingNotifier,
		neverBaselineStore:  neverBaselineStore,
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

	//log.Printf("ingest/events: org=%s batch=%d", orgID, len(events))
	accepted, rejected, sampled, err := ingest.IngestCanonicalEvents(r.Context(), h.telemetryStore, h.eventStore, h.eventBuffer, h.sampler, h.attributionSvc, h.processTreeWriter, h.detectionEngine, h.baselineCollector, h.findingStore, h.graphQuerier, h.safeDomainStore, h.cooldown, h.chainCorrelator, h.exceptionStore, h.ruleSettingsStore, h.incidentCorrelator, h.findingNotifier, h.neverBaselineStore, orgID, events)
	if err != nil {
		log.Printf("ingest/events error: %v", err)
		Internal(w)
		return
	}

	// Log sampling stats if events were sampled
	if sampled > 0 {
		//log.Printf("Sampled %d events (accepted: %d, rejected: %d)", sampled, accepted, rejected)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(LiveIngestResponse{Accepted: accepted, Rejected: rejected})
}

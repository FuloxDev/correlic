package telemetry

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/correlic/correlic-backend/internal/ai/attribution"
	apierrors "github.com/correlic/correlic-backend/internal/api"
	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/storage"
)

// IngestHandler is the HTTP handler for telemetry ingestion.
// For now, this is a scaffold that preserves the control-plane contracts:
// - org_id is derived server-side (auth middleware)
// - tenant scoping is mandatory (org_id in context)
type IngestHandler struct {
	store          storage.TelemetryStore
	agentCertStore storage.AgentCertStore
	attributionSvc *attribution.Service
}

const maxTelemetryBodyBytes = 5 << 20 // 5MiB

func NewIngestHandler(store storage.TelemetryStore, agentCertStore storage.AgentCertStore, attributionSvc *attribution.Service) *IngestHandler {
	return &IngestHandler{store: store, agentCertStore: agentCertStore, attributionSvc: attributionSvc}
}

func (h *IngestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Debug log removed — too noisy for production
	if r.Method != http.MethodPost {
		IngestRejectedTotal.Add(1)
		apierrors.MethodNotAllowed(w, http.MethodPost)
		return
	}

	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		IngestRejectedTotal.Add(1)
		apierrors.Unauthorized(w, "missing org context")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxTelemetryBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var batch model.TelemetryBatch
	if err := dec.Decode(&batch); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			IngestRejectedTotal.Add(1)
			apierrors.PayloadTooLarge(w, "")
			return
		}
		IngestRejectedTotal.Add(1)
		apierrors.BadRequest(w, "invalid payload")
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		IngestRejectedTotal.Add(1)
		apierrors.BadRequest(w, "invalid payload")
		return
	}

	if len(batch.Events) == 0 {
		IngestRejectedTotal.Add(1)
		apierrors.BadRequest(w, "events required")
		return
	}

	// If mTLS fingerprint is present, enforce a single agent_id per batch and bind it.
	if fp, ok := middleware.ClientCertFingerprintFromContext(r.Context()); ok && h.agentCertStore != nil {
		agentID := ""
		for i := range batch.Events {
			if batch.Events[i].AgentID == "" {
				continue
			}
			if agentID == "" {
				agentID = batch.Events[i].AgentID
				continue
			}
			if batch.Events[i].AgentID != agentID {
				IngestRejectedTotal.Add(1)
				apierrors.BadRequest(w, "telemetry batch must contain a single agent_id when using mTLS")
				return
			}
		}
		if agentID != "" {
			if err := h.agentCertStore.EnsureBound(orgID, agentID, fp); err != nil {
				log.Printf("[DEBUG INGEST BOUND] orgID='%s' agentID='%s' fp='%s' err='%v'", orgID, agentID, fp, err)
				if errors.Is(err, storage.ErrAgentCertMismatch) || errors.Is(err, storage.ErrFingerprintAlreadyBound) {
					middleware.AgentCertMismatchTotal.Add(1)
					IngestRejectedTotal.Add(1)
					apierrors.Unauthorized(w, "mTLS client cert does not match agent identity")
					return
				}
				log.Printf("telemetry mTLS bind failed: org=%s agent_id=%s err=%v", orgID, agentID, err)
				IngestRejectedTotal.Add(1)
				apierrors.Internal(w)
				return
			}
		}
	}

	for i := range batch.Events {
		e := &batch.Events[i]
		if e.AgentID == "" || e.EventType == "" || e.Timestamp.IsZero() {
			IngestRejectedTotal.Add(1)
			apierrors.BadRequest(w, "event is missing required fields")
			return
		}
		if e.Timestamp.After(time.Now().Add(5 * time.Minute)) {
			IngestRejectedTotal.Add(1)
			apierrors.BadRequest(w, "event timestamp too far in the future")
			return
		}
		if len(e.Payload) == 0 {
			IngestRejectedTotal.Add(1)
			apierrors.BadRequest(w, "event payload required")
			return
		}
	}

	if err := h.store.InsertEvents(orgID, batch.Events); err != nil {
		log.Printf("telemetry insert failed: org_id=%s events=%d err=%v", orgID, len(batch.Events), err)
		IngestRejectedTotal.Add(1)
		apierrors.Internal(w)
		return
	}

	// Attribute process_exec events to AI agents
	if h.attributionSvc != nil {
		for _, te := range batch.Events {
			if te.EventType == "exec" || te.EventType == "process_exec" {
				h.attributionSvc.AttributeEvent(orgID, te.AgentID, te)
			}
		}
	}

	IngestAcceptedTotal.Add(1)
	w.WriteHeader(http.StatusAccepted)
}

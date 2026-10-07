package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/ai/attribution"
	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/storage"
)

const maxTelemetryBodyBytes = 4 << 20 // 4MiB for batch ingest

// TelemetryHandler exposes telemetry event listing (GET) and batch ingest (POST) for agents.
type TelemetryHandler struct {
	store          storage.TelemetryStore
	attributionSvc *attribution.Service
}

func NewTelemetryHandler(store storage.TelemetryStore, attributionSvc *attribution.Service) *TelemetryHandler {
	return &TelemetryHandler{store: store, attributionSvc: attributionSvc}
}

func (h *TelemetryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	switch r.Method {
	case http.MethodPost:
		h.servePost(w, r, orgID)
		return
	case http.MethodGet:
		h.serveGet(w, r, orgID)
		return
	default:
		MethodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		return
	}
}

// servePost accepts agent telemetry batches (POST body: {"events": [...]}) and inserts into telemetry_events.
func (h *TelemetryHandler) servePost(w http.ResponseWriter, r *http.Request, orgID string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTelemetryBodyBytes)
	var batch model.TelemetryBatch
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&batch); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			PayloadTooLarge(w, "")
			return
		}
		log.Printf("telemetry ingest decode error: %v", err)
		BadRequest(w, "invalid JSON body (expected {\"events\": [...]})")
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		BadRequest(w, "invalid payload")
		return
	}
	if len(batch.Events) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}
	if err := h.store.InsertEvents(orgID, batch.Events); err != nil {
		log.Printf("telemetry ingest insert error: %v", err)
		Internal(w)
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

	w.WriteHeader(http.StatusAccepted)
}

// serveGet lists telemetry events with optional filters (query params).
func (h *TelemetryHandler) serveGet(w http.ResponseWriter, r *http.Request, orgID string) {
	// Parse query params
	eventType := r.URL.Query().Get("event_type")
	agentID := r.URL.Query().Get("agent_id")
	sinceStr := r.URL.Query().Get("since")
	untilStr := r.URL.Query().Get("until")
	pidStr := r.URL.Query().Get("pid")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	aiOnlyStr := r.URL.Query().Get("ai_only")

	limit := 50
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}

	offset := 0
	if offsetStr != "" {
		if n, err := strconv.Atoi(offsetStr); err == nil && n >= 0 {
			offset = n
		}
	}

	var since time.Time
	if sinceStr != "" {
		if t, err := time.Parse(time.RFC3339Nano, sinceStr); err == nil {
			since = t
		} else if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		} else {
			BadRequest(w, "invalid since (expected RFC3339)")
			return
		}
	}
	var until time.Time
	if untilStr != "" {
		if t, err := time.Parse(time.RFC3339Nano, untilStr); err == nil {
			until = t
		} else if t, err := time.Parse(time.RFC3339, untilStr); err == nil {
			until = t
		} else {
			BadRequest(w, "invalid until (expected RFC3339)")
			return
		}
	}
	var pid int64
	if pidStr != "" {
		if n, err := strconv.ParseInt(pidStr, 10, 64); err == nil && n > 0 {
			pid = n
		} else {
			BadRequest(w, "invalid pid")
			return
		}
	}

	aiOnly := aiOnlyStr == "true" || aiOnlyStr == "1" || strings.EqualFold(aiOnlyStr, "yes")
	fetchLimit := limit
	// If ai_only is requested, overfetch a bit so post-filtering still returns "limit" items.
	// (Filter is best-effort and based on comm-like payload fields.)
	if aiOnly {
		fetchLimit = limit * 5
		if fetchLimit > 500 {
			fetchLimit = 500
		}
	}

	events, err := h.store.ListFiltered(orgID, storage.TelemetryListFilter{
		AgentID:   agentID,
		EventType: eventType,
		Since:     since,
		Until:     until,
		PID:       pid,
		Limit:     fetchLimit,
		Offset:    offset,
	})
	if err != nil {
		Internal(w)
		return
	}

	if aiOnly && len(events) > 0 {
		aiPIDs := buildAIPIDSet(h.store, orgID, agentID, since, until)
		events = filterAIAttributedEvents(events, aiPIDs, limit)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/ingest"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/storage"
	"github.com/google/uuid"
)

const maxHeartbeatBodyBytes = 1 << 20 // 1MiB

// HeartbeatHandler is the handler for heartbeat requests
type HeartbeatHandler struct {
	service        *ingest.HeartbeatService
	agentCertStore storage.AgentCertStore
	apiKeyStore    storage.APIKeyStore
}

// NewHeartbeatHandler creates a new heartbeat handler
func NewHeartbeatHandler(service *ingest.HeartbeatService, agentCertStore storage.AgentCertStore, apiKeyStore storage.APIKeyStore) *HeartbeatHandler {
	return &HeartbeatHandler{
		service:        service,
		agentCertStore: agentCertStore,
		apiKeyStore:    apiKeyStore,
	}
}

// ServeHTTP handles heartbeat requests. It is reachable by the agent role
// (agent API keys and mTLS-only callers) as well as members and admins.
func (h *HeartbeatHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		MethodNotAllowed(w, http.MethodPost)
		return
	}

	// get the org ID from the context
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// decode the payload
	r.Body = http.MaxBytesReader(w, r.Body, maxHeartbeatBodyBytes)
	var payload model.HeartbeatPayload
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		log.Printf("heartbeat decode error: %v", err)
		// MaxBytesReader returns a decode error when the body is too large; treat as 413.
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			PayloadTooLarge(w, "")
			return
		}
		BadRequest(w, "invalid payload")
		return
	}
	// Reject trailing JSON tokens (e.g. "{}{}").
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		BadRequest(w, "invalid payload")
		return
	}

	log.Printf(
		"heartbeat received: agent_id=%s state=%s",
		payload.AgentID,
		payload.State,
	)

	if payload.AgentID == "" {
		log.Printf("heartbeat rejected: missing agent_id")
		BadRequest(w, "missing agent_id")
		return
	}

	// If mTLS fingerprint is present, enforce binding to this agent_id.
	if fp, ok := middleware.ClientCertFingerprintFromContext(r.Context()); ok && h.agentCertStore != nil {
		if err := h.agentCertStore.EnsureBound(orgID, payload.AgentID, fp); err != nil {
			// Treat binding mismatch as unauthorized.
			if errors.Is(err, storage.ErrAgentCertMismatch) || errors.Is(err, storage.ErrFingerprintAlreadyBound) {
				middleware.AgentCertMismatchTotal.Add(1)
				Unauthorized(w, "mTLS client cert does not match agent identity")
				return
			}
			log.Printf("heartbeat mTLS bind failed: org=%s agent_id=%s err=%v", orgID, payload.AgentID, err)
			Internal(w)
			return
		}
	}

	// Link the agent to the key's owner when the API key is tied to a user.
	// The auth middleware stores the user_id as the actor ID for such keys;
	// for keys without an owner the actor ID is the key hash, which must not
	// be written into agents.user_id (it is a UUID foreign key to users).
	var userID string
	actorType, actorID, hasActor := middleware.ActorFromContext(r.Context())
	if hasActor && actorType == middleware.ActorTypeAPIKey && actorID != "" {
		if _, err := uuid.Parse(actorID); err == nil {
			userID = actorID
			log.Printf("heartbeat: linking agent %s to user %s (from API key)", payload.AgentID, userID)
		}
	}

	agent := &model.Agent{
		AgentID:  payload.AgentID,
		UserID:   userID, // Link agent to user if API key has user_id
		Hostname: payload.Hostname,
		OS:       payload.OS,
		Profile:  payload.Profile,
		Version:  payload.Version,
		State:    payload.State,
	}

	// process the heartbeat
	if err := h.service.Process(orgID, agent); err != nil {
		log.Printf(
			"heartbeat rejected: agent_id=%s state=%s error=%v",
			payload.AgentID,
			payload.State,
			err,
		)
		if errors.Is(err, ingest.ErrInvalidStateTransition) {
			BadRequest(w, "invalid state transition")
			return
		}
		Internal(w)
		return
	}

	log.Printf(
		"heartbeat accepted: agent_id=%s state=%s",
		payload.AgentID,
		payload.State,
	)

	w.WriteHeader(http.StatusOK)
}

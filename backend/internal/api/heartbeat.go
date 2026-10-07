package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/ingest"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/storage"
)

// hashAPIKey hashes the API key using SHA-256 (same as auth middleware)
func hashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

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

// ServeHTTP handles heartbeat requests
func (h *HeartbeatHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Debug log removed
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

	// Extract user_id from API key (if agent token is used)
	// The auth middleware already resolved the API key and stored user_id in actorID
	var userID string
	actorType, actorID, hasActor := middleware.ActorFromContext(r.Context())
	if hasActor && actorType == "api_key" && actorID != "" {
		// actorID contains the user_id if the API key is linked to a user
		// (set by auth middleware when it calls LookupKeyInfo)
		userID = actorID
		log.Printf("heartbeat: linking agent %s to user %s (from API key)", payload.AgentID, userID)
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

package ingest

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/storage"
)

// ErrInvalidStateTransition is returned when the state transition is invalid
var ErrInvalidStateTransition = errors.New("invalid state transition")

// HeartbeatService is responsible for processing heartbeat requests
type HeartbeatService struct {
	// store is the storage layer for the heartbeat service
	store storage.AgentStore
}

// NewHeartbeatService creates a new heartbeat service
func NewHeartbeatService(store storage.AgentStore) *HeartbeatService {
	return &HeartbeatService{store: store}
}

// Process processes a heartbeat request
func (s *HeartbeatService) Process(orgID string, hb *model.Agent) error {

	if orgID == "" {
		log.Println("DEBUG: orgID is empty in HeartbeatService")
	}

	now := time.Now().UTC()

	// get the existing agent from the store
	existing, err := s.store.GetAgent(orgID, hb.AgentID)
	if err != nil {
		return fmt.Errorf("get agent: %w", err)
	}

	if existing == nil {
		// if the agent is not found, set the first seen at and created at to the current time
		hb.FirstSeenAt = now
		hb.CreatedAt = now
	} else {
		// if the agent is found, check if the state transition is valid
		if !isValidTransition(existing.State, hb.State) {
			return ErrInvalidStateTransition
		}
		hb.FirstSeenAt = existing.FirstSeenAt
		hb.CreatedAt = existing.CreatedAt
	}

	hb.LastSeenAt = now
	hb.UpdatedAt = now

	// upsert the agent into the store
	if err := s.store.UpsertAgent(orgID, hb); err != nil {
		return fmt.Errorf("upsert agent: %w", err)
	}
	return nil
}

// isValidTransition checks if the state transition is valid
func isValidTransition(from, to string) bool {
	// starting is always allowed (agent restart / recovery)
	if to == "starting" {
		return true
	}

	switch from {
	case "":
		return to == "starting"
	case "starting":
		return to == "running"
	case "running":
		return to == "running" || to == "stopping"
	case "stopping":
		return to == "stopped"
	default:
		return false
	}
}

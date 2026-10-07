package service

import (
	"time"

	"github.com/correlic/correlic-backend/internal/model"
)

// ComputeLiveness computes the liveness of an agent
func ComputeLiveness(lastSeen time.Time) model.AgentLiveness {
	now := time.Now().UTC()
	diff := now.Sub(lastSeen)

	switch {
	case diff <= 1*time.Minute:
		return model.LivenessOnline
	case diff <= 5*time.Minute:
		return model.LivenessStale
	default:
		return model.LivenessOffline
	}
}

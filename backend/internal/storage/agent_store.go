package storage

import "github.com/correlic/correlic-backend/internal/model"

// AgentStore is the interface for the agent store
type AgentStore interface {
	// UpsertAgent upserts an agent into the store
	UpsertAgent(orgID string, agent *model.Agent) error
	// GetAgent gets an agent from the store by agent ID
	GetAgent(orgID, agentID string) (*model.Agent, error)
	// ListAgents lists all agents from the store (optionally filtered by userID)
	ListAgents(orgID string, userID *string) ([]*model.Agent, error)
	// GetAgentsByUserID lists all agents for a specific user
	GetAgentsByUserID(orgID, userID string) ([]*model.Agent, error)
	// CountAgentsByUserID counts agents for a user (for deletion safety check)
	CountAgentsByUserID(userID string) (int, error)
}

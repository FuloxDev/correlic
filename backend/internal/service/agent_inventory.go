package service

import (
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/storage"
)

// AgentInventoryService is the service for the agent inventory
type AgentInventoryService struct {
	store storage.AgentStore
}

// NewAgentInventoryService creates a new agent inventory service
func NewAgentInventoryService(store storage.AgentStore) *AgentInventoryService {
	return &AgentInventoryService{store: store}
}

// ListAgents lists all agents for an organization (optionally filtered by userID)
func (s *AgentInventoryService) ListAgents(orgID string, userID *string) ([]*model.Agent, error) {
	return s.store.ListAgents(orgID, userID)
}

// GetAgent gets an agent for an organization
func (s *AgentInventoryService) GetAgent(orgID, agentID string) (*model.Agent, error) {
	return s.store.GetAgent(orgID, agentID)
}

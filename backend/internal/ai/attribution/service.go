package attribution

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/correlic/correlic-backend/internal/model"
)

// Service handles AI agent attribution for telemetry events.
type Service struct {
	store Store
	mu    sync.RWMutex
	// In-memory cache of active sessions by (orgID, agentID, pid)
	sessionCache map[string]*AIAgentSession
}

// NewService creates a new attribution service.
func NewService(store Store) *Service {
	svc := &Service{
		store:        store,
		sessionCache: make(map[string]*AIAgentSession),
	}
	// Load patterns into cache on startup
	if ps, ok := store.(*PostgresStore); ok {
		_ = ps.LoadPatterns()
	}
	return svc
}

// cacheKey generates a cache key for session lookup.
func cacheKey(orgID, agentID string, pid int64) string {
	return orgID + ":" + agentID + ":" + strconv.FormatInt(pid, 10)
}

// AttributeEvent checks if an event belongs to an AI agent and attributes it.
// Returns the agent type if attributed, empty string otherwise.
func (s *Service) AttributeEvent(orgID, agentID string, event model.TelemetryEvent) string {
	// Unmarshal payload to extract process info
	var payload map[string]interface{}
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return ""
	}

	// Extract process info from payload
	comm, _ := payload["comm"].(string)
	pid, _ := payload["pid"].(float64)
	ppid, _ := payload["ppid"].(float64)
	// AI Session ID from agent-side lineage tracker (cross-PID correlation).
	aiSessionID, _ := payload["ai_session_id"].(string)

	if comm == "" || pid == 0 {
		return ""
	}

	pidInt := int64(pid)
	ppidInt := int64(ppid)
	now := time.Now()

	// 1. Check if this process itself is a known AI agent
	agentType, err := s.store.GetPattern(comm)
	if err == nil && agentType != "" {
		// This is a root AI agent process - create/update session
		session := &AIAgentSession{
			OrgID:       orgID,
			AgentID:     agentID,
			RootPID:     pidInt,
			RootComm:    comm,
			AgentType:   agentType,
			AISessionID: aiSessionID,
			StartedAt:   now,
			LastSeenAt:  now,
			EventCount:  1,
		}
		_ = s.store.UpsertSession(session)

		// Cache the session
		s.mu.Lock()
		s.sessionCache[cacheKey(orgID, agentID, pidInt)] = session
		s.mu.Unlock()

		return agentType
	}

	// 2. Check if parent is a known AI session
	// First check cache
	s.mu.RLock()
	parentSession := s.sessionCache[cacheKey(orgID, agentID, ppidInt)]
	s.mu.RUnlock()

	if parentSession == nil && ppidInt > 0 {
		// Check database
		parentSession, _ = s.store.FindSessionByPID(orgID, agentID, ppidInt)
		if parentSession != nil {
			// Cache it
			s.mu.Lock()
			s.sessionCache[cacheKey(orgID, agentID, ppidInt)] = parentSession
			s.mu.Unlock()
		}
	}

	if parentSession != nil {
		// This is a child of an AI agent - increment count
		_ = s.store.IncrementEventCount(parentSession.ID)

		// Also cache this process as part of the session (for grandchildren)
		childSession := &AIAgentSession{
			ID:         parentSession.ID,
			OrgID:      orgID,
			AgentID:    agentID,
			RootPID:    parentSession.RootPID,
			RootComm:   parentSession.RootComm,
			AgentType:  parentSession.AgentType,
			StartedAt:  parentSession.StartedAt,
			LastSeenAt: now,
		}
		s.mu.Lock()
		s.sessionCache[cacheKey(orgID, agentID, pidInt)] = childSession
		s.mu.Unlock()

		return parentSession.AgentType
	}

	return ""
}

// CountDistinctAgents returns the number of distinct AI agents active in the last hour.
func (s *Service) CountDistinctAgents(orgID string) (int, error) {
	since := time.Now().Add(-1 * time.Hour)
	return s.store.CountDistinctAgents(orgID, since)
}

// CountDistinctAgentsSince returns the number of distinct AI agents active since the given time.
func (s *Service) CountDistinctAgentsSince(orgID string, since time.Time) (int, error) {
	return s.store.CountDistinctAgents(orgID, since)
}

// ListActiveSessions returns active AI sessions for an org.
func (s *Service) ListActiveSessions(orgID string, limit int) ([]AIAgentSession, error) {
	since := time.Now().Add(-1 * time.Hour)
	return s.store.ListActiveSessions(orgID, since, limit)
}

// ClearCache clears the in-memory session cache.
func (s *Service) ClearCache() {
	s.mu.Lock()
	s.sessionCache = make(map[string]*AIAgentSession)
	s.mu.Unlock()
}

// GetPatternNeedles returns all pattern strings from the database for substring matching.
// This provides a single source of truth for AI process identification.
func (s *Service) GetPatternNeedles() []string {
	patterns, err := s.store.GetPatterns()
	if err != nil {
		return nil
	}
	needles := make([]string, 0, len(patterns))
	for _, p := range patterns {
		needles = append(needles, p.Pattern)
	}
	return needles
}

// GetPatternNeedlesForOrg returns the pattern strings visible to orgID
// (built-ins plus the org's own) for agent-side substring matching.
func (s *Service) GetPatternNeedlesForOrg(orgID string) []string {
	patterns, err := s.store.GetPatternsForOrg(orgID)
	if err != nil {
		return nil
	}
	needles := make([]string, 0, len(patterns))
	for _, p := range patterns {
		needles = append(needles, p.Pattern)
	}
	return needles
}

// GetAllPatterns returns the AI agent patterns visible to orgID with full details:
// built-ins (org_id NULL) plus the org's own.
func (s *Service) GetAllPatterns(orgID string) ([]AIAgentPattern, error) {
	return s.store.GetPatternsForOrg(orgID)
}

// CreatePattern adds a new AI agent pattern owned by orgID and clears caches.
func (s *Service) CreatePattern(orgID string, p AIAgentPattern) (AIAgentPattern, error) {
	created, err := s.store.CreatePattern(orgID, p)
	if err != nil {
		return AIAgentPattern{}, err
	}
	s.ClearCache()
	return created, nil
}

// DeletePattern removes one of orgID's own AI agent patterns and clears caches.
func (s *Service) DeletePattern(orgID string, id int) error {
	if err := s.store.DeletePattern(orgID, id); err != nil {
		return err
	}
	s.ClearCache()
	return nil
}

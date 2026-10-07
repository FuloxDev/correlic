package attribution

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// ErrPatternExists is returned when a pattern already exists in the database.
var ErrPatternExists = errors.New("pattern already exists")

// ErrPatternNotFound is returned when a pattern is not found.
var ErrPatternNotFound = errors.New("pattern not found")

// AIAgentPattern represents a known AI agent process pattern.
type AIAgentPattern struct {
	ID          int       `json:"id"`
	Pattern     string    `json:"pattern"`
	AgentType   string    `json:"agent_type"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// AIAgentSession represents an active AI agent session.
type AIAgentSession struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	AgentID     string    `json:"agent_id"`
	RootPID     int64     `json:"root_pid"`
	RootComm    string    `json:"root_comm"`
	AgentType   string    `json:"agent_type"`
	AISessionID string    `json:"ai_session_id,omitempty"` // Correlic AI session UUID for cross-PID correlation
	StartedAt   time.Time `json:"started_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	EventCount  int       `json:"event_count"`
}

// Store provides storage operations for AI attribution.
type Store interface {
	// GetPatterns returns all known AI agent patterns.
	GetPatterns() ([]AIAgentPattern, error)
	// GetPattern returns the agent type if comm matches a pattern, empty if no match.
	GetPattern(comm string) (agentType string, err error)
	// UpsertSession creates or updates an AI agent session.
	UpsertSession(session *AIAgentSession) error
	// FindSessionByPID finds a session by organization, agent, and root PID.
	FindSessionByPID(orgID, agentID string, pid int64) (*AIAgentSession, error)
	// IncrementEventCount increments the event count for a session.
	IncrementEventCount(sessionID string) error
	// CountDistinctAgents returns the count of distinct AI agents active since the given time.
	CountDistinctAgents(orgID string, since time.Time) (int, error)
	// ListActiveSessions returns active AI sessions for an org.
	ListActiveSessions(orgID string, since time.Time, limit int) ([]AIAgentSession, error)
	// CreatePattern adds a new AI agent pattern.
	CreatePattern(p AIAgentPattern) (AIAgentPattern, error)
	// DeletePattern removes an AI agent pattern by ID.
	DeletePattern(id int) error
}

// PostgresStore implements Store using PostgreSQL.
type PostgresStore struct {
	db       *sql.DB
	patterns map[string]string // cache: comm -> agent_type
}

// NewPostgresStore creates a new PostgresStore.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{
		db:       db,
		patterns: make(map[string]string),
	}
}

// LoadPatterns loads patterns from the database into cache.
func (s *PostgresStore) LoadPatterns() error {
	rows, err := s.db.Query(`SELECT pattern, agent_type FROM ai_agent_patterns`)
	if err != nil {
		return err
	}
	defer rows.Close()

	s.patterns = make(map[string]string)
	for rows.Next() {
		var pattern, agentType string
		if err := rows.Scan(&pattern, &agentType); err != nil {
			return err
		}
		s.patterns[pattern] = agentType
	}
	return rows.Err()
}

func (s *PostgresStore) GetPatterns() ([]AIAgentPattern, error) {
	rows, err := s.db.Query(`
		SELECT id, pattern, agent_type, COALESCE(description, ''), created_at
		FROM ai_agent_patterns
		ORDER BY agent_type, pattern
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []AIAgentPattern
	for rows.Next() {
		var p AIAgentPattern
		if err := rows.Scan(&p.ID, &p.Pattern, &p.AgentType, &p.Description, &p.CreatedAt); err != nil {
			return nil, err
		}
		patterns = append(patterns, p)
	}
	return patterns, rows.Err()
}

func (s *PostgresStore) GetPattern(comm string) (string, error) {
	// Substring match against cached patterns — aligned with agent's CheckPattern().
	commLower := strings.ToLower(comm)
	for pattern, agentType := range s.patterns {
		if strings.Contains(commLower, strings.ToLower(pattern)) {
			return agentType, nil
		}
	}
	return "", nil
}

func (s *PostgresStore) UpsertSession(session *AIAgentSession) error {
	if session.ID == "" {
		session.ID = ulid.Make().String()
	}

	_, err := s.db.Exec(`
		INSERT INTO ai_agent_sessions (id, org_id, agent_id, root_pid, root_comm, agent_type, ai_session_id, started_at, last_seen_at, event_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (org_id, agent_id, root_pid)
		DO UPDATE SET last_seen_at = $9, event_count = ai_agent_sessions.event_count + 1,
		             ai_session_id = COALESCE(NULLIF($7, ''), ai_agent_sessions.ai_session_id)
	`, session.ID, session.OrgID, session.AgentID, session.RootPID, session.RootComm, session.AgentType, session.AISessionID, session.StartedAt, session.LastSeenAt, session.EventCount)
	return err
}

func (s *PostgresStore) FindSessionByPID(orgID, agentID string, pid int64) (*AIAgentSession, error) {
	var session AIAgentSession
	err := s.db.QueryRow(`
		SELECT id, org_id, agent_id, root_pid, root_comm, agent_type, started_at, last_seen_at, event_count
		FROM ai_agent_sessions
		WHERE org_id = $1 AND agent_id = $2 AND root_pid = $3
	`, orgID, agentID, pid).Scan(
		&session.ID, &session.OrgID, &session.AgentID, &session.RootPID,
		&session.RootComm, &session.AgentType, &session.StartedAt, &session.LastSeenAt, &session.EventCount,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (s *PostgresStore) IncrementEventCount(sessionID string) error {
	_, err := s.db.Exec(`
		UPDATE ai_agent_sessions
		SET event_count = event_count + 1, last_seen_at = now()
		WHERE id = $1
	`, sessionID)
	return err
}

func (s *PostgresStore) CountDistinctAgents(orgID string, since time.Time) (int, error) {
	var count int
	// Count distinct agent_type per agent_id (host), not by individual process PIDs
	// This ensures multiple processes from the same AI tool are counted as 1 agent
	err := s.db.QueryRow(`
		SELECT COUNT(DISTINCT (agent_id, agent_type))
		FROM ai_agent_sessions
		WHERE org_id = $1 AND last_seen_at >= $2
	`, orgID, since).Scan(&count)
	return count, err
}

func (s *PostgresStore) ListActiveSessions(orgID string, since time.Time, limit int) ([]AIAgentSession, error) {
	rows, err := s.db.Query(`
		SELECT id, org_id, agent_id, root_pid, root_comm, agent_type, started_at, last_seen_at, event_count
		FROM ai_agent_sessions
		WHERE org_id = $1 AND last_seen_at >= $2
		ORDER BY last_seen_at DESC
		LIMIT $3
	`, orgID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []AIAgentSession
	for rows.Next() {
		var s AIAgentSession
		if err := rows.Scan(
			&s.ID, &s.OrgID, &s.AgentID, &s.RootPID,
			&s.RootComm, &s.AgentType, &s.StartedAt, &s.LastSeenAt, &s.EventCount,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

func (s *PostgresStore) CreatePattern(p AIAgentPattern) (AIAgentPattern, error) {
	var created AIAgentPattern
	err := s.db.QueryRow(`
		INSERT INTO ai_agent_patterns (pattern, agent_type, description)
		VALUES ($1, $2, $3)
		RETURNING id, pattern, agent_type, COALESCE(description, ''), created_at
	`, strings.TrimSpace(p.Pattern), strings.TrimSpace(p.AgentType), p.Description).Scan(
		&created.ID, &created.Pattern, &created.AgentType, &created.Description, &created.CreatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			return AIAgentPattern{}, ErrPatternExists
		}
		return AIAgentPattern{}, err
	}
	// Refresh in-memory cache
	_ = s.LoadPatterns()
	return created, nil
}

func (s *PostgresStore) DeletePattern(id int) error {
	result, err := s.db.Exec(`DELETE FROM ai_agent_patterns WHERE id = $1`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrPatternNotFound
	}
	// Refresh in-memory cache
	_ = s.LoadPatterns()
	return nil
}

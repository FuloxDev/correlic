package storage

import (
	"database/sql"

	"github.com/correlic/correlic-backend/internal/model"
)

type PostgresAgentStore struct {
	db *sql.DB
}

func NewPostgresAgentStore(db *sql.DB) *PostgresAgentStore {
	return &PostgresAgentStore{db: db}
}

// GetAgent returns a single agent scoped to an org
func (s *PostgresAgentStore) GetAgent(orgID, agentID string) (*model.Agent, error) {
	row := s.db.QueryRow(`
		SELECT agent_id, user_id::text, hostname, os, profile, version, state,
		       first_seen_at, last_seen_at, created_at, updated_at
		FROM agents
		WHERE org_id = $1::uuid AND agent_id = $2
	`, orgID, agentID)

	var a model.Agent
	var userID sql.NullString
	err := row.Scan(
		&a.AgentID,
		&userID,
		&a.Hostname,
		&a.OS,
		&a.Profile,
		&a.Version,
		&a.State,
		&a.FirstSeenAt,
		&a.LastSeenAt,
		&a.CreatedAt,
		&a.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if userID.Valid {
		a.UserID = userID.String
	}

	return &a, nil
}

// UpsertAgent inserts or updates an agent scoped to an org
func (s *PostgresAgentStore) UpsertAgent(orgID string, a *model.Agent) error {
	var userID interface{}
	if a.UserID != "" {
		userID = a.UserID
	} else {
		userID = nil
	}

	_, err := s.db.Exec(`
		INSERT INTO agents (
			org_id, agent_id, user_id, hostname, os, profile, version, state,
			first_seen_at, last_seen_at, created_at, updated_at
		) VALUES (
			$1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
		ON CONFLICT (org_id, agent_id) DO UPDATE SET
			user_id = COALESCE(EXCLUDED.user_id, agents.user_id),
			hostname = EXCLUDED.hostname,
			os = EXCLUDED.os,
			profile = EXCLUDED.profile,
			version = EXCLUDED.version,
			state = EXCLUDED.state,
			last_seen_at = EXCLUDED.last_seen_at,
			updated_at = EXCLUDED.updated_at
	`,
		orgID,
		a.AgentID,
		userID,
		a.Hostname,
		a.OS,
		a.Profile,
		a.Version,
		a.State,
		a.FirstSeenAt,
		a.LastSeenAt,
		a.CreatedAt,
		a.UpdatedAt,
	)

	return err
}

// ListAgents returns all agents for an org (optionally filtered by userID)
func (s *PostgresAgentStore) ListAgents(orgID string, userID *string) ([]*model.Agent, error) {
	var rows *sql.Rows
	var err error

	if userID != nil && *userID != "" {
		// Filter by user
		rows, err = s.db.Query(`
			SELECT agent_id, user_id::text, hostname, os, profile, version, state,
			       first_seen_at, last_seen_at, created_at, updated_at
			FROM agents
			WHERE org_id = $1::uuid AND user_id = $2::uuid
			ORDER BY last_seen_at DESC
		`, orgID, *userID)
	} else {
		// All agents in org
		rows, err = s.db.Query(`
			SELECT agent_id, user_id::text, hostname, os, profile, version, state,
			       first_seen_at, last_seen_at, created_at, updated_at
			FROM agents
			WHERE org_id = $1::uuid
			ORDER BY last_seen_at DESC
		`, orgID)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*model.Agent

	for rows.Next() {
		var a model.Agent
		var uid sql.NullString
		if err := rows.Scan(
			&a.AgentID,
			&uid,
			&a.Hostname,
			&a.OS,
			&a.Profile,
			&a.Version,
			&a.State,
			&a.FirstSeenAt,
			&a.LastSeenAt,
			&a.CreatedAt,
			&a.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if uid.Valid {
			a.UserID = uid.String
		}
		agents = append(agents, &a)
	}

	return agents, rows.Err()
}

// GetAgentsByUserID lists all agents for a specific user
func (s *PostgresAgentStore) GetAgentsByUserID(orgID, userID string) ([]*model.Agent, error) {
	return s.ListAgents(orgID, &userID)
}

// CountAgentsByUserID counts agents for a user (for deletion safety check)
func (s *PostgresAgentStore) CountAgentsByUserID(userID string) (int, error) {
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*)
		FROM agents
		WHERE user_id = $1::uuid
	`, userID).Scan(&count)
	return count, err
}

package storage

import (
	"database/sql"
	"fmt"
	"strings"
)

type PostgresAgentCertStore struct {
	db *sql.DB
}

func NewPostgresAgentCertStore(db *sql.DB) *PostgresAgentCertStore {
	return &PostgresAgentCertStore{db: db}
}

func (s *PostgresAgentCertStore) EnsureBound(orgID string, agentID string, fingerprint string) error {
	orgID = strings.TrimSpace(orgID)
	agentID = strings.TrimSpace(agentID)
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if orgID == "" || agentID == "" || fingerprint == "" {
		return fmt.Errorf("orgID, agentID, and fingerprint are required")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var existingFP string
	var revokedAt sql.NullTime
	row := tx.QueryRow(`
		SELECT fingerprint, revoked_at
		FROM org_agent_certs
		WHERE org_id = $1 AND agent_id = $2
	`, orgID, agentID)
	switch err := row.Scan(&existingFP, &revokedAt); err {
	case nil:
		if revokedAt.Valid {
			// allow re-bind after revoke
			_, err := tx.Exec(`
				UPDATE org_agent_certs
				SET fingerprint = $3, revoked_at = NULL, created_at = now()
				WHERE org_id = $1 AND agent_id = $2
			`, orgID, agentID, fingerprint)
			if err != nil {
				return err
			}
		} else {
			if strings.ToLower(existingFP) != fingerprint {
				return ErrAgentCertMismatch
			}
		}
	case sql.ErrNoRows:
		_, err := tx.Exec(`
			INSERT INTO org_agent_certs (org_id, agent_id, fingerprint)
			VALUES ($1, $2, $3)
		`, orgID, agentID, fingerprint)
		if err != nil {
			// if fingerprint uniqueness violated, it is already bound to a different agent_id
			if strings.Contains(err.Error(), "org_agent_certs_org_fingerprint_unique") {
				return ErrFingerprintAlreadyBound
			}
			return err
		}
	default:
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *PostgresAgentCertStore) Revoke(orgID string, agentID string) (bool, error) {
	orgID = strings.TrimSpace(orgID)
	agentID = strings.TrimSpace(agentID)
	if orgID == "" || agentID == "" {
		return false, fmt.Errorf("orgID and agentID are required")
	}
	res, err := s.db.Exec(`
		UPDATE org_agent_certs
		SET revoked_at = now()
		WHERE org_id = $1 AND agent_id = $2 AND revoked_at IS NULL
	`, orgID, agentID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *PostgresAgentCertStore) List(orgID string, limit int, includeRevoked bool) ([]AgentCertRecord, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, fmt.Errorf("orgID is required")
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}

	q := `
		SELECT agent_id, fingerprint, created_at, revoked_at
		FROM org_agent_certs
		WHERE org_id = $1
	`
	args := []any{orgID}
	if !includeRevoked {
		q += " AND revoked_at IS NULL"
	}
	q += " ORDER BY created_at DESC LIMIT $2"
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AgentCertRecord
	for rows.Next() {
		var r AgentCertRecord
		var revoked sql.NullTime
		if err := rows.Scan(&r.AgentID, &r.Fingerprint, &r.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		if revoked.Valid {
			t := revoked.Time
			r.RevokedAt = &t
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

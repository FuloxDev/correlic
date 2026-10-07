package storage

import (
	"database/sql"
	"fmt"
	"strings"
)

type PostgresClientCertStore struct {
	db *sql.DB
}

func NewPostgresClientCertStore(db *sql.DB) *PostgresClientCertStore {
	return &PostgresClientCertStore{db: db}
}

func (s *PostgresClientCertStore) IsEnrolled(orgID string, fingerprint string) (bool, error) {
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if orgID == "" || fingerprint == "" {
		return false, fmt.Errorf("orgID and fingerprint are required")
	}
	var exists bool
	err := s.db.QueryRow(`
		SELECT EXISTS(
			SELECT 1
			FROM org_client_certs
			WHERE org_id = $1 AND fingerprint = $2 AND revoked_at IS NULL
		)
	`, orgID, fingerprint).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (s *PostgresClientCertStore) LookupOrgIDByFingerprint(fingerprint string) (string, error) {
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if fingerprint == "" {
		return "", fmt.Errorf("fingerprint is required")
	}
	var orgID string
	err := s.db.QueryRow(`
		SELECT org_id
		FROM org_client_certs
		WHERE fingerprint = $1 AND revoked_at IS NULL
	`, fingerprint).Scan(&orgID)
	if err != nil {
		return "", err
	}
	return orgID, nil
}

func (s *PostgresClientCertStore) Enroll(orgID string, name string, fingerprint string) error {
	name = strings.TrimSpace(name)
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if orgID == "" || name == "" || fingerprint == "" {
		return fmt.Errorf("orgID, name, and fingerprint are required")
	}
	_, err := s.db.Exec(`
		INSERT INTO org_client_certs (org_id, name, fingerprint)
		VALUES ($1, $2, $3)
		ON CONFLICT (org_id, fingerprint) DO UPDATE SET
		  name = EXCLUDED.name
	`, orgID, name, fingerprint)
	return err
}

func (s *PostgresClientCertStore) Revoke(orgID string, fingerprint string) (bool, error) {
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if orgID == "" || fingerprint == "" {
		return false, fmt.Errorf("orgID and fingerprint are required")
	}
	res, err := s.db.Exec(`
		UPDATE org_client_certs
		SET revoked_at = now()
		WHERE org_id = $1 AND fingerprint = $2 AND revoked_at IS NULL
	`, orgID, fingerprint)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *PostgresClientCertStore) List(orgID string, limit int, includeRevoked bool) ([]ClientCertRecord, error) {
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
		SELECT name, fingerprint, created_at, revoked_at
		FROM org_client_certs
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

	var out []ClientCertRecord
	for rows.Next() {
		var r ClientCertRecord
		var revoked sql.NullTime
		if err := rows.Scan(&r.Name, &r.Fingerprint, &r.CreatedAt, &revoked); err != nil {
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

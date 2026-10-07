package storage

import (
	"context"
	"database/sql"
	"time"
)

type PostgresOrgStore struct {
	db *sql.DB
}

func NewPostgresOrgStore(db *sql.DB) *PostgresOrgStore {
	return &PostgresOrgStore{db: db}
}

func (s *PostgresOrgStore) Get(orgID string) (*Organization, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var org Organization
	err := s.db.QueryRowContext(ctx, `
		SELECT id::text, name, created_at
		FROM organizations
		WHERE id = $1
	`, orgID).Scan(&org.ID, &org.Name, &org.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &org, nil
}

func (s *PostgresOrgStore) CreateOrg(orgID, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES ($1::uuid, $2, now())
	`, orgID, name)
	return err
}

// GetOrCreate returns the org if it exists, or creates it with the given name
func (s *PostgresOrgStore) GetOrCreate(orgID, name string) (*Organization, error) {
	org, err := s.Get(orgID)
	if err != nil {
		return nil, err
	}
	if org != nil {
		return org, nil
	}
	// Org doesn't exist, create it
	if err := s.CreateOrg(orgID, name); err != nil {
		// Could be a race condition, try get again
		org, getErr := s.Get(orgID)
		if getErr == nil && org != nil {
			return org, nil
		}
		return nil, err
	}
	return s.Get(orgID)
}

var _ OrgStore = (*PostgresOrgStore)(nil)

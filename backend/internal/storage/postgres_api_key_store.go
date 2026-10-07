package storage

import "database/sql"

type PostgresAPIKeyStore struct {
	db *sql.DB
}

// NewPostgresAPIKeyStore creates a new postgres API key store
func NewPostgresAPIKeyStore(db *sql.DB) *PostgresAPIKeyStore {
	return &PostgresAPIKeyStore{db: db}
}

// LookupOrgID looks up an organization ID by a hashed API key
func (s *PostgresAPIKeyStore) LookupOrgID(keyHash string) (string, error) {
	var orgID string
	err := s.db.QueryRow(`
		SELECT org_id
		FROM api_keys
		WHERE key_hash = $1 AND revoked_at IS NULL
	`, keyHash).Scan(&orgID)
	return orgID, err
}

// LookupKeyInfo looks up full API key info (org, user, role) by hashed key
func (s *PostgresAPIKeyStore) LookupKeyInfo(keyHash string) (*APIKeyInfo, error) {
	var info APIKeyInfo
	var userID sql.NullString
	var role sql.NullString

	err := s.db.QueryRow(`
		SELECT 
			ak.org_id::text,
			ak.user_id::text,
			ou.role
		FROM api_keys ak
		LEFT JOIN org_users ou ON ak.user_id = ou.user_id AND ak.org_id = ou.org_id
		WHERE ak.key_hash = $1 AND ak.revoked_at IS NULL
	`, keyHash).Scan(&info.OrgID, &userID, &role)

	if err != nil {
		return nil, err
	}

	if userID.Valid {
		info.UserID = userID.String
	}
	if role.Valid {
		info.Role = role.String
	}

	return &info, nil
}

// Create inserts a new API key
func (s *PostgresAPIKeyStore) Create(keyID, orgID, userID, name, keyHash string) error {
	_, err := s.db.Exec(`
		INSERT INTO api_keys (id, org_id, user_id, name, key_hash, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
	`, keyID, orgID, userID, name, keyHash)
	return err
}

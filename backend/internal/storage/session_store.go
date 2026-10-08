package storage

import (
	"context"
	"database/sql"
	"time"
)

// SessionRevoker revokes login sessions. It is separate from UserStore so the
// logout path can be wired without touching the (much larger) user store.
type SessionRevoker interface {
	// DeleteSessionByTokenHash removes the session identified by the SHA-256
	// hash of its bearer token. Deleting a session that does not exist is not
	// an error.
	DeleteSessionByTokenHash(tokenHash string) error
}

// PostgresSessionStore implements SessionRevoker on the sessions table.
type PostgresSessionStore struct {
	db *sql.DB
}

// NewPostgresSessionStore creates a session store backed by the given database.
func NewPostgresSessionStore(db *sql.DB) *PostgresSessionStore {
	return &PostgresSessionStore{db: db}
}

// DeleteSessionByTokenHash implements SessionRevoker.
func (s *PostgresSessionStore) DeleteSessionByTokenHash(tokenHash string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

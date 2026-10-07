package storage

import (
	"context"
	"encoding/json"
	"time"

	"database/sql"
	"github.com/google/uuid"
)

type PostgresAuditStore struct {
	db *sql.DB
}

func NewPostgresAuditStore(db *sql.DB) *PostgresAuditStore {
	return &PostgresAuditStore{db: db}
}

func (s *PostgresAuditStore) InsertEvent(e *AuditEvent) error {
	if e == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	id := e.ID
	if id == "" {
		id = uuid.New().String()
	}
	raw, _ := json.Marshal(e.Meta)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events (id, org_id, actor_type, actor_id, action, target_type, target_id, meta)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
	`, id, e.OrgID, e.ActorType, e.ActorID, e.Action, e.TargetType, e.TargetID, raw)
	return err
}

var _ AuditStore = (*PostgresAuditStore)(nil)

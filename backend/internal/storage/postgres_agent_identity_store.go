package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type PostgresAgentIdentityStore struct {
	db *sql.DB
}

func NewPostgresAgentIdentityStore(db *sql.DB) *PostgresAgentIdentityStore {
	return &PostgresAgentIdentityStore{db: db}
}

func nullUUIDArg(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func (s *PostgresAgentIdentityStore) UpsertSeen(orgID, agentID, kind string, values []string, seenAt time.Time, sourceEventType string, sourceEventID string, meta any) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rawMeta := []byte(`{}`)
	if meta != nil {
		if b, err := json.Marshal(meta); err == nil && len(b) > 0 {
			rawMeta = b
		}
	}

	newVals := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		var inserted bool
		err := s.db.QueryRowContext(ctx, `
			INSERT INTO org_agent_identities (org_id, agent_id, kind, value, first_seen_at, last_seen_at, seen_count, last_event_id, last_event_type, last_meta)
			VALUES ($1, $2, $3, $4, $5, $5, 1, $6::uuid, $7, $8::jsonb)
			ON CONFLICT (org_id, agent_id, kind, value) DO UPDATE SET
			  last_seen_at = EXCLUDED.last_seen_at,
			  seen_count = org_agent_identities.seen_count + 1,
			  last_event_id = EXCLUDED.last_event_id,
			  last_event_type = EXCLUDED.last_event_type,
			  last_meta = EXCLUDED.last_meta
			RETURNING (xmax = 0) AS inserted
		`, orgID, agentID, kind, v, seenAt, nullUUIDArg(sourceEventID), sourceEventType, rawMeta).Scan(&inserted)
		if err != nil {
			return nil, fmt.Errorf("upsert identity: %w", err)
		}
		if inserted {
			newVals = append(newVals, v)
		}
	}
	return newVals, nil
}

func (s *PostgresAgentIdentityStore) ListByAgent(orgID, agentID, kind string, limit int) ([]AgentIdentityRecord, error) {
	if limit <= 0 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		rows *sql.Rows
		err  error
	)
	if kind == "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT kind, value, first_seen_at, last_seen_at, seen_count, COALESCE(last_event_id::text, ''), COALESCE(last_event_type, ''), last_meta
			FROM org_agent_identities
			WHERE org_id = $1 AND agent_id = $2
			ORDER BY last_seen_at DESC
			LIMIT $3
		`, orgID, agentID, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT kind, value, first_seen_at, last_seen_at, seen_count, COALESCE(last_event_id::text, ''), COALESCE(last_event_type, ''), last_meta
			FROM org_agent_identities
			WHERE org_id = $1 AND agent_id = $2 AND kind = $3
			ORDER BY last_seen_at DESC
			LIMIT $4
		`, orgID, agentID, kind, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AgentIdentityRecord
	for rows.Next() {
		var r AgentIdentityRecord
		if err := rows.Scan(&r.Kind, &r.Value, &r.FirstSeenAt, &r.LastSeenAt, &r.SeenCount, &r.LastEventID, &r.LastEventType, &r.LastMeta); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

var _ AgentIdentityStore = (*PostgresAgentIdentityStore)(nil)

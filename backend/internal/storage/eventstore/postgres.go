package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

type PostgresEventStore struct {
	db *sql.DB
}

func NewPostgresEventStore(db *sql.DB) *PostgresEventStore {
	return &PostgresEventStore{db: db}
}

func (s *PostgresEventStore) Append(ctx context.Context, evt event.Event) error {
	actorJSON, err := json.Marshal(evt.Process)
	if err != nil {
		return err
	}
	targetJSON, err := json.Marshal(evt.Target)
	if err != nil {
		return err
	}
	contextJSON, err := json.Marshal(evt.Context)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO events (id, schema_version, host_id, ts, source, type, actor, target, context)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		evt.ID,
		evt.SchemaVersion,
		evt.HostID,
		evt.Timestamp,
		evt.Source,
		evt.Type,
		actorJSON,
		targetJSON,
		contextJSON,
	)
	return err
}

// AppendIdempotent inserts the event into events. If id already exists, does nothing (ON CONFLICT DO NOTHING).
func (s *PostgresEventStore) AppendIdempotent(ctx context.Context, evt event.Event) error {
	actorJSON, err := json.Marshal(evt.Process)
	if err != nil {
		return err
	}
	targetJSON, err := json.Marshal(evt.Target)
	if err != nil {
		return err
	}
	contextJSON, err := json.Marshal(evt.Context)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO events (id, schema_version, host_id, ts, source, type, actor, target, context)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO NOTHING
	`,
		evt.ID,
		evt.SchemaVersion,
		evt.HostID,
		evt.Timestamp,
		evt.Source,
		evt.Type,
		actorJSON,
		targetJSON,
		contextJSON,
	)
	return err
}

func (s *PostgresEventStore) GetByID(ctx context.Context, id string) (*event.Event, error) {
	var evt event.Event
	var actorRaw, targetRaw, contextRaw []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT id, schema_version, host_id, ts, source, type, actor, target, context
		FROM events
		WHERE id = $1
	`, id).Scan(
		&evt.ID,
		&evt.SchemaVersion,
		&evt.HostID,
		&evt.Timestamp,
		&evt.Source,
		&evt.Type,
		&actorRaw,
		&targetRaw,
		&contextRaw,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(actorRaw) > 0 {
		_ = json.Unmarshal(actorRaw, &evt.Process)
	}
	if len(targetRaw) > 0 {
		_ = json.Unmarshal(targetRaw, &evt.Target)
	}
	if len(contextRaw) > 0 {
		_ = json.Unmarshal(contextRaw, &evt.Context)
	}
	return &evt, nil
}

func (s *PostgresEventStore) GetRange(ctx context.Context, hostID string, from, to time.Time) ([]event.Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, schema_version, host_id, ts, source, type, actor, target, context
		FROM events
		WHERE host_id = $1 AND ts >= $2 AND ts <= $3
		ORDER BY ts ASC
	`, hostID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []event.Event
	for rows.Next() {
		var evt event.Event
		var actorRaw, targetRaw, contextRaw []byte
		if err := rows.Scan(
			&evt.ID,
			&evt.SchemaVersion,
			&evt.HostID,
			&evt.Timestamp,
			&evt.Source,
			&evt.Type,
			&actorRaw,
			&targetRaw,
			&contextRaw,
		); err != nil {
			return nil, err
		}
		if len(actorRaw) > 0 {
			_ = json.Unmarshal(actorRaw, &evt.Process)
		}
		if len(targetRaw) > 0 {
			_ = json.Unmarshal(targetRaw, &evt.Target)
		}
		if len(contextRaw) > 0 {
			_ = json.Unmarshal(contextRaw, &evt.Context)
		}
		out = append(out, evt)
	}
	return out, rows.Err()
}

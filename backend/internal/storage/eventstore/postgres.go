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

// eventColumns is the SELECT list shared by every read; keep in sync with scanEvent.
const eventColumns = `id, schema_version, host_id, ts, source, type, actor, target, context`

func marshalEvent(evt event.Event) (actorJSON, targetJSON, contextJSON []byte, err error) {
	if actorJSON, err = json.Marshal(evt.Process); err != nil {
		return nil, nil, nil, err
	}
	if targetJSON, err = json.Marshal(evt.Target); err != nil {
		return nil, nil, nil, err
	}
	if contextJSON, err = json.Marshal(evt.Context); err != nil {
		return nil, nil, nil, err
	}
	return actorJSON, targetJSON, contextJSON, nil
}

// nullableOrg converts an empty org to SQL NULL so pre-tenant rows stay distinguishable.
func nullableOrg(orgID string) any {
	if orgID == "" {
		return nil
	}
	return orgID
}

func (s *PostgresEventStore) Append(ctx context.Context, evt event.Event) error {
	actorJSON, targetJSON, contextJSON, err := marshalEvent(evt)
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
	return s.AppendIdempotentForOrg(ctx, "", evt)
}

// AppendIdempotentForOrg inserts the event with its owning org. If id already exists, does nothing.
func (s *PostgresEventStore) AppendIdempotentForOrg(ctx context.Context, orgID string, evt event.Event) error {
	actorJSON, targetJSON, contextJSON, err := marshalEvent(evt)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO events (id, schema_version, host_id, ts, source, type, actor, target, context, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::uuid)
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
		nullableOrg(orgID),
	)
	return err
}

func (s *PostgresEventStore) GetByID(ctx context.Context, id string) (*event.Event, error) {
	return s.GetByIDForOrg(ctx, "", id)
}

// GetByIDForOrg returns the event if it belongs to orgID. Rows without an org (written
// before org stamping) remain visible so existing timelines do not go blank after upgrade.
func (s *PostgresEventStore) GetByIDForOrg(ctx context.Context, orgID string, id string) (*event.Event, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT `+eventColumns+`
		FROM events
		WHERE id = $1 AND ($2::uuid IS NULL OR org_id IS NULL OR org_id = $2::uuid)
	`, id, nullableOrg(orgID))
	evt, err := scanEvent(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &evt, nil
}

func (s *PostgresEventStore) GetRange(ctx context.Context, hostID string, from, to time.Time) ([]event.Event, error) {
	return s.GetRangeForOrg(ctx, "", hostID, from, to)
}

// GetRangeForOrg returns a host's events in [from, to], restricted to orgID when set.
func (s *PostgresEventStore) GetRangeForOrg(ctx context.Context, orgID string, hostID string, from, to time.Time) ([]event.Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+eventColumns+`
		FROM events
		WHERE host_id = $1 AND ts >= $2 AND ts <= $3
		  AND ($4::uuid IS NULL OR org_id IS NULL OR org_id = $4::uuid)
		ORDER BY ts ASC
	`, hostID, from, to, nullableOrg(orgID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []event.Event
	for rows.Next() {
		evt, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, evt)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEvent(r rowScanner) (event.Event, error) {
	var evt event.Event
	var actorRaw, targetRaw, contextRaw []byte
	if err := r.Scan(
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
		return event.Event{}, err
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
	return evt, nil
}

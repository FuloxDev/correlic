package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/model"
)

type PostgresTelemetryStore struct {
	db *sql.DB
}

func NewPostgresTelemetryStore(db *sql.DB) *PostgresTelemetryStore {
	return &PostgresTelemetryStore{db: db}
}

func (s *PostgresTelemetryStore) InsertEvents(orgID string, events []model.TelemetryEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO telemetry_events (org_id, agent_id, event_type, event_ts, payload)
		VALUES ($1, $2, $3, $4, $5)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert telemetry_events: %w", err)
	}
	defer stmt.Close()

	for _, e := range events {
		if _, err := stmt.Exec(orgID, e.AgentID, e.EventType, e.Timestamp, e.Payload); err != nil {
			return fmt.Errorf("insert telemetry event (agent_id=%s event_type=%s): %w", e.AgentID, e.EventType, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (s *PostgresTelemetryStore) ListRecent(orgID string, agentID string, limit int) ([]model.TelemetryEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	rows, err := s.db.Query(`
		SELECT id, agent_id, event_type, event_ts, payload, received_at
		FROM telemetry_events
		WHERE org_id = $1 AND agent_id = $2
		ORDER BY event_ts DESC, received_at DESC
		LIMIT $3
	`, orgID, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("query recent telemetry: %w", err)
	}
	defer rows.Close()

	var out []model.TelemetryEvent
	for rows.Next() {
		var ev model.TelemetryEvent
		if err := rows.Scan(&ev.ID, &ev.AgentID, &ev.EventType, &ev.Timestamp, &ev.Payload, &ev.ReceivedAt); err != nil {
			return nil, fmt.Errorf("scan recent telemetry: %w", err)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recent telemetry: %w", err)
	}
	return out, nil
}

func (s *PostgresTelemetryStore) ListRange(orgID string, agentID string, eventType string, from, to time.Time, limit int) ([]model.TelemetryEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	if from.IsZero() || to.IsZero() || to.Before(from) {
		return nil, fmt.Errorf("invalid time range")
	}

	q := `
		SELECT id, agent_id, event_type, event_ts, payload, received_at
		FROM telemetry_events
		WHERE org_id = $1
		  AND agent_id = $2
		  AND event_ts >= $3
		  AND event_ts <= $4
	`
	args := []any{orgID, agentID, from, to}
	if eventType != "" {
		q += " AND event_type = $5"
		args = append(args, eventType)
		q += " ORDER BY event_ts DESC, received_at DESC LIMIT $6"
		args = append(args, limit)
	} else {
		q += " ORDER BY event_ts DESC, received_at DESC LIMIT $5"
		args = append(args, limit)
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query telemetry range: %w", err)
	}
	defer rows.Close()

	var out []model.TelemetryEvent
	for rows.Next() {
		var ev model.TelemetryEvent
		if err := rows.Scan(&ev.ID, &ev.AgentID, &ev.EventType, &ev.Timestamp, &ev.Payload, &ev.ReceivedAt); err != nil {
			return nil, fmt.Errorf("scan telemetry range: %w", err)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate telemetry range: %w", err)
	}
	return out, nil
}

func (s *PostgresTelemetryStore) ListByIDs(orgID string, agentID string, ids []string, limit int) ([]model.TelemetryEvent, error) {
	if len(ids) == 0 {
		return []model.TelemetryEvent{}, nil
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}
	if len(ids) > limit {
		ids = ids[:limit]
	}

	// Build a safe IN list without relying on driver-specific UUID array support.
	var b strings.Builder
	b.WriteString(`
		SELECT id, agent_id, event_type, event_ts, payload, received_at
		FROM telemetry_events
		WHERE org_id = $1 AND agent_id = $2 AND id IN (
	`)
	args := make([]any, 0, 2+len(ids)+1)
	args = append(args, orgID, agentID)
	for i, id := range ids {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "$%d::uuid", 3+i)
		args = append(args, id)
	}
	b.WriteString(`
		)
		ORDER BY event_ts DESC, received_at DESC
		LIMIT $`)
	fmt.Fprintf(&b, "%d", 3+len(ids))
	args = append(args, limit)

	rows, err := s.db.Query(b.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query telemetry by ids: %w", err)
	}
	defer rows.Close()

	var out []model.TelemetryEvent
	for rows.Next() {
		var ev model.TelemetryEvent
		if err := rows.Scan(&ev.ID, &ev.AgentID, &ev.EventType, &ev.Timestamp, &ev.Payload, &ev.ReceivedAt); err != nil {
			return nil, fmt.Errorf("scan telemetry by ids: %w", err)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate telemetry by ids: %w", err)
	}
	return out, nil
}

// ListAll returns recent events for an org (all agents, optionally filtered by event_type)
func (s *PostgresTelemetryStore) ListAll(orgID string, eventType string, limit int, offset int) ([]model.TelemetryEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}

	var q string
	var args []any

	if eventType != "" {
		q = `
			SELECT id, agent_id, event_type, event_ts, payload, received_at
			FROM telemetry_events
			WHERE org_id = $1 AND event_type = $2
			ORDER BY event_ts DESC, received_at DESC
			LIMIT $3 OFFSET $4
		`
		args = []any{orgID, eventType, limit, offset}
	} else {
		q = `
			SELECT id, agent_id, event_type, event_ts, payload, received_at
			FROM telemetry_events
			WHERE org_id = $1
			ORDER BY event_ts DESC, received_at DESC
			LIMIT $2 OFFSET $3
		`
		args = []any{orgID, limit, offset}
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query all telemetry: %w", err)
	}
	defer rows.Close()

	var out []model.TelemetryEvent
	for rows.Next() {
		var ev model.TelemetryEvent
		if err := rows.Scan(&ev.ID, &ev.AgentID, &ev.EventType, &ev.Timestamp, &ev.Payload, &ev.ReceivedAt); err != nil {
			return nil, fmt.Errorf("scan all telemetry: %w", err)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate all telemetry: %w", err)
	}
	return out, nil
}

// ListFiltered returns recent events with optional filters (agent_id, event_type, time range, pid).
func (s *PostgresTelemetryStore) ListFiltered(orgID string, f TelemetryListFilter) ([]model.TelemetryEvent, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	var b strings.Builder
	b.WriteString(`
		SELECT id, agent_id, event_type, event_ts, payload, received_at
		FROM telemetry_events
		WHERE org_id = $1
	`)
	args := []any{orgID}

	// Optional filters
	if f.AgentID != "" {
		args = append(args, f.AgentID)
		fmt.Fprintf(&b, " AND agent_id = $%d", len(args))
	}
	if f.EventType != "" {
		args = append(args, f.EventType)
		fmt.Fprintf(&b, " AND event_type = $%d", len(args))
	}
	if !f.Since.IsZero() {
		args = append(args, f.Since)
		fmt.Fprintf(&b, " AND event_ts >= $%d", len(args))
	}
	if !f.Until.IsZero() {
		args = append(args, f.Until)
		fmt.Fprintf(&b, " AND event_ts <= $%d", len(args))
	}
	if f.PID > 0 {
		args = append(args, f.PID)
		// Safe numeric extraction: only cast when pid is all digits.
		fmt.Fprintf(&b, `
		 AND (
		   CASE WHEN (payload->>'pid') ~ '^[0-9]+$' THEN (payload->>'pid')::bigint END
		 ) = $%d
		`, len(args))
	}

	// Pagination
	args = append(args, limit, offset)
	fmt.Fprintf(&b, `
		ORDER BY event_ts DESC, received_at DESC
		LIMIT $%d OFFSET $%d
	`, len(args)-1, len(args))

	rows, err := s.db.Query(b.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query filtered telemetry: %w", err)
	}
	defer rows.Close()

	out := make([]model.TelemetryEvent, 0)
	for rows.Next() {
		var ev model.TelemetryEvent
		if err := rows.Scan(&ev.ID, &ev.AgentID, &ev.EventType, &ev.Timestamp, &ev.Payload, &ev.ReceivedAt); err != nil {
			return nil, fmt.Errorf("scan filtered telemetry: %w", err)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate filtered telemetry: %w", err)
	}
	return out, nil
}

// CountFiltered returns the number of events matching the filter (Limit/Offset are ignored).
func (s *PostgresTelemetryStore) CountFiltered(orgID string, f TelemetryListFilter) (int, error) {
	var b strings.Builder
	b.WriteString(`
		SELECT COUNT(*)
		FROM telemetry_events
		WHERE org_id = $1
	`)
	args := []any{orgID}
	if f.AgentID != "" {
		args = append(args, f.AgentID)
		fmt.Fprintf(&b, " AND agent_id = $%d", len(args))
	}
	if f.EventType != "" {
		args = append(args, f.EventType)
		fmt.Fprintf(&b, " AND event_type = $%d", len(args))
	}
	if !f.Since.IsZero() {
		args = append(args, f.Since)
		fmt.Fprintf(&b, " AND event_ts >= $%d", len(args))
	}
	if !f.Until.IsZero() {
		args = append(args, f.Until)
		fmt.Fprintf(&b, " AND event_ts <= $%d", len(args))
	}
	if f.PID > 0 {
		args = append(args, f.PID)
		fmt.Fprintf(&b, `
		 AND (
		   CASE WHEN (payload->>'pid') ~ '^[0-9]+$' THEN (payload->>'pid')::bigint END
		 ) = $%d
		`, len(args))
	}
	var count int
	if err := s.db.QueryRow(b.String(), args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count filtered telemetry: %w", err)
	}
	return count, nil
}

// CountToday returns the count of events since midnight for an org
func (s *PostgresTelemetryStore) CountToday(orgID string) (int, error) {
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*)
		FROM telemetry_events
		WHERE org_id = $1 AND event_ts >= CURRENT_DATE
	`, orgID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count today: %w", err)
	}
	return count, nil
}

// CountByEventType returns event counts grouped by event_type since a given time.
// Single query replaces multiple CountFiltered calls for the dashboard.
func (s *PostgresTelemetryStore) CountByEventType(orgID string, since time.Time) (map[string]int, int, error) {
	rows, err := s.db.Query(`
		SELECT event_type, COUNT(*)
		FROM telemetry_events
		WHERE org_id = $1 AND event_ts >= $2
		GROUP BY event_type
	`, orgID, since)
	if err != nil {
		return nil, 0, fmt.Errorf("count by event type: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	total := 0
	for rows.Next() {
		var eventType string
		var count int
		if err := rows.Scan(&eventType, &count); err != nil {
			continue
		}
		counts[eventType] = count
		total += count
	}
	return counts, total, rows.Err()
}

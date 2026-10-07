package notification

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// DeliveryStore manages the external notification delivery queue in PostgreSQL.
type DeliveryStore struct {
	db *sql.DB
}

// NewDeliveryStore creates a new delivery store. Nil-safe.
func NewDeliveryStore(db *sql.DB) *DeliveryStore {
	if db == nil {
		return nil
	}
	return &DeliveryStore{db: db}
}

// Enqueue inserts a delivery into the queue. Uses ON CONFLICT DO NOTHING for dedup.
func (s *DeliveryStore) Enqueue(ctx context.Context, d Delivery) error {
	if s == nil {
		return nil
	}
	payloadJSON, err := json.Marshal(d.Payload)
	if err != nil {
		payloadJSON = []byte("{}")
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO notification_deliveries_v2
			(org_id, endpoint_id, reference_type, reference_id, payload, max_attempts)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (endpoint_id, reference_type, reference_id) DO NOTHING
	`, d.OrgID, d.EndpointID, d.ReferenceType, d.ReferenceID, payloadJSON, d.MaxAttempts)
	return err
}

// PollPending claims up to `limit` pending deliveries that are due. The claim
// pushes next_attempt_at two minutes ahead in the same statement, so a second
// worker (the api and telemetry planes both run one) cannot pick the same row;
// MarkDelivered/MarkFailed/MarkDead then record the outcome. A worker that dies
// mid-delivery simply lets the row become due again.
func (s *DeliveryStore) PollPending(ctx context.Context, limit int) ([]Delivery, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, `
		WITH due AS (
			SELECT id
			FROM notification_deliveries_v2
			WHERE status = 'pending' AND next_attempt_at <= now()
			ORDER BY next_attempt_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE notification_deliveries_v2 d
		SET next_attempt_at = now() + interval '2 minutes', updated_at = now()
		FROM due
		WHERE d.id = due.id
		RETURNING d.id, d.org_id, d.endpoint_id, d.reference_type, d.reference_id, d.payload, d.status,
			   d.attempts, d.max_attempts, d.last_error, d.next_attempt_at, d.delivered_at, d.created_at, d.updated_at
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []Delivery
	for rows.Next() {
		var d Delivery
		var payloadJSON []byte
		var deliveredAt sql.NullTime
		if err := rows.Scan(&d.ID, &d.OrgID, &d.EndpointID, &d.ReferenceType, &d.ReferenceID,
			&payloadJSON, &d.Status, &d.Attempts, &d.MaxAttempts, &d.LastError,
			&d.NextAttemptAt, &deliveredAt, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		if deliveredAt.Valid {
			d.DeliveredAt = &deliveredAt.Time
		}
		if err := json.Unmarshal(payloadJSON, &d.Payload); err != nil {
			d.Payload = map[string]any{}
		}
		deliveries = append(deliveries, d)
	}
	return deliveries, rows.Err()
}

// MarkDelivered marks a delivery as successfully delivered.
func (s *DeliveryStore) MarkDelivered(ctx context.Context, id string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE notification_deliveries_v2
		SET status = 'delivered', delivered_at = now(), attempts = attempts + 1, updated_at = now()
		WHERE id = $1
	`, id)
	return err
}

// MarkFailed increments the attempt count and schedules the next retry.
func (s *DeliveryStore) MarkFailed(ctx context.Context, id string, errMsg string, nextAttempt time.Time) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE notification_deliveries_v2
		SET status = 'pending', attempts = attempts + 1, last_error = $2, next_attempt_at = $3, updated_at = now()
		WHERE id = $1
	`, id, errMsg, nextAttempt)
	return err
}

// MarkDead marks a delivery as permanently failed (exceeded max attempts).
func (s *DeliveryStore) MarkDead(ctx context.Context, id string, errMsg string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE notification_deliveries_v2
		SET status = 'dead', attempts = attempts + 1, last_error = $2, updated_at = now()
		WHERE id = $1
	`, id, errMsg)
	return err
}

// ListByOrg returns delivery history for an org.
func (s *DeliveryStore) ListByOrg(ctx context.Context, orgID string, limit int) ([]Delivery, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, org_id, endpoint_id, reference_type, reference_id, payload, status,
			   attempts, max_attempts, last_error, next_attempt_at, delivered_at, created_at, updated_at
		FROM notification_deliveries_v2
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []Delivery
	for rows.Next() {
		var d Delivery
		var payloadJSON []byte
		var deliveredAt sql.NullTime
		if err := rows.Scan(&d.ID, &d.OrgID, &d.EndpointID, &d.ReferenceType, &d.ReferenceID,
			&payloadJSON, &d.Status, &d.Attempts, &d.MaxAttempts, &d.LastError,
			&d.NextAttemptAt, &deliveredAt, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		if deliveredAt.Valid {
			d.DeliveredAt = &deliveredAt.Time
		}
		if err := json.Unmarshal(payloadJSON, &d.Payload); err != nil {
			d.Payload = map[string]any{}
		}
		deliveries = append(deliveries, d)
	}
	return deliveries, rows.Err()
}

package notification

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// NotificationStore manages in-app notifications in PostgreSQL.
type NotificationStore struct {
	db *sql.DB
}

// NewNotificationStore creates a new notification store. Nil-safe.
func NewNotificationStore(db *sql.DB) *NotificationStore {
	if db == nil {
		return nil
	}
	return &NotificationStore{db: db}
}

// Insert creates a new in-app notification.
func (s *NotificationStore) Insert(ctx context.Context, n Notification) error {
	if s == nil {
		return nil
	}
	contextJSON, err := json.Marshal(n.Context)
	if err != nil {
		contextJSON = []byte("{}")
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO notifications (org_id, category, severity, title, summary, reference_type, reference_id, host_id, context)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, n.OrgID, n.Category, n.Severity, n.Title, n.Summary, n.ReferenceType, n.ReferenceID, n.HostID, contextJSON)
	return err
}

// List returns notifications for an org, optionally filtered to unread only.
func (s *NotificationStore) List(ctx context.Context, orgID string, unreadOnly bool, limit int) ([]Notification, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `
		SELECT id, org_id, category, severity, title, summary, reference_type, reference_id, host_id, context, read, dismissed, created_at
		FROM notifications
		WHERE org_id = $1 AND NOT dismissed
	`
	if unreadOnly {
		query += ` AND NOT read`
	}
	query += ` ORDER BY created_at DESC LIMIT $2`

	rows, err := s.db.QueryContext(ctx, query, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notifications []Notification
	for rows.Next() {
		var n Notification
		var contextJSON []byte
		var refType, refID, hostID sql.NullString
		if err := rows.Scan(&n.ID, &n.OrgID, &n.Category, &n.Severity, &n.Title, &n.Summary, &refType, &refID, &hostID, &contextJSON, &n.Read, &n.Dismissed, &n.CreatedAt); err != nil {
			return nil, err
		}
		n.ReferenceType = refType.String
		n.ReferenceID = refID.String
		n.HostID = hostID.String
		if err := json.Unmarshal(contextJSON, &n.Context); err != nil {
			n.Context = map[string]any{}
		}
		notifications = append(notifications, n)
	}
	return notifications, rows.Err()
}

// CountUnread returns the number of unread, non-dismissed notifications for an org.
func (s *NotificationStore) CountUnread(ctx context.Context, orgID string) (int, error) {
	if s == nil {
		return 0, nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM notifications
		WHERE org_id = $1 AND NOT read AND NOT dismissed
	`, orgID).Scan(&count)
	return count, err
}

// MarkRead marks a single notification as read.
func (s *NotificationStore) MarkRead(ctx context.Context, orgID, id string) error {
	if s == nil {
		return nil
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE notifications SET read = true WHERE id = $1 AND org_id = $2
	`, id, orgID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("notification not found")
	}
	return nil
}

// MarkAllRead marks all unread notifications as read for an org.
func (s *NotificationStore) MarkAllRead(ctx context.Context, orgID string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE notifications SET read = true WHERE org_id = $1 AND NOT read
	`, orgID)
	return err
}

// Dismiss soft-deletes a notification.
func (s *NotificationStore) Dismiss(ctx context.Context, orgID, id string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE notifications SET dismissed = true WHERE id = $1 AND org_id = $2
	`, id, orgID)
	return err
}

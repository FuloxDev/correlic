package conversation

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Message represents a stored conversation turn.
type Message struct {
	ID         string
	Role       string // "user" or "assistant"
	Content    string
	TokenCount int
	Compressed bool
	CreatedAt  time.Time
}

// Store manages ai_conversation_threads and ai_conversation_messages tables.
// Both tables are added by migration 074.
// All methods are nil-safe.
type Store struct{ db *sql.DB }

// NewStore creates a new conversation Store.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// GetOrCreateThread returns an existing thread ID or creates a new one.
// If threadID is "" or doesn't exist for this org+incident, a new thread is created.
func (s *Store) GetOrCreateThread(ctx context.Context, orgID, incidentID, threadID string) (string, error) {
	if s == nil {
		return uuid.New().String(), nil
	}

	// If a thread ID was provided, check if it exists.
	if threadID != "" {
		var existing string
		err := s.db.QueryRowContext(ctx, `
			SELECT id FROM ai_conversation_threads
			WHERE id = $1 AND org_id = $2 AND incident_id = $3
		`, threadID, orgID, incidentID).Scan(&existing)
		if err == nil {
			return existing, nil
		}
		// Not found or error — fall through to create a new thread.
	}

	// Create a new thread.
	newID := uuid.New().String()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ai_conversation_threads (id, org_id, incident_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (id) DO NOTHING
	`, newID, orgID, incidentID)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// AppendMessage saves a message and increments message_count on the thread.
func (s *Store) AppendMessage(ctx context.Context, threadID, orgID, role, content string, tokenCount int) error {
	if s == nil {
		return nil
	}

	msgID := uuid.New().String()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ai_conversation_messages (id, thread_id, org_id, role, content, token_count)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, msgID, threadID, orgID, role, content, tokenCount)
	if err != nil {
		return err
	}

	// Increment message_count and update last_active.
	_, _ = s.db.ExecContext(ctx, `
		UPDATE ai_conversation_threads
		SET message_count = message_count + 1, last_active = NOW()
		WHERE id = $1
	`, threadID)

	return nil
}

// GetHistory returns messages for a thread ordered oldest-first.
// If limit <= 0, up to 200 messages are returned.
func (s *Store) GetHistory(ctx context.Context, threadID, orgID string, limit int) ([]Message, error) {
	if s == nil {
		return nil, nil
	}

	cap := limit
	if cap <= 0 {
		cap = 200
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, role, content, token_count, compressed, created_at
		FROM ai_conversation_messages
		WHERE thread_id = $1 AND org_id = $2
		ORDER BY created_at ASC
		LIMIT $3
	`, threadID, orgID, cap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.Role, &m.Content, &m.TokenCount, &m.Compressed, &m.CreatedAt); err != nil {
			continue
		}
		messages = append(messages, m)
	}
	return messages, rows.Err()
}

// Touch updates last_active on the thread.
func (s *Store) Touch(ctx context.Context, threadID string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE ai_conversation_threads SET last_active = NOW() WHERE id = $1
	`, threadID)
	return err
}

// DeleteThread removes a thread (cascade deletes messages via FK).
func (s *Store) DeleteThread(ctx context.Context, threadID, orgID string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM ai_conversation_threads WHERE id = $1 AND org_id = $2
	`, threadID, orgID)
	return err
}

// PurgeOldThreads deletes threads inactive for more than 7 days.
// Called by the proactive summarizer periodically.
func (s *Store) PurgeOldThreads(ctx context.Context) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM ai_conversation_threads WHERE last_active < NOW() - INTERVAL '7 days'
	`)
	return err
}

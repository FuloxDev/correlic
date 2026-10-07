package ai

import (
	"database/sql"
	"time"
)

// IncidentSummary represents a cached AI-generated summary for an incident.
type IncidentSummary struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	IncidentID   string    `json:"incident_id"`
	Summary      string    `json:"summary"`
	Model        string    `json:"model"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	GeneratedAt  time.Time `json:"generated_at"`
}

// IncidentSummaryStore manages cached AI summaries for incidents.
// Nil-safe: all methods check for nil receiver.
type IncidentSummaryStore struct {
	db *sql.DB
}

// NewIncidentSummaryStore creates a new summary store.
func NewIncidentSummaryStore(db *sql.DB) *IncidentSummaryStore {
	return &IncidentSummaryStore{db: db}
}

// GetSummary returns a valid (non-invalidated) summary for an incident.
// Returns nil if no valid summary exists.
func (s *IncidentSummaryStore) GetSummary(orgID, incidentID string) (*IncidentSummary, error) {
	if s == nil {
		return nil, nil
	}

	var sum IncidentSummary
	err := s.db.QueryRow(`
		SELECT id, org_id, incident_id, summary, model, input_tokens, output_tokens, generated_at
		FROM incident_ai_summaries
		WHERE incident_id = $1 AND org_id = $2 AND invalidated_at IS NULL
	`, incidentID, orgID).Scan(
		&sum.ID, &sum.OrgID, &sum.IncidentID, &sum.Summary,
		&sum.Model, &sum.InputTokens, &sum.OutputTokens, &sum.GeneratedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sum, nil
}

// SaveSummary inserts or replaces the cached summary for an incident.
func (s *IncidentSummaryStore) SaveSummary(orgID, incidentID, summary, model string, inputTokens, outputTokens int) error {
	if s == nil {
		return nil
	}

	_, err := s.db.Exec(`
		INSERT INTO incident_ai_summaries (org_id, incident_id, summary, model, input_tokens, output_tokens, generated_at, invalidated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), NULL)
		ON CONFLICT (org_id, incident_id) DO UPDATE SET
			org_id = EXCLUDED.org_id,
			summary = EXCLUDED.summary,
			model = EXCLUDED.model,
			input_tokens = EXCLUDED.input_tokens,
			output_tokens = EXCLUDED.output_tokens,
			generated_at = EXCLUDED.generated_at,
			invalidated_at = NULL
	`, orgID, incidentID, summary, model, inputTokens, outputTokens)
	return err
}

// InvalidateSummary marks a summary as stale (e.g., after an incident is updated).
func (s *IncidentSummaryStore) InvalidateSummary(incidentID string) {
	if s == nil {
		return
	}

	_, _ = s.db.Exec(`
		UPDATE incident_ai_summaries
		SET invalidated_at = NOW()
		WHERE incident_id = $1 AND invalidated_at IS NULL
	`, incidentID)
}

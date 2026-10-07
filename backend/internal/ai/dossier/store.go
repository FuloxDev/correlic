package dossier

import (
	"context"
	"database/sql"
	"log"
	"time"
)

// Store reads and writes pre-rendered dossier text on the incidents table.
// The incidents table must have dossier_text (text) and dossier_built_at (timestamptz) columns
// (added by migration 073).
type Store struct{ db *sql.DB }

// NewStore creates a new dossier Store.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// GetText returns the pre-rendered dossier text and when it was built.
// Returns ("", zero, nil) if no dossier has been built yet.
func (s *Store) GetText(ctx context.Context, orgID, incidentID string) (text string, builtAt time.Time, err error) {
	if s == nil {
		return "", time.Time{}, nil
	}
	var rawText string
	var rawTime time.Time
	err = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(dossier_text, ''), COALESCE(dossier_built_at, '1970-01-01'::timestamptz)
		FROM incidents
		WHERE id = $1 AND org_id = $2
	`, incidentID, orgID).Scan(&rawText, &rawTime)
	if err == sql.ErrNoRows {
		return "", time.Time{}, nil
	}
	if err != nil {
		return "", time.Time{}, err
	}
	return rawText, rawTime, nil
}

// Save writes the rendered dossier text to the incidents table.
func (s *Store) Save(ctx context.Context, orgID, incidentID, text string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE incidents SET dossier_text = $1, dossier_built_at = NOW()
		WHERE id = $2 AND org_id = $3
	`, text, incidentID, orgID)
	return err
}

// Invalidate clears the dossier for an incident (sets both columns to NULL).
// Called when new findings are added to an incident, so the next chat
// request triggers a fresh build.
func (s *Store) Invalidate(ctx context.Context, incidentID string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE incidents SET dossier_text = NULL, dossier_built_at = NULL
		WHERE id = $1
	`, incidentID)
	return err
}

// InvalidateDossier implements the incident.DossierInvalidator interface.
// It clears the dossier for an incident (fire-and-forget; errors are logged).
func (s *Store) InvalidateDossier(incidentID string) {
	if s == nil {
		return
	}
	if err := s.Invalidate(context.Background(), incidentID); err != nil {
		log.Printf("WARN: dossier invalidate %s: %v", incidentID, err)
	}
}

// ListNeedingBuild returns up to limit incidents that have no dossier and are open/investigating.
// Returns (orgID, incidentID) pairs, prioritised by severity then recency.
func (s *Store) ListNeedingBuild(ctx context.Context, limit int) ([]struct{ OrgID, IncidentID string }, error) {
	if s == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT org_id, id FROM incidents
		WHERE dossier_text IS NULL
		  AND status IN ('open', 'investigating')
		  AND created_at > NOW() - INTERVAL '48 hours'
		ORDER BY
		  CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
		  created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []struct{ OrgID, IncidentID string }
	for rows.Next() {
		var item struct{ OrgID, IncidentID string }
		if err := rows.Scan(&item.OrgID, &item.IncidentID); err != nil {
			continue
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

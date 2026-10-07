package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"
)

// NeverBaselineEntry is a user-defined pattern that must never be auto-baselined.
type NeverBaselineEntry struct {
	ID          int       `json:"id"`
	OrgID       string    `json:"org_id"`
	SignalType  string    `json:"signal_type"`
	Pattern     string    `json:"pattern"`
	Description string    `json:"description"`
	Source      string    `json:"source"` // "system" or "user"
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// ErrPatternAlreadyBaselined is returned when a pattern being added to the
// never-baseline list already exists in behavioral_baselines.
type ErrPatternAlreadyBaselined struct {
	BaselineIDs []int
}

func (e ErrPatternAlreadyBaselined) Error() string {
	return fmt.Sprintf("%d existing baseline(s) match this pattern and would suppress it", len(e.BaselineIDs))
}

// NeverBaselineStore is an org-scoped, in-memory-cached store for user-defined
// never-baseline patterns. System-level (hardcoded) rules are handled separately
// in detection/never_baseline.go.
type NeverBaselineStore struct {
	db    *sql.DB
	mu    sync.RWMutex
	byOrg map[string][]NeverBaselineEntry // orgID → entries
	done  chan struct{}
}

func NewNeverBaselineStore(db *sql.DB) *NeverBaselineStore {
	s := &NeverBaselineStore{
		db:    db,
		byOrg: make(map[string][]NeverBaselineEntry),
		done:  make(chan struct{}),
	}
	if err := s.reload(context.Background()); err != nil {
		log.Printf("WARN: never_baseline_store initial load: %v", err)
	}
	go s.refreshLoop()
	return s
}

func (s *NeverBaselineStore) Stop() {
	if s == nil {
		return
	}
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

func (s *NeverBaselineStore) refreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if err := s.reload(context.Background()); err != nil {
				log.Printf("WARN: never_baseline_store refresh: %v", err)
			}
		}
	}
}

func (s *NeverBaselineStore) reload(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, org_id, signal_type, pattern, description, created_by, created_at
		 FROM org_never_baselines ORDER BY org_id, id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	byOrg := make(map[string][]NeverBaselineEntry)
	for rows.Next() {
		var e NeverBaselineEntry
		if err := rows.Scan(&e.ID, &e.OrgID, &e.SignalType, &e.Pattern, &e.Description, &e.CreatedBy, &e.CreatedAt); err != nil {
			return err
		}
		e.Source = "user"
		byOrg[e.OrgID] = append(byOrg[e.OrgID], e)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	s.byOrg = byOrg
	s.mu.Unlock()
	return nil
}

// List returns user-defined never-baseline entries for the given org.
func (s *NeverBaselineStore) List(ctx context.Context, orgID string) ([]NeverBaselineEntry, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	entries := append([]NeverBaselineEntry(nil), s.byOrg[orgID]...)
	s.mu.RUnlock()
	return entries, nil
}

// Add inserts a new user-defined never-baseline entry.
// Returns ErrPatternAlreadyBaselined if existing baselines conflict.
func (s *NeverBaselineStore) Add(ctx context.Context, orgID, signalType, pattern, description, createdBy string) (*NeverBaselineEntry, error) {
	if s == nil {
		return nil, fmt.Errorf("never_baseline_store is nil")
	}

	// Conflict check: look for existing baselines that would suppress this pattern.
	conflictRows, err := s.db.QueryContext(ctx,
		`SELECT id FROM behavioral_baselines WHERE org_id = $1 AND signal_type = $2 AND pattern = $3`,
		orgID, signalType, pattern)
	if err != nil {
		return nil, fmt.Errorf("conflict check: %w", err)
	}
	var conflictIDs []int
	for conflictRows.Next() {
		var id int
		if scanErr := conflictRows.Scan(&id); scanErr == nil {
			conflictIDs = append(conflictIDs, id)
		}
	}
	conflictRows.Close()
	if len(conflictIDs) > 0 {
		return nil, ErrPatternAlreadyBaselined{BaselineIDs: conflictIDs}
	}

	var e NeverBaselineEntry
	err = s.db.QueryRowContext(ctx,
		`INSERT INTO org_never_baselines (org_id, signal_type, pattern, description, created_by)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (org_id, signal_type, pattern) DO UPDATE
		   SET description = EXCLUDED.description, created_by = EXCLUDED.created_by
		 RETURNING id, org_id, signal_type, pattern, description, created_by, created_at`,
		orgID, signalType, pattern, description, createdBy,
	).Scan(&e.ID, &e.OrgID, &e.SignalType, &e.Pattern, &e.Description, &e.CreatedBy, &e.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert never-baseline: %w", err)
	}
	e.Source = "user"

	_ = s.reload(ctx)
	return &e, nil
}

// Delete removes a user-defined never-baseline entry (org-scoped).
func (s *NeverBaselineStore) Delete(ctx context.Context, orgID string, id int) error {
	if s == nil {
		return fmt.Errorf("never_baseline_store is nil")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM org_never_baselines WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("never-baseline %d not found for org %s", id, orgID)
	}
	_ = s.reload(ctx)
	return nil
}

// MatchesAny returns true if the given signal_type+pattern has a user-defined
// never-baseline entry for the org. Uses exact string match (v1).
func (s *NeverBaselineStore) MatchesAny(orgID, signalType, pattern string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.byOrg[orgID] {
		if e.SignalType == signalType && e.Pattern == pattern {
			return true
		}
	}
	return false
}

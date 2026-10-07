package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/correlic/correlic-backend/internal/detection"
)

// RuleException represents a per-rule suppression entry.
type RuleException struct {
	ID           int64
	OrgID        string
	DetectionID  string // "ai.credential_access" or "*" for all rules
	HostID       string // specific host or "*" for all hosts
	ContextKey   string // context field to filter on; "" means no context filter
	ContextValue string // required value; "" means any non-empty value
	MatchMode    string // "exact" (default) or "prefix"
	Reason       string
	CreatedAt    time.Time
}

// RuleExceptionStore caches per-org exceptions and provides fast in-memory matching.
// It implements detection.ExceptionChecker.
type RuleExceptionStore struct {
	db *sql.DB

	mu         sync.RWMutex
	byOrg      map[string][]RuleException // orgID → exceptions
	lastReload time.Time
	done       chan struct{}
}

// NewRuleExceptionStore creates a store, loads exceptions, and starts background refresh.
func NewRuleExceptionStore(db *sql.DB) *RuleExceptionStore {
	s := &RuleExceptionStore{
		db:    db,
		byOrg: make(map[string][]RuleException),
		done:  make(chan struct{}),
	}
	if err := s.reload(context.Background()); err != nil {
		log.Printf("WARN: rule_exception_store initial load failed: %v", err)
	}
	go s.backgroundRefresh()
	return s
}

// Stop signals the background refresh goroutine to exit.
func (s *RuleExceptionStore) Stop() {
	close(s.done)
}

func (s *RuleExceptionStore) backgroundRefresh() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if err := s.reload(context.Background()); err != nil {
				log.Printf("WARN: rule_exception_store refresh failed: %v", err)
			}
		}
	}
}

func (s *RuleExceptionStore) reload(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, org_id, detection_id, host_id, context_key, context_value, COALESCE(match_mode, 'exact'), reason, created_at
		 FROM rule_exceptions ORDER BY org_id, id`)
	if err != nil {
		return fmt.Errorf("query rule_exceptions: %w", err)
	}
	defer rows.Close()

	byOrg := make(map[string][]RuleException)
	for rows.Next() {
		var e RuleException
		if err := rows.Scan(&e.ID, &e.OrgID, &e.DetectionID, &e.HostID,
			&e.ContextKey, &e.ContextValue, &e.MatchMode, &e.Reason, &e.CreatedAt); err != nil {
			continue
		}
		byOrg[e.OrgID] = append(byOrg[e.OrgID], e)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	s.byOrg = byOrg
	s.lastReload = time.Now()
	s.mu.Unlock()
	return nil
}

// Matches returns true if the finding is suppressed by any exception for the org.
// Implements detection.ExceptionChecker.
func (s *RuleExceptionStore) Matches(orgID string, f detection.Finding) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	exceptions := s.byOrg[orgID]
	s.mu.RUnlock()

	for _, e := range exceptions {
		// detection_id must match or be "*"
		if e.DetectionID != "*" && e.DetectionID != f.DetectionID {
			continue
		}
		// host_id must match or be "*"
		if e.HostID != "*" && e.HostID != f.HostID {
			continue
		}
		// context filter: if key is set, finding must have matching context value
		if e.ContextKey != "" {
			val, ok := f.Context[e.ContextKey]
			if !ok {
				continue
			}
			if e.ContextValue != "" {
				valStr := fmt.Sprintf("%v", val)
				if e.MatchMode == "prefix" {
					if !strings.HasPrefix(valStr, e.ContextValue) {
						continue
					}
				} else {
					if valStr != e.ContextValue {
						continue
					}
				}
			}
		}
		return true
	}
	return false
}

// List returns all exceptions for an org.
func (s *RuleExceptionStore) List(orgID string) []RuleException {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]RuleException, len(s.byOrg[orgID]))
	copy(result, s.byOrg[orgID])
	return result
}

// Insert adds a new exception to the database and reloads the cache.
func (s *RuleExceptionStore) Insert(ctx context.Context, e RuleException) (int64, error) {
	var id int64
	matchMode := e.MatchMode
	if matchMode == "" {
		matchMode = "exact"
	}
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO rule_exceptions (org_id, detection_id, host_id, context_key, context_value, match_mode, reason)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		e.OrgID, e.DetectionID, e.HostID, e.ContextKey, e.ContextValue, matchMode, e.Reason,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert rule_exception: %w", err)
	}
	_ = s.reload(ctx)
	return id, nil
}

// Delete removes an exception by ID (org-scoped for safety) and reloads.
func (s *RuleExceptionStore) Delete(ctx context.Context, orgID string, id int64) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM rule_exceptions WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return fmt.Errorf("delete rule_exception: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("rule_exception %d not found for org %s", id, orgID)
	}
	_ = s.reload(ctx)
	return nil
}

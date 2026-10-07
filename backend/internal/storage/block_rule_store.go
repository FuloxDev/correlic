package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// BlockRule is a user- or system-defined soft-block rule.
type BlockRule struct {
	ID          int       `json:"id"`
	OrgID       string    `json:"org_id"`
	SignalType  string    `json:"signal_type"`  // process_exec | net_connect | file_open
	Pattern     string    `json:"pattern"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	KillTree    bool      `json:"kill_tree"`
	Source      string    `json:"source"`     // user | system
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// BlockRuleStore is an org-scoped, in-memory-cached store for block rules.
type BlockRuleStore struct {
	db    *sql.DB
	mu    sync.RWMutex
	byOrg map[string][]BlockRule // orgID → rules
	done  chan struct{}
}

func NewBlockRuleStore(db *sql.DB) *BlockRuleStore {
	s := &BlockRuleStore{
		db:    db,
		byOrg: make(map[string][]BlockRule),
		done:  make(chan struct{}),
	}
	if err := s.reload(context.Background()); err != nil {
		log.Printf("WARN: block_rule_store initial load: %v", err)
	}
	go s.refreshLoop()
	return s
}

func (s *BlockRuleStore) Stop() {
	if s == nil {
		return
	}
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

func (s *BlockRuleStore) refreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if err := s.reload(context.Background()); err != nil {
				log.Printf("WARN: block_rule_store refresh: %v", err)
			}
		}
	}
}

func (s *BlockRuleStore) reload(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, org_id, signal_type, pattern, description, enabled, kill_tree, source, created_by, created_at, updated_at
		 FROM block_rules ORDER BY org_id, id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	byOrg := make(map[string][]BlockRule)
	for rows.Next() {
		var r BlockRule
		if err := rows.Scan(&r.ID, &r.OrgID, &r.SignalType, &r.Pattern, &r.Description,
			&r.Enabled, &r.KillTree, &r.Source, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return err
		}
		byOrg[r.OrgID] = append(byOrg[r.OrgID], r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	s.byOrg = byOrg
	s.mu.Unlock()
	return nil
}

// List returns all block rules for the given org.
func (s *BlockRuleStore) List(ctx context.Context, orgID string) ([]BlockRule, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	rules := append([]BlockRule(nil), s.byOrg[orgID]...)
	s.mu.RUnlock()
	return rules, nil
}

// ListEnabled returns only enabled block rules for the given org.
func (s *BlockRuleStore) ListEnabled(ctx context.Context, orgID string) ([]BlockRule, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	var out []BlockRule
	for _, r := range s.byOrg[orgID] {
		if r.Enabled {
			out = append(out, r)
		}
	}
	s.mu.RUnlock()
	return out, nil
}

// Add inserts a new block rule.
func (s *BlockRuleStore) Add(ctx context.Context, orgID, signalType, pattern, description string, killTree bool, createdBy string) (*BlockRule, error) {
	if s == nil {
		return nil, fmt.Errorf("block_rule_store is nil")
	}

	var r BlockRule
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO block_rules (org_id, signal_type, pattern, description, enabled, kill_tree, source, created_by)
		 VALUES ($1, $2, $3, $4, true, $5, 'user', $6)
		 ON CONFLICT (org_id, signal_type, pattern) DO UPDATE
		   SET description = EXCLUDED.description, kill_tree = EXCLUDED.kill_tree,
		       created_by = EXCLUDED.created_by, updated_at = now()
		 RETURNING id, org_id, signal_type, pattern, description, enabled, kill_tree, source, created_by, created_at, updated_at`,
		orgID, signalType, pattern, description, killTree, createdBy,
	).Scan(&r.ID, &r.OrgID, &r.SignalType, &r.Pattern, &r.Description,
		&r.Enabled, &r.KillTree, &r.Source, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert block_rule: %w", err)
	}

	_ = s.reload(ctx)
	return &r, nil
}

// Delete removes a block rule (org-scoped).
func (s *BlockRuleStore) Delete(ctx context.Context, orgID string, id int) error {
	if s == nil {
		return fmt.Errorf("block_rule_store is nil")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM block_rules WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("block_rule %d not found for org %s", id, orgID)
	}
	_ = s.reload(ctx)
	return nil
}

// Toggle updates the enabled flag of a block rule.
func (s *BlockRuleStore) Toggle(ctx context.Context, orgID string, id int, enabled bool) error {
	if s == nil {
		return fmt.Errorf("block_rule_store is nil")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE block_rules SET enabled = $1, updated_at = now() WHERE id = $2 AND org_id = $3`,
		enabled, id, orgID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("block_rule %d not found for org %s", id, orgID)
	}
	_ = s.reload(ctx)
	return nil
}

// MatchesAny checks if a candidate matches any enabled rule for the given org.
// For process_exec: matches exe basename case-insensitively.
// For net_connect: matches IP:port or IP-only.
// For file_open: matches with filepath.Match glob.
func (s *BlockRuleStore) MatchesAny(orgID, signalType, candidate string) (bool, *BlockRule) {
	if s == nil {
		return false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i, r := range s.byOrg[orgID] {
		if !r.Enabled || r.SignalType != signalType {
			continue
		}
		if matchesRule(signalType, r.Pattern, candidate) {
			return true, &s.byOrg[orgID][i]
		}
	}
	return false, nil
}

func matchesRule(signalType, pattern, candidate string) bool {
	switch signalType {
	case "process_exec":
		// Match exe basename case-insensitively.
		candidateBase := filepath.Base(candidate)
		return strings.EqualFold(candidateBase, pattern)
	case "net_connect":
		// Match IP:port exactly, or IP-only (pattern without port matches any port).
		if strings.EqualFold(candidate, pattern) {
			return true
		}
		// If pattern has no port, match just the IP part.
		if !strings.Contains(pattern, ":") {
			host, _, err := net.SplitHostPort(candidate)
			if err != nil {
				return strings.EqualFold(candidate, pattern)
			}
			return strings.EqualFold(host, pattern)
		}
		return false
	case "file_open":
		// Match with filepath.Match glob.
		matched, err := filepath.Match(pattern, candidate)
		if err != nil {
			return false
		}
		return matched
	default:
		return strings.EqualFold(candidate, pattern)
	}
}

// VersionHash returns a SHA256 hash of all enabled rules for the given org,
// suitable for ETag-style polling.
func (s *BlockRuleStore) VersionHash(orgID string) string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	var enabled []BlockRule
	for _, r := range s.byOrg[orgID] {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	s.mu.RUnlock()

	// Sort by ID for deterministic hashing.
	sort.Slice(enabled, func(i, j int) bool { return enabled[i].ID < enabled[j].ID })

	h := sha256.New()
	for _, r := range enabled {
		fmt.Fprintf(h, "%d|%s|%s|%s|%v\n", r.ID, r.SignalType, r.Pattern, r.Description, r.KillTree)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

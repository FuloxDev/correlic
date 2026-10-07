package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

type SafeDomain struct {
	ID          string
	Domain      string
	Description string
	CreatedAt   time.Time
}

type SafeDomainStore struct {
	db *sql.DB

	mu      sync.RWMutex
	domains []string // Cached list of domains (e.g. "api.openai.com", "github.com")
}

func NewSafeDomainStore(db *sql.DB) *SafeDomainStore {
	store := &SafeDomainStore{
		db:      db,
		domains: []string{},
	}
	// Initial load
	store.ReloadCache(context.Background())
	return store
}

// ReloadCache fetches the latest safe domains from the database.
func (s *SafeDomainStore) ReloadCache(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT domain FROM safe_domains_list")
	if err != nil {
		return err
	}
	defer rows.Close()

	var newDomains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			continue
		}
		newDomains = append(newDomains, strings.ToLower(domain))
	}

	if err := rows.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	s.domains = newDomains
	s.mu.Unlock()

	return nil
}

// GetCachedDomains returns a copy of the current safe domain list.
func (s *SafeDomainStore) GetCachedDomains() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, len(s.domains))
	copy(result, s.domains)
	return result
}

// IsSafe checks if a given domain ends with any of the safe domains.
// e.g. "api.openai.com" matches "openai.com" or exactly "api.openai.com".
func (s *SafeDomainStore) IsSafe(targetDomain string) bool {
	if targetDomain == "" {
		return false
	}
	targetDomain = strings.ToLower(targetDomain)

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, safe := range s.domains {
		if targetDomain == safe || strings.HasSuffix(targetDomain, "."+safe) {
			return true
		}
	}
	return false
}

// Add inserts a new safe domain and reloads the cache.
func (s *SafeDomainStore) Add(ctx context.Context, domain, description string) (*SafeDomain, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	var d SafeDomain
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO safe_domains_list (domain, description) VALUES ($1, $2)
		 ON CONFLICT (domain) DO UPDATE SET description = EXCLUDED.description
		 RETURNING id, domain, description, created_at`,
		domain, description,
	).Scan(&d.ID, &d.Domain, &d.Description, &d.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert safe domain: %w", err)
	}

	_ = s.ReloadCache(ctx)
	return &d, nil
}

// Delete removes a safe domain by ID and reloads the cache.
func (s *SafeDomainStore) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM safe_domains_list WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete safe domain: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("safe domain not found")
	}
	_ = s.ReloadCache(ctx)
	return nil
}

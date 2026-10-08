package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrSafeDomainNotFound is returned when a delete targets a domain the org does not own
// (including built-in rows, which are read-only).
var ErrSafeDomainNotFound = errors.New("safe domain not found")

// SafeDomain is one allowlisted domain. OrgID is empty for built-in (seeded) rows,
// which every org sees and no org can delete.
type SafeDomain struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id,omitempty"`
	Domain      string    `json:"domain"`
	Description string    `json:"description"`
	BuiltIn     bool      `json:"built_in"`
	CreatedAt   time.Time `json:"created_at"`
}

// SafeDomainStore caches safe_domains_list in memory. Rows with org_id NULL are
// built-ins shared by all tenants; rows with an org_id belong to that tenant only.
type SafeDomainStore struct {
	db *sql.DB

	mu       sync.RWMutex
	builtins []string            // org_id IS NULL
	perOrg   map[string][]string // org_id → domains
}

func NewSafeDomainStore(db *sql.DB) *SafeDomainStore {
	store := &SafeDomainStore{
		db:       db,
		builtins: []string{},
		perOrg:   map[string][]string{},
	}
	// Initial load
	_ = store.ReloadCache(context.Background())
	return store
}

// ReloadCache fetches the latest safe domains from the database.
func (s *SafeDomainStore) ReloadCache(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT domain, org_id::text FROM safe_domains_list")
	if err != nil {
		return err
	}
	defer rows.Close()

	builtins := []string{}
	perOrg := map[string][]string{}
	for rows.Next() {
		var domain string
		var orgID sql.NullString
		if err := rows.Scan(&domain, &orgID); err != nil {
			continue
		}
		domain = strings.ToLower(domain)
		if orgID.Valid && orgID.String != "" {
			perOrg[orgID.String] = append(perOrg[orgID.String], domain)
		} else {
			builtins = append(builtins, domain)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	s.builtins = builtins
	s.perOrg = perOrg
	s.mu.Unlock()
	return nil
}

// GetCachedDomains returns every cached domain (built-ins and all orgs). Prefer
// GetCachedDomainsForOrg where the tenant is known.
func (s *SafeDomainStore) GetCachedDomains() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, 0, len(s.builtins))
	result = append(result, s.builtins...)
	for _, ds := range s.perOrg {
		result = append(result, ds...)
	}
	return result
}

// GetCachedDomainsForOrg returns built-in domains plus orgID's own.
func (s *SafeDomainStore) GetCachedDomainsForOrg(orgID string) []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, 0, len(s.builtins)+len(s.perOrg[orgID]))
	result = append(result, s.builtins...)
	result = append(result, s.perOrg[orgID]...)
	return result
}

func matchesSafeList(targetDomain string, safe []string) bool {
	for _, d := range safe {
		if targetDomain == d || strings.HasSuffix(targetDomain, "."+d) {
			return true
		}
	}
	return false
}

// IsSafe checks targetDomain against built-ins and every org's list. It exists for
// callers without tenant context; detection uses ForOrg(orgID).
func (s *SafeDomainStore) IsSafe(targetDomain string) bool {
	if s == nil || targetDomain == "" {
		return false
	}
	targetDomain = strings.ToLower(targetDomain)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if matchesSafeList(targetDomain, s.builtins) {
		return true
	}
	for _, ds := range s.perOrg {
		if matchesSafeList(targetDomain, ds) {
			return true
		}
	}
	return false
}

// IsSafeForOrg checks targetDomain against built-ins plus orgID's own domains.
// e.g. "api.openai.com" matches "openai.com" or exactly "api.openai.com".
func (s *SafeDomainStore) IsSafeForOrg(orgID, targetDomain string) bool {
	if s == nil || targetDomain == "" {
		return false
	}
	targetDomain = strings.ToLower(targetDomain)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return matchesSafeList(targetDomain, s.builtins) || matchesSafeList(targetDomain, s.perOrg[orgID])
}

// OrgSafeDomainChecker is a tenant-bound view of a SafeDomainStore; it satisfies
// detection.SafeDomainChecker.
type OrgSafeDomainChecker struct {
	store *SafeDomainStore
	orgID string
}

// IsSafe reports whether domain is allowlisted for the bound org.
func (c *OrgSafeDomainChecker) IsSafe(domain string) bool {
	if c == nil || c.store == nil {
		return false
	}
	return c.store.IsSafeForOrg(c.orgID, domain)
}

// ForOrg returns a checker scoped to orgID. Nil-safe: a nil store yields a checker
// that never matches.
func (s *SafeDomainStore) ForOrg(orgID string) *OrgSafeDomainChecker {
	return &OrgSafeDomainChecker{store: s, orgID: orgID}
}

// ListForOrg returns built-in domains plus the ones orgID added, ordered by domain.
func (s *SafeDomainStore) ListForOrg(ctx context.Context, orgID string) ([]SafeDomain, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(org_id::text, ''), domain, COALESCE(description, ''), created_at
		FROM safe_domains_list
		WHERE org_id IS NULL OR org_id::text = $1
		ORDER BY domain ASC
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list safe domains: %w", err)
	}
	defer rows.Close()

	out := []SafeDomain{}
	for rows.Next() {
		var d SafeDomain
		if err := rows.Scan(&d.ID, &d.OrgID, &d.Domain, &d.Description, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.BuiltIn = d.OrgID == ""
		out = append(out, d)
	}
	return out, rows.Err()
}

// Add inserts (or updates the description of) a safe domain owned by orgID and
// reloads the cache. The org is required: built-ins are only created by migrations.
func (s *SafeDomainStore) Add(ctx context.Context, orgID, domain, description string) (*SafeDomain, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, ErrOrgRequired
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	var d SafeDomain
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO safe_domains_list (org_id, domain, description) VALUES ($1::uuid, $2, $3)
		 ON CONFLICT (COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid), domain)
		 DO UPDATE SET description = EXCLUDED.description
		 RETURNING id, COALESCE(org_id::text, ''), domain, COALESCE(description, ''), created_at`,
		orgID, domain, description,
	).Scan(&d.ID, &d.OrgID, &d.Domain, &d.Description, &d.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert safe domain: %w", err)
	}

	_ = s.ReloadCache(ctx)
	return &d, nil
}

// Delete removes a safe domain by ID if orgID owns it, then reloads the cache.
// Built-in rows (org_id NULL) and other orgs' rows return ErrSafeDomainNotFound.
func (s *SafeDomainStore) Delete(ctx context.Context, orgID, id string) error {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return ErrOrgRequired
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM safe_domains_list WHERE id = $1 AND org_id::text = $2`, id, orgID)
	if err != nil {
		return fmt.Errorf("delete safe domain: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrSafeDomainNotFound
	}
	_ = s.ReloadCache(ctx)
	return nil
}

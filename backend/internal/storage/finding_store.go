package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotFound is returned when a finding does not exist or does not belong to the given org.
var ErrNotFound = errors.New("finding not found")

// FindingRow represents a finding stored in PostgreSQL.
type FindingRow struct {
	ID            string         `json:"id"`
	OrgID         string         `json:"org_id"`
	DetectionID   string         `json:"detection_id"`
	HostID        string         `json:"host_id"`
	Severity      string         `json:"severity"`
	Confidence    float64        `json:"confidence"`
	Title         string         `json:"title"`
	Summary       string         `json:"summary"`
	AnchorEvent   string         `json:"anchor_event"`
	RelatedEvents []string       `json:"related_events"`
	Context       map[string]any `json:"context"`
	Status        string         `json:"status"`
	Resolution    *string        `json:"resolution,omitempty"`
	ResolvedBy    *string        `json:"resolved_by,omitempty"`
	ResolvedAt    *time.Time     `json:"resolved_at,omitempty"`
	Suppressed    bool           `json:"suppressed"`
	BaselineMatch *string        `json:"baseline_match,omitempty"`
	IncidentID    *string        `json:"incident_id,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

// FindingStore handles persistence of detection findings.
type FindingStore struct {
	db *sql.DB
}

// NewFindingStore creates a new finding store.
func NewFindingStore(db *sql.DB) *FindingStore {
	return &FindingStore{db: db}
}

// Insert stores a new finding.
func (s *FindingStore) Insert(f FindingRow) error {
	contextJSON, err := json.Marshal(f.Context)
	if err != nil {
		contextJSON = []byte("{}")
	}

	relatedArr := pgTextArray(f.RelatedEvents)

	_, err = s.db.Exec(`
		INSERT INTO findings (id, org_id, detection_id, host_id, severity, confidence, title, summary,
			anchor_event, related_events, context, status, suppressed, baseline_match, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (id) DO NOTHING
	`,
		f.ID, f.OrgID, f.DetectionID, f.HostID, f.Severity, f.Confidence, f.Title, f.Summary,
		f.AnchorEvent, relatedArr, contextJSON,
		f.Status, f.Suppressed, f.BaselineMatch, f.CreatedAt,
	)
	return err
}

// ListByHost returns findings for a host, optionally filtered by status.
// By default, suppressed findings are excluded. Set showSuppressed=true to include them.
func (s *FindingStore) ListByHost(orgID, hostID string, status string, since time.Time, limit int, showSuppressed bool) ([]FindingRow, error) {
	query := `
		SELECT id, COALESCE(org_id, '') as org_id, detection_id, host_id, severity, confidence, title, summary,
		       anchor_event, related_events, context, status,
		       resolution, resolved_by, resolved_at,
		       suppressed, baseline_match, incident_id, created_at
		FROM findings
		WHERE host_id = $1 AND created_at >= $2 AND org_id = $3
	`
	args := []any{hostID, since, orgID}
	argN := 3

	if !showSuppressed {
		argN++
		query += fmt.Sprintf(" AND suppressed = $%d", argN)
		args = append(args, false)
	}

	if status != "" {
		argN++
		query += fmt.Sprintf(" AND status = $%d", argN)
		args = append(args, status)
	}

	query += " ORDER BY created_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanFindings(rows)
}

// ListAll returns findings optionally filtered by status (no host_id required).
// By default, suppressed findings are excluded. Set showSuppressed=true to include them.
func (s *FindingStore) ListAll(orgID string, status string, since time.Time, limit int, showSuppressed bool) ([]FindingRow, error) {
	query := `
		SELECT id, COALESCE(org_id, '') as org_id, detection_id, host_id, severity, confidence, title, summary,
		       anchor_event, related_events, context, status,
		       resolution, resolved_by, resolved_at,
		       suppressed, baseline_match, incident_id, created_at
		FROM findings
		WHERE created_at >= $1 AND org_id = $2
	`
	args := []any{since, orgID}
	argN := 2

	if !showSuppressed {
		argN++
		query += fmt.Sprintf(" AND suppressed = $%d", argN)
		args = append(args, false)
	}

	if status != "" {
		argN++
		query += fmt.Sprintf(" AND status = $%d", argN)
		args = append(args, status)
	}

	query += " ORDER BY created_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanFindings(rows)
}

// FindingCounts holds aggregated finding counts for the dashboard.
type FindingCounts struct {
	Total         int `json:"total"`
	Pending       int `json:"pending"`
	Allowed       int `json:"allowed"`
	Dismissed     int `json:"dismissed"`
	AutoResolved  int `json:"auto_resolved"`
	Investigating int `json:"investigating"`
	Suppressed    int `json:"suppressed"`
}

// CountByStatus returns aggregated finding counts since a given time.
func (s *FindingStore) CountByStatus(orgID string, since time.Time) (FindingCounts, error) {
	var c FindingCounts
	rows, err := s.db.Query(`
		SELECT status, COUNT(*) FROM findings
		WHERE created_at >= $1 AND org_id = $2
		GROUP BY status
	`, since, orgID)
	if err != nil {
		return c, err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			continue
		}
		c.Total += count
		switch status {
		case "pending":
			c.Pending = count
		case "allowed":
			c.Allowed = count
		case "dismissed":
			c.Dismissed = count
		case "auto_resolved":
			c.AutoResolved = count
		case "investigating":
			c.Investigating = count
		}
	}

	// Count suppressed separately — suppressed findings still have status='pending'
	// so subtract them from Pending to get the actionable pending count.
	s.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE created_at >= $1 AND org_id = $2 AND suppressed = true AND status = 'pending'`, since, orgID).Scan(&c.Suppressed)
	c.Pending -= c.Suppressed
	if c.Pending < 0 {
		c.Pending = 0
	}

	return c, nil
}

// UpdateStatus changes the status of a finding (allow/dismiss/investigate).
// Org-scoped: only updates findings belonging to the given org.
// Returns ErrNotFound if the finding does not exist or does not belong to the org.
// BatchUpdateStatus sets the status of multiple findings in a single query.
// Returns the number of rows updated. Not org-scoped — caller must have already
// verified ownership (used by reconcile which processes its own org's findings).
func (s *FindingStore) BatchUpdateStatus(ids []string, status, resolution, resolvedBy string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	now := time.Now()
	placeholders := make([]string, len(ids))
	args := []any{status, resolution, resolvedBy, now}
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+5)
		args = append(args, id)
	}
	query := fmt.Sprintf(
		`UPDATE findings SET status = $1, resolution = $2, resolved_by = $3, resolved_at = $4 WHERE id IN (%s)`,
		strings.Join(placeholders, ", "))
	result, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return n, nil
}

func (s *FindingStore) UpdateStatus(orgID, id, status, resolution, resolvedBy string) error {
	now := time.Now()
	result, err := s.db.Exec(`
		UPDATE findings
		SET status = $2, resolution = $3, resolved_by = $4, resolved_at = $5
		WHERE id = $1 AND org_id = $6
	`, id, status, resolution, resolvedBy, now, orgID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetByID returns a single finding, scoped to the given org.
func (s *FindingStore) GetByID(orgID, id string) (*FindingRow, error) {
	row := s.db.QueryRow(`
		SELECT id, COALESCE(org_id, '') as org_id, detection_id, host_id, severity, confidence, title, summary,
		       anchor_event, related_events, context, status,
		       resolution, resolved_by, resolved_at,
		       suppressed, baseline_match, incident_id, created_at
		FROM findings
		WHERE id = $1 AND org_id = $2
	`, id, orgID)

	f := &FindingRow{}
	var relatedStr *string
	var contextJSON []byte
	err := row.Scan(
		&f.ID, &f.OrgID, &f.DetectionID, &f.HostID, &f.Severity, &f.Confidence, &f.Title, &f.Summary,
		&f.AnchorEvent, &relatedStr, &contextJSON, &f.Status,
		&f.Resolution, &f.ResolvedBy, &f.ResolvedAt,
		&f.Suppressed, &f.BaselineMatch, &f.IncidentID, &f.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if relatedStr != nil {
		f.RelatedEvents = parsePgTextArray(*relatedStr)
	}
	if len(contextJSON) > 0 {
		if err := json.Unmarshal(contextJSON, &f.Context); err != nil {
			log.Printf("WARN: finding context unmarshal failed for %s: %v", f.ID, err)
		}
	}
	return f, nil
}

func scanFindings(rows *sql.Rows) ([]FindingRow, error) {
	var findings []FindingRow
	for rows.Next() {
		var f FindingRow
		var relatedStr *string
		var contextJSON []byte
		err := rows.Scan(
			&f.ID, &f.OrgID, &f.DetectionID, &f.HostID, &f.Severity, &f.Confidence, &f.Title, &f.Summary,
			&f.AnchorEvent, &relatedStr, &contextJSON, &f.Status,
			&f.Resolution, &f.ResolvedBy, &f.ResolvedAt,
			&f.Suppressed, &f.BaselineMatch, &f.IncidentID, &f.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		if relatedStr != nil {
			f.RelatedEvents = parsePgTextArray(*relatedStr)
		}
		if len(contextJSON) > 0 {
			if err := json.Unmarshal(contextJSON, &f.Context); err != nil {
				log.Printf("WARN: finding context unmarshal failed for %s: %v", f.ID, err)
			}
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// SetIncidentID links a finding to an incident.
func (s *FindingStore) SetIncidentID(orgID, findingID, incidentID string) error {
	_, err := s.db.Exec(`
		UPDATE findings SET incident_id = $1
		WHERE id = $2 AND org_id = $3
	`, incidentID, findingID, orgID)
	return err
}

// CountPendingByIncident returns the number of unresolved findings for an incident.
// Unresolved = status NOT IN ('allowed', 'dismissed', 'resolved', 'auto_resolved').
func (s *FindingStore) CountPendingByIncident(orgID, incidentID string) (int, error) {
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM findings
		WHERE incident_id = $1 AND org_id = $2
		  AND status NOT IN ('allowed', 'dismissed', 'resolved', 'auto_resolved')
	`, incidentID, orgID).Scan(&count)
	return count, err
}

// UpdateContext updates the context JSONB column for a finding.
func (s *FindingStore) UpdateContext(orgID, findingID string, ctx map[string]any) error {
	contextJSON, err := json.Marshal(ctx)
	if err != nil {
		return fmt.Errorf("marshal context: %w", err)
	}
	_, err = s.db.Exec(`
		UPDATE findings SET context = $1
		WHERE id = $2 AND org_id = $3
	`, contextJSON, findingID, orgID)
	return err
}

// ErrOrgRequired is returned by tenant-scoped writes that were called without an org.
var ErrOrgRequired = errors.New("org id is required")

// AutoResolveBySafeDomainForOrg retroactively resolves orgID's pending network-related
// findings whose domain context matches the given safe domain (exact or suffix match,
// mirroring SafeDomainStore.IsSafe() logic). Returns the count of resolved findings and
// the distinct org IDs touched (always just orgID) for incident reconciliation.
func (s *FindingStore) AutoResolveBySafeDomainForOrg(orgID, domain string) (int64, []string, error) {
	if strings.TrimSpace(orgID) == "" {
		return 0, nil, ErrOrgRequired
	}
	return s.autoResolveBySafeDomain(orgID, domain)
}

// AutoResolveBySafeDomain resolves matching pending findings in EVERY org.
//
// Deprecated: use AutoResolveBySafeDomainForOrg. Kept only for callers that predate
// org scoping; safe-domain rows are per-org now, so cross-org resolution is wrong.
func (s *FindingStore) AutoResolveBySafeDomain(domain string) (int64, []string, error) {
	return s.autoResolveBySafeDomain("", domain)
}

func (s *FindingStore) autoResolveBySafeDomain(orgID, domain string) (int64, []string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return 0, nil, nil
	}

	suffixPattern := "%." + domain

	rows, err := s.db.Query(`
		WITH resolved AS (
			UPDATE findings
			SET status = 'auto_resolved',
				resolution = 'safe domain suppression',
				resolved_by = 'system',
				resolved_at = NOW()
			WHERE status = 'pending'
			  AND ($3 = '' OR org_id = $3)
			  AND detection_id IN ('ai.unexpected_network', 'ai.data_exfiltration', 'ai.suspicious_dns')
			  AND (
				LOWER(context->>'domain') = $1
				OR LOWER(context->>'domain') LIKE $2
				OR LOWER(context->>'dns_domain') = $1
				OR LOWER(context->>'dns_domain') LIKE $2
				OR LOWER(context->>'dns_query') = $1
				OR LOWER(context->>'dns_query') LIKE $2
			  )
			RETURNING COALESCE(org_id, '') AS org_id
		)
		SELECT DISTINCT org_id FROM resolved
	`, domain, suffixPattern, strings.TrimSpace(orgID))
	if err != nil {
		return 0, nil, fmt.Errorf("auto-resolve by safe domain: %w", err)
	}
	defer rows.Close()

	var orgIDs []string
	var count int64
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			continue
		}
		orgIDs = append(orgIDs, orgID)
		count++
	}
	return count, orgIDs, rows.Err()
}

// AutoResolveByBaseline retroactively resolves all pending findings that match a
// newly confirmed baseline pattern. Supports both exact pattern match and directory
// prefix match (for glob patterns ending with /**).
//
// For file_pattern directory globs (e.g. /home/user/**), matches findings across
// ALL file-related signal types — a directory baseline suppresses code_tamper,
// credential_file, persistence_path, etc. findings under that path. This mirrors
// the detection-time behavior where IsFileBaselined() is called for all file signal types.
//
// Returns the count of resolved findings and distinct org IDs.
func (s *FindingStore) AutoResolveByBaseline(orgID, hostID, signalType, pattern string) (int64, []string, error) {
	if strings.TrimSpace(orgID) == "" {
		return 0, nil, ErrOrgRequired
	}
	if signalType == "" || pattern == "" {
		return 0, nil, nil
	}

	// Normalize Windows backslashes so SQL LIKE matches forward-slash paths from the agent.
	pattern = filepath.ToSlash(pattern)

	dirPrefix := ""
	if strings.HasSuffix(pattern, "/**") {
		dirPrefix = strings.TrimSuffix(pattern, "**")
	}

	var rows *sql.Rows
	var err error

	if dirPrefix != "" && (signalType == "file_pattern" || signalType == "file_activity") {
		// file directory glob: match across all file-related signal types.
		// The finding's pattern is the exact file path (e.g. /home/alice/.next/.../file.js)
		// so we match with LIKE dirPrefix% to catch all files under the directory.
		rows, err = s.db.Query(`
			WITH resolved AS (
				UPDATE findings
				SET status = 'auto_resolved',
					resolution = 'baseline suppression',
					resolved_by = 'system',
					resolved_at = NOW()
				WHERE status = 'pending'
				  AND org_id = $1
				  AND ($2 = '*' OR host_id = $2)
				  AND context->>'signal_type' IN ('file_pattern', 'credential_file', 'persistence_path', 'code_tamper', 'file_write_burst', 'file_activity')
				  AND (
					context->>'pattern' = $3
					OR context->>'pattern' LIKE $4 || '%'
				  )
				RETURNING COALESCE(org_id, '') AS org_id
			)
			SELECT DISTINCT org_id FROM resolved
		`, orgID, hostID, pattern, dirPrefix)
	} else if signalType == "command_binary" {
		// Binary baseline: resolve all findings where binary name matches,
		// regardless of which detection rule produced them (command_activity,
		// unauthorized_exec, privilege_escalation, etc.).
		rows, err = s.db.Query(`
			WITH resolved AS (
				UPDATE findings
				SET status = 'auto_resolved',
					resolution = 'baseline suppression',
					resolved_by = 'system',
					resolved_at = NOW()
				WHERE status = 'pending'
				  AND org_id = $1
				  AND ($2 = '*' OR host_id = $2)
				  AND context->>'binary' = $3
				RETURNING COALESCE(org_id, '') AS org_id
			)
			SELECT DISTINCT org_id FROM resolved
		`, orgID, hostID, pattern)
	} else {
		// Exact signal_type + pattern match (including non-file or non-directory patterns)
		rows, err = s.db.Query(`
			WITH resolved AS (
				UPDATE findings
				SET status = 'auto_resolved',
					resolution = 'baseline suppression',
					resolved_by = 'system',
					resolved_at = NOW()
				WHERE status = 'pending'
				  AND org_id = $1
				  AND ($2 = '*' OR host_id = $2)
				  AND context->>'signal_type' = $3
				  AND context->>'pattern' = $4
				RETURNING COALESCE(org_id, '') AS org_id
			)
			SELECT DISTINCT org_id FROM resolved
		`, orgID, hostID, signalType, pattern)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("auto-resolve by baseline: %w", err)
	}
	defer rows.Close()

	var orgIDs []string
	var count int64
	for rows.Next() {
		var orgID string
		if err := rows.Scan(&orgID); err != nil {
			continue
		}
		orgIDs = append(orgIDs, orgID)
		count++
	}
	return count, orgIDs, rows.Err()
}

// SuppressedGroup holds a count of suppressed findings grouped by baseline match.
type SuppressedGroup struct {
	BaselineMatch string    `json:"baseline_match"`
	Count         int64     `json:"count"`
	LastSeen      time.Time `json:"last_seen"`
}

// SuppressedSummary returns a summary of suppressed findings grouped by baseline match.
func (s *FindingStore) SuppressedSummary(orgID string, since time.Time) ([]SuppressedGroup, error) {
	rows, err := s.db.Query(`
		SELECT COALESCE(baseline_match, 'unknown') as baseline_match,
		       COUNT(*) as count,
		       MAX(created_at) as last_seen
		FROM findings
		WHERE org_id = $1 AND suppressed = true AND created_at > $2
		GROUP BY baseline_match
		ORDER BY count DESC
		LIMIT 100
	`, orgID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []SuppressedGroup
	for rows.Next() {
		var g SuppressedGroup
		if err := rows.Scan(&g.BaselineMatch, &g.Count, &g.LastSeen); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// pgTextArray formats a Go string slice as a PostgreSQL text array literal.
func pgTextArray(ss []string) string {
	if len(ss) == 0 {
		return "{}"
	}
	parts := make([]string, len(ss))
	for i, s := range ss {
		// Escape double quotes and backslashes
		escaped := strings.ReplaceAll(s, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		parts[i] = `"` + escaped + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// parsePgTextArray parses a PostgreSQL text array literal into a Go string slice.
func parsePgTextArray(s string) []string {
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if s == "" {
		return nil
	}
	// Simple split — doesn't handle escaped commas inside quoted strings,
	// but event IDs don't contain commas so this is safe for our use case.
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.Trim(p, `"`)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

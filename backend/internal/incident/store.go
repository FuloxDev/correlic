package incident

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// ErrIncidentNotFound is returned when an incident does not exist or does not belong to the given org.
var ErrIncidentNotFound = errors.New("incident not found")

// IncidentStore handles persistence of incidents in PostgreSQL.
type IncidentStore struct {
	db *sql.DB
}

// NewIncidentStore creates a new incident store.
func NewIncidentStore(db *sql.DB) *IncidentStore {
	return &IncidentStore{db: db}
}

// Upsert inserts a new incident or updates an existing one.
func (s *IncidentStore) Upsert(ctx context.Context, inc Incident) error {
	contextJSON, err := json.Marshal(inc.ContextSummary)
	if err != nil {
		contextJSON = []byte("{}")
	}

	mitreArr := pgTextArray(inc.MITRETechniques)
	findingArr := pgTextArray(inc.FindingIDs)

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO incidents (id, org_id, host_id, category, severity, confidence, title, summary,
			mitre_techniques, finding_ids, chain_finding_id,
			started_at, ended_at, context_summary, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (id) DO UPDATE SET
			category = EXCLUDED.category,
			severity = EXCLUDED.severity,
			confidence = EXCLUDED.confidence,
			title = EXCLUDED.title,
			summary = EXCLUDED.summary,
			mitre_techniques = EXCLUDED.mitre_techniques,
			finding_ids = EXCLUDED.finding_ids,
			ended_at = EXCLUDED.ended_at,
			context_summary = EXCLUDED.context_summary,
			status = EXCLUDED.status,
			updated_at = EXCLUDED.updated_at
	`,
		inc.ID, inc.OrgID, inc.HostID, inc.Category, inc.Severity, inc.Confidence, inc.Title, inc.Summary,
		mitreArr, findingArr, nilIfEmpty(inc.ChainFindingID),
		inc.StartedAt, inc.EndedAt, contextJSON, inc.Status,
		inc.CreatedAt, inc.UpdatedAt,
	)
	return err
}

// GetByID returns a single incident, org-scoped.
func (s *IncidentStore) GetByID(ctx context.Context, orgID, id string) (*Incident, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, host_id, category, severity, confidence, title, summary,
		       mitre_techniques, finding_ids, chain_finding_id,
		       started_at, ended_at, context_summary, status,
		       resolution, resolved_by, resolved_at, created_at, updated_at
		FROM incidents
		WHERE id = $1 AND org_id = $2
	`, id, orgID)

	return scanIncident(row)
}

// List returns incidents with optional filters.
func (s *IncidentStore) List(ctx context.Context, orgID string, opts ListOptions) ([]Incident, error) {
	query := `
		SELECT id, org_id, host_id, category, severity, confidence, title, summary,
		       mitre_techniques, finding_ids, chain_finding_id,
		       started_at, ended_at, context_summary, status,
		       resolution, resolved_by, resolved_at, created_at, updated_at
		FROM incidents
		WHERE org_id = $1
	`
	args := []any{orgID}
	argIdx := 2

	if opts.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, opts.Status)
		argIdx++
	}
	if opts.Severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argIdx)
		args = append(args, opts.Severity)
		argIdx++
	}
	if opts.HostID != "" {
		query += fmt.Sprintf(" AND host_id = $%d", argIdx)
		args = append(args, opts.HostID)
		argIdx++
	}
	if opts.Category != "" {
		query += fmt.Sprintf(" AND category = $%d", argIdx)
		args = append(args, opts.Category)
		argIdx++
	}
	if !opts.Since.IsZero() {
		query += fmt.Sprintf(" AND created_at >= $%d", argIdx)
		args = append(args, opts.Since)
		argIdx++
	}

	query += " ORDER BY created_at DESC"

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, opts.Limit)
		argIdx++
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, opts.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanIncidents(rows)
}

// CountByStatus returns aggregated incident counts since a given time.
func (s *IncidentStore) CountByStatus(ctx context.Context, orgID string, since time.Time) (IncidentCounts, error) {
	var c IncidentCounts
	rows, err := s.db.QueryContext(ctx, `
		SELECT status, COUNT(*) FROM incidents
		WHERE org_id = $1 AND created_at >= $2
		GROUP BY status
	`, orgID, since)
	if err != nil {
		return c, err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			log.Printf("WARN: scan incident count failed: %v", err)
			continue
		}
		c.Total += count
		switch status {
		case "open":
			c.Open = count
		case "investigating":
			c.Investigating = count
		case "resolved":
			c.Resolved = count
		case "dismissed":
			c.Dismissed = count
		case "auto_resolved":
			c.AutoResolved = count
		}
	}
	if err := rows.Err(); err != nil {
		return c, err
	}
	return c, nil
}

// UpdateStatus changes the status of an incident. Org-scoped.
// Returns ErrIncidentNotFound if the incident does not exist or does not belong to the org.
func (s *IncidentStore) UpdateStatus(ctx context.Context, orgID, id, status, resolution, resolvedBy string) error {
	now := time.Now()
	var result sql.Result
	var err error

	if status == "resolved" || status == "dismissed" {
		result, err = s.db.ExecContext(ctx, `
			UPDATE incidents
			SET status = $2, resolution = $3, resolved_by = $4, resolved_at = $5, updated_at = $5
			WHERE id = $1 AND org_id = $6
		`, id, status, resolution, resolvedBy, now, orgID)
	} else {
		result, err = s.db.ExecContext(ctx, `
			UPDATE incidents
			SET status = $2, updated_at = $3
			WHERE id = $1 AND org_id = $4
		`, id, status, now, orgID)
	}
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrIncidentNotFound
	}
	return nil
}

// FindMergeCandidate finds an open/investigating/auto_resolved incident on the same
// host+session+category within the merge window. Returns nil if no candidate exists.
func (s *IncidentStore) FindMergeCandidate(ctx context.Context, orgID, hostID, sessionID, aiType, category string, window time.Duration) (*Incident, error) {
	cutoff := time.Now().Add(-window)

	query := `
		SELECT id, org_id, host_id, category, severity, confidence, title, summary,
		       mitre_techniques, finding_ids, chain_finding_id,
		       started_at, ended_at, context_summary, status,
		       resolution, resolved_by, resolved_at, created_at, updated_at
		FROM incidents
		WHERE org_id = $1
		  AND host_id = $2
		  AND status IN ('open', 'investigating', 'auto_resolved')
		  AND ended_at >= $3
		  AND category = $4
	`
	args := []any{orgID, hostID, cutoff, category}
	argIdx := 5

	// Scope to same AI agent type so findings from different agents
	// (e.g. claude vs cursor) create separate incidents.
	if aiType != "" {
		query += fmt.Sprintf(` AND context_summary->'ai_types' @> to_jsonb($%d::text)`, argIdx)
		args = append(args, aiType)
		argIdx++
	}

	// If we have a session ID, prefer incidents from the same session.
	if sessionID != "" {
		query += fmt.Sprintf(` AND context_summary->'session_ids' @> to_jsonb($%d::text)`, argIdx)
		args = append(args, sessionID)
		argIdx++
	}

	query += ` ORDER BY ended_at DESC LIMIT 1`

	row := s.db.QueryRowContext(ctx, query, args...)
	inc, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		// No session match — if we had a session filter, try without it
		// to merge host-level incidents (still scoped to same AI type + category).
		if sessionID != "" {
			fbQuery := `
				SELECT id, org_id, host_id, category, severity, confidence, title, summary,
				       mitre_techniques, finding_ids, chain_finding_id,
				       started_at, ended_at, context_summary, status,
				       resolution, resolved_by, resolved_at, created_at, updated_at
				FROM incidents
				WHERE org_id = $1
				  AND host_id = $2
				  AND status IN ('open', 'investigating', 'auto_resolved')
				  AND ended_at >= $3
				  AND category = $4
			`
			fbArgs := []any{orgID, hostID, cutoff, category}
			fbArgIdx := 5
			if aiType != "" {
				fbQuery += fmt.Sprintf(` AND context_summary->'ai_types' @> to_jsonb($%d::text)`, fbArgIdx)
				fbArgs = append(fbArgs, aiType)
			}
			fbQuery += ` ORDER BY ended_at DESC LIMIT 1`

			row2 := s.db.QueryRowContext(ctx, fbQuery, fbArgs...)
			inc2, err2 := scanIncident(row2)
			if errors.Is(err2, sql.ErrNoRows) {
				return nil, nil
			}
			return inc2, err2
		}
		return nil, nil
	}
	return inc, err
}

// FindMergeCandidateAnyCategory finds the most recently updated open/investigating/auto_resolved
// incident on the same host within the merge window, ignoring category. Used for informational
// detections (command_activity, file_activity) that should attach to whatever incident exists.
func (s *IncidentStore) FindMergeCandidateAnyCategory(ctx context.Context, orgID, hostID, sessionID, aiType string, window time.Duration) (*Incident, error) {
	cutoff := time.Now().Add(-window)

	query := `
		SELECT id, org_id, host_id, category, severity, confidence, title, summary,
		       mitre_techniques, finding_ids, chain_finding_id,
		       started_at, ended_at, context_summary, status,
		       resolution, resolved_by, resolved_at, created_at, updated_at
		FROM incidents
		WHERE org_id = $1
		  AND host_id = $2
		  AND status IN ('open', 'investigating', 'auto_resolved')
		  AND ended_at >= $3
	`
	args := []any{orgID, hostID, cutoff}
	argIdx := 4

	if aiType != "" {
		query += fmt.Sprintf(` AND context_summary->'ai_types' @> to_jsonb($%d::text)`, argIdx)
		args = append(args, aiType)
		argIdx++
	}

	if sessionID != "" {
		query += fmt.Sprintf(` AND context_summary->'session_ids' @> to_jsonb($%d::text)`, argIdx)
		args = append(args, sessionID)
		argIdx++
	}

	// Prefer higher-severity incidents (more likely the "real" incident to attach to).
	query += ` ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC, ended_at DESC LIMIT 1`

	row := s.db.QueryRowContext(ctx, query, args...)
	inc, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return inc, err
}

// Update updates mutable fields of an existing incident.
func (s *IncidentStore) Update(ctx context.Context, inc *Incident) error {
	contextJSON, err := json.Marshal(inc.ContextSummary)
	if err != nil {
		contextJSON = []byte("{}")
	}

	mitreArr := pgTextArray(inc.MITRETechniques)
	findingArr := pgTextArray(inc.FindingIDs)

	_, err = s.db.ExecContext(ctx, `
		UPDATE incidents
		SET category = $2, severity = $3, confidence = $4, title = $5, summary = $6,
		    mitre_techniques = $7, finding_ids = $8, ended_at = $9,
		    context_summary = $10, updated_at = $11, status = $12
		WHERE id = $1 AND org_id = $13
	`,
		inc.ID, inc.Category, inc.Severity, inc.Confidence, inc.Title, inc.Summary,
		mitreArr, findingArr, inc.EndedAt,
		contextJSON, time.Now(), inc.Status, inc.OrgID,
	)
	return err
}

// GetFindingIDs returns the finding_ids for an incident. Used by cascade resolution.
func (s *IncidentStore) GetFindingIDs(ctx context.Context, orgID, id string) ([]string, error) {
	var findingStr *string
	err := s.db.QueryRowContext(ctx, `
		SELECT finding_ids FROM incidents WHERE id = $1 AND org_id = $2
	`, id, orgID).Scan(&findingStr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIncidentNotFound
	}
	if err != nil {
		return nil, err
	}
	if findingStr == nil {
		return nil, nil
	}
	return parsePgTextArray(*findingStr), nil
}

// scanIncident scans a single row into an Incident.
func scanIncident(row *sql.Row) (*Incident, error) {
	inc := &Incident{}
	var mitreStr, findingStr *string
	var contextJSON []byte
	var chainFindingID *string

	err := row.Scan(
		&inc.ID, &inc.OrgID, &inc.HostID, &inc.Category, &inc.Severity, &inc.Confidence, &inc.Title, &inc.Summary,
		&mitreStr, &findingStr, &chainFindingID,
		&inc.StartedAt, &inc.EndedAt, &contextJSON, &inc.Status,
		&inc.Resolution, &inc.ResolvedBy, &inc.ResolvedAt, &inc.CreatedAt, &inc.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if mitreStr != nil {
		inc.MITRETechniques = parsePgTextArray(*mitreStr)
	}
	if findingStr != nil {
		inc.FindingIDs = parsePgTextArray(*findingStr)
	}
	if chainFindingID != nil {
		inc.ChainFindingID = *chainFindingID
	}
	if len(contextJSON) > 0 {
		if err := json.Unmarshal(contextJSON, &inc.ContextSummary); err != nil {
			log.Printf("WARN: incident context_summary unmarshal failed for %s: %v", inc.ID, err)
		}
	}
	return inc, nil
}

// scanIncidents scans multiple rows into Incidents.
func scanIncidents(rows *sql.Rows) ([]Incident, error) {
	var incidents []Incident
	for rows.Next() {
		inc := Incident{}
		var mitreStr, findingStr *string
		var contextJSON []byte
		var chainFindingID *string

		err := rows.Scan(
			&inc.ID, &inc.OrgID, &inc.HostID, &inc.Category, &inc.Severity, &inc.Confidence, &inc.Title, &inc.Summary,
			&mitreStr, &findingStr, &chainFindingID,
			&inc.StartedAt, &inc.EndedAt, &contextJSON, &inc.Status,
			&inc.Resolution, &inc.ResolvedBy, &inc.ResolvedAt, &inc.CreatedAt, &inc.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if mitreStr != nil {
			inc.MITRETechniques = parsePgTextArray(*mitreStr)
		}
		if findingStr != nil {
			inc.FindingIDs = parsePgTextArray(*findingStr)
		}
		if chainFindingID != nil {
			inc.ChainFindingID = *chainFindingID
		}
		if len(contextJSON) > 0 {
			if err := json.Unmarshal(contextJSON, &inc.ContextSummary); err != nil {
				log.Printf("WARN: incident context_summary unmarshal failed for %s: %v", inc.ID, err)
			}
		}
		incidents = append(incidents, inc)
	}
	return incidents, rows.Err()
}

// pgTextArray formats a Go string slice as a PostgreSQL text array literal.
func pgTextArray(ss []string) string {
	if len(ss) == 0 {
		return "{}"
	}
	parts := make([]string, len(ss))
	for i, s := range ss {
		escaped := strings.ReplaceAll(s, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		parts[i] = `"` + escaped + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// parsePgTextArray parses a PostgreSQL text array literal into a Go string slice.
// Handles quoted values containing commas and escaped characters.
func parsePgTextArray(s string) []string {
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if s == "" {
		return nil
	}
	var result []string
	inQuote := false
	var current strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' && !inQuote:
			inQuote = true
		case c == '"' && inQuote:
			inQuote = false
		case c == '\\' && inQuote && i+1 < len(s):
			i++
			current.WriteByte(s[i])
		case c == ',' && !inQuote:
			if current.Len() > 0 {
				result = append(result, current.String())
			}
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		result = append(result, current.String())
	}
	return result
}

// ReconcileStaleIncidents resolves any open/investigating incidents where ALL
// constituent findings have been resolved. This handles the race condition in
// bulk operations (e.g. "Allow Always" on 67 findings) and retroactive cleanup.
// Single SQL statement — fast and atomic.
func (s *IncidentStore) ReconcileStaleIncidents(ctx context.Context, orgID string) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		UPDATE incidents
		SET status = 'resolved',
		    resolution = 'auto-resolved: all constituent findings resolved',
		    resolved_by = 'system',
		    resolved_at = NOW(),
		    updated_at = NOW()
		WHERE org_id = $1
		  AND status IN ('open', 'investigating')
		  AND NOT EXISTS (
		      SELECT 1 FROM findings
		      WHERE (findings.incident_id = incidents.id
		             OR findings.id = ANY(incidents.finding_ids))
		        AND (findings.org_id = $1 OR findings.org_id IS NULL)
		        AND findings.status NOT IN ('allowed', 'dismissed', 'resolved', 'auto_resolved')
		  )
	`, orgID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

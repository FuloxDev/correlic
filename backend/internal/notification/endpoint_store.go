package notification

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// EndpointStore manages notification endpoint CRUD in PostgreSQL.
type EndpointStore struct {
	db *sql.DB
}

// NewEndpointStore creates a new endpoint store. Nil-safe: pass nil to disable.
func NewEndpointStore(db *sql.DB) *EndpointStore {
	if db == nil {
		return nil
	}
	return &EndpointStore{db: db}
}

// Create inserts a new notification endpoint.
func (s *EndpointStore) Create(ctx context.Context, e Endpoint) error {
	if s == nil {
		return nil
	}
	configJSON, err := json.Marshal(e.Config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO notification_endpoints (id, org_id, name, channel_type, config, min_severity, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, e.ID, e.OrgID, e.Name, e.ChannelType, configJSON, e.MinSeverity, e.Enabled)
	return err
}

// GetByID retrieves an endpoint by ID, scoped to org.
func (s *EndpointStore) GetByID(ctx context.Context, orgID, id string) (*Endpoint, error) {
	if s == nil {
		return nil, fmt.Errorf("endpoint store not initialized")
	}
	var e Endpoint
	var configJSON []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT id, org_id, name, channel_type, config, min_severity, enabled, created_at, updated_at
		FROM notification_endpoints
		WHERE id = $1 AND org_id = $2
	`, id, orgID).Scan(&e.ID, &e.OrgID, &e.Name, &e.ChannelType, &configJSON, &e.MinSeverity, &e.Enabled, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(configJSON, &e.Config); err != nil {
		e.Config = map[string]any{}
	}
	return &e, nil
}

// List returns all endpoints for an org.
func (s *EndpointStore) List(ctx context.Context, orgID string) ([]Endpoint, error) {
	if s == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, org_id, name, channel_type, config, min_severity, enabled, created_at, updated_at
		FROM notification_endpoints
		WHERE org_id = $1
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var endpoints []Endpoint
	for rows.Next() {
		var e Endpoint
		var configJSON []byte
		if err := rows.Scan(&e.ID, &e.OrgID, &e.Name, &e.ChannelType, &configJSON, &e.MinSeverity, &e.Enabled, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(configJSON, &e.Config); err != nil {
			e.Config = map[string]any{}
		}
		endpoints = append(endpoints, e)
	}
	return endpoints, rows.Err()
}

// ListEnabled returns all enabled endpoints for an org where min_severity_rank <= the given rank.
func (s *EndpointStore) ListEnabled(ctx context.Context, orgID string, severityRank int) ([]Endpoint, error) {
	if s == nil {
		return nil, nil
	}
	all, err := s.List(ctx, orgID)
	if err != nil {
		return nil, err
	}
	var result []Endpoint
	for _, e := range all {
		if e.Enabled && SeverityRank[e.MinSeverity] <= severityRank {
			result = append(result, e)
		}
	}
	return result, nil
}

// Update modifies an existing endpoint.
func (s *EndpointStore) Update(ctx context.Context, e Endpoint) error {
	if s == nil {
		return nil
	}
	configJSON, err := json.Marshal(e.Config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		UPDATE notification_endpoints
		SET name = $1, channel_type = $2, config = $3, min_severity = $4, enabled = $5, updated_at = $6
		WHERE id = $7 AND org_id = $8
	`, e.Name, e.ChannelType, configJSON, e.MinSeverity, e.Enabled, time.Now(), e.ID, e.OrgID)
	return err
}

// Delete removes an endpoint by ID, scoped to org.
func (s *EndpointStore) Delete(ctx context.Context, orgID, id string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM notification_endpoints WHERE id = $1 AND org_id = $2
	`, id, orgID)
	return err
}

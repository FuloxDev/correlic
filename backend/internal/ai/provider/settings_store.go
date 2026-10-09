package provider

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/correlic/correlic-backend/internal/secrets"
	"github.com/google/uuid"
)

// LLMSettings represents user LLM configuration.
type LLMSettings struct {
	ID          uuid.UUID  `json:"id"`
	OrgID       uuid.UUID  `json:"org_id"`
	UserID      uuid.UUID  `json:"user_id,omitempty"`
	Provider    string     `json:"provider"`
	Model       string     `json:"model"`
	Enabled     bool       `json:"enabled"`
	MaxTokens   int        `json:"max_tokens"`
	Temperature float64    `json:"temperature"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// SettingsStore manages LLM settings in the database.
type SettingsStore struct {
	db     *sql.DB
	cipher *secrets.Cipher
}

// NewSettingsStore creates a new settings store.
//
// Provider keys are sealed with the shared secrets.Cipher (AES-256-GCM under
// SHA-256(LLM_ENCRYPTION_KEY)). Releases before 1.0.1 used the first 32 bytes
// of the env value directly; provider keys encrypted by those builds are NOT
// readable by this one (acceptable pre-release — re-enter the provider key
// in Settings).
func NewSettingsStore(db *sql.DB, encryptionKey string) (*SettingsStore, error) {
	c, err := secrets.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	return &SettingsStore{db: db, cipher: c}, nil
}

// Cipher returns the cipher the store seals provider keys with, so other
// stores (notification endpoints) can protect their secrets the same way.
func (s *SettingsStore) Cipher() *secrets.Cipher {
	return s.cipher
}

// SaveSettings saves or updates LLM settings for an organization.
func (s *SettingsStore) SaveSettings(ctx context.Context, orgID uuid.UUID, provider, model, apiKey string) (*LLMSettings, error) {
	encryptedKey, err := s.encrypt(apiKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt api key: %w", err)
	}

	query := `
		INSERT INTO llm_settings (org_id, provider, model, api_key_encrypted, enabled)
		VALUES ($1, $2, $3, $4, true)
		ON CONFLICT (org_id, provider) DO UPDATE SET
			model = EXCLUDED.model,
			api_key_encrypted = EXCLUDED.api_key_encrypted,
			enabled = true,
			updated_at = NOW()
		RETURNING id, org_id, provider, model, enabled, max_tokens_per_request, temperature, created_at, updated_at
	`

	settings := &LLMSettings{}
	err = s.db.QueryRowContext(ctx, query, orgID, provider, model, encryptedKey).Scan(
		&settings.ID,
		&settings.OrgID,
		&settings.Provider,
		&settings.Model,
		&settings.Enabled,
		&settings.MaxTokens,
		&settings.Temperature,
		&settings.CreatedAt,
		&settings.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("save settings: %w", err)
	}

	return settings, nil
}

// GetSettings retrieves LLM settings for an organization.
func (s *SettingsStore) GetSettings(ctx context.Context, orgID uuid.UUID, provider string) (*LLMSettings, string, error) {
	query := `
		SELECT id, org_id, provider, model, api_key_encrypted, enabled,
		       max_tokens_per_request, temperature, created_at, updated_at, last_used_at
		FROM llm_settings
		WHERE org_id = $1 AND provider = $2
	`

	var encryptedKey string
	settings := &LLMSettings{}
	err := s.db.QueryRowContext(ctx, query, orgID, provider).Scan(
		&settings.ID,
		&settings.OrgID,
		&settings.Provider,
		&settings.Model,
		&encryptedKey,
		&settings.Enabled,
		&settings.MaxTokens,
		&settings.Temperature,
		&settings.CreatedAt,
		&settings.UpdatedAt,
		&settings.LastUsedAt,
	)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("get settings: %w", err)
	}

	apiKey, err := s.decrypt(encryptedKey)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt api key: %w", err)
	}

	return settings, apiKey, nil
}

// GetActiveProvider returns the first enabled provider for an organization.
func (s *SettingsStore) GetActiveProvider(ctx context.Context, orgID uuid.UUID) (*LLMSettings, string, error) {
	query := `
		SELECT id, org_id, provider, model, api_key_encrypted, enabled, 
		       max_tokens_per_request, temperature, created_at, updated_at, last_used_at
		FROM llm_settings
		WHERE org_id = $1 AND enabled = true
		ORDER BY updated_at DESC
		LIMIT 1
	`

	var encryptedKey string
	settings := &LLMSettings{}
	err := s.db.QueryRowContext(ctx, query, orgID).Scan(
		&settings.ID,
		&settings.OrgID,
		&settings.Provider,
		&settings.Model,
		&encryptedKey,
		&settings.Enabled,
		&settings.MaxTokens,
		&settings.Temperature,
		&settings.CreatedAt,
		&settings.UpdatedAt,
		&settings.LastUsedAt,
	)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("get active provider: %w", err)
	}

	apiKey, err := s.decrypt(encryptedKey)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt api key: %w", err)
	}

	return settings, apiKey, nil
}

// ListSettings lists all LLM settings for an organization (without API keys).
func (s *SettingsStore) ListSettings(ctx context.Context, orgID uuid.UUID) ([]*LLMSettings, error) {
	query := `
		SELECT id, org_id, provider, model, enabled, 
		       max_tokens_per_request, temperature, created_at, updated_at, last_used_at
		FROM llm_settings
		WHERE org_id = $1
		ORDER BY provider
	`

	rows, err := s.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("list settings: %w", err)
	}
	defer rows.Close()

	var settings []*LLMSettings
	for rows.Next() {
		s := &LLMSettings{}
		err := rows.Scan(
			&s.ID,
			&s.OrgID,
			&s.Provider,
			&s.Model,
			&s.Enabled,
			&s.MaxTokens,
			&s.Temperature,
			&s.CreatedAt,
			&s.UpdatedAt,
			&s.LastUsedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan settings: %w", err)
		}
		settings = append(settings, s)
	}

	return settings, nil
}

// DeleteSettings removes LLM settings for a provider.
func (s *SettingsStore) DeleteSettings(ctx context.Context, orgID uuid.UUID, provider string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM llm_settings WHERE org_id = $1 AND provider = $2",
		orgID, provider)
	return err
}

// UpdateLastUsed updates the last_used_at timestamp.
func (s *SettingsStore) UpdateLastUsed(ctx context.Context, settingsID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE llm_settings SET last_used_at = NOW() WHERE id = $1",
		settingsID)
	return err
}

// DisableProvider disables a provider without deleting it.
func (s *SettingsStore) DisableProvider(ctx context.Context, orgID uuid.UUID, provider string) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE llm_settings SET enabled = false, updated_at = NOW() WHERE org_id = $1 AND provider = $2",
		orgID, provider)
	return err
}

// EnableProvider enables a provider and optionally updates its model.
func (s *SettingsStore) EnableProvider(ctx context.Context, orgID uuid.UUID, provider, model string) (*LLMSettings, error) {
	query := `
		UPDATE llm_settings 
		SET enabled = true, model = $3, updated_at = NOW()
		WHERE org_id = $1 AND provider = $2
		RETURNING id, org_id, provider, model, enabled, max_tokens_per_request, temperature, created_at, updated_at
	`

	settings := &LLMSettings{}
	err := s.db.QueryRowContext(ctx, query, orgID, provider, model).Scan(
		&settings.ID,
		&settings.OrgID,
		&settings.Provider,
		&settings.Model,
		&settings.Enabled,
		&settings.MaxTokens,
		&settings.Temperature,
		&settings.CreatedAt,
		&settings.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("enable provider: %w", err)
	}

	return settings, nil
}

// encrypt seals plaintext with the shared cipher.
func (s *SettingsStore) encrypt(plaintext string) (string, error) {
	return s.cipher.Encrypt(plaintext)
}

// decrypt opens a value produced by encrypt.
func (s *SettingsStore) decrypt(ciphertext string) (string, error) {
	return s.cipher.Decrypt(ciphertext)
}

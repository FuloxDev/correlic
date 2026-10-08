package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type PostgresUserStore struct {
	db *sql.DB
}

func NewPostgresUserStore(db *sql.DB) *PostgresUserStore {
	return &PostgresUserStore{db: db}
}

func (s *PostgresUserStore) CreateUser(email, name string) (*User, error) {
	// Generate a random password for new users
	randomPassword := generateRandomPassword()
	hash, err := bcrypt.GenerateFromPassword([]byte(randomPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user, _, err := s.CreateUserWithPassword(email, name, string(hash))
	return user, err
}

func (s *PostgresUserStore) CreateUserWithPassword(email, name, passwordHash string) (*User, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	id := uuid.New().String()
	if strings.TrimSpace(name) == "" {
		name = email
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, email, name, password_hash, password_reset_required, email_verified)
		VALUES ($1, $2, $3, $4, true, false)
		ON CONFLICT (email) DO NOTHING
	`, id, email, name, passwordHash)
	if err != nil {
		return nil, false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	user, err := s.GetUserByEmail(email)
	if err != nil {
		return nil, false, err
	}
	return user, rowsAffected > 0, nil
}

func (s *PostgresUserStore) CreateServiceAccount(email, name string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	id := uuid.New().String()
	if strings.TrimSpace(name) == "" {
		name = email
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, email, name, is_service_account, email_verified)
		VALUES ($1, $2, $3, true, true)
		ON CONFLICT (email) DO UPDATE SET
			is_service_account = true,
			name = EXCLUDED.name
	`, id, email, name)
	if err != nil {
		return nil, err
	}
	return s.GetUserByEmail(email)
}

func (s *PostgresUserStore) GetUserByEmail(email string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var u User
	var passwordHash sql.NullString
	var resetRequired sql.NullBool
	var username sql.NullString
	var avatarURL sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id::text, email, name, COALESCE(username, ''), COALESCE(avatar_url, ''),
		       is_service_account, email_verified, password_hash, password_reset_required, created_at
		FROM users
		WHERE email = $1
	`, email).Scan(&u.ID, &u.Email, &u.Name, &username, &avatarURL,
		&u.IsServiceAccount, &u.EmailVerified, &passwordHash, &resetRequired, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if passwordHash.Valid {
		u.PasswordHash = passwordHash.String
	}
	if resetRequired.Valid {
		u.PasswordResetRequired = resetRequired.Bool
	}
	if username.Valid {
		u.Username = username.String
	}
	if avatarURL.Valid {
		u.AvatarURL = avatarURL.String
	}
	return &u, nil
}

func (s *PostgresUserStore) GetUser(id string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var u User
	var passwordHash sql.NullString
	var resetRequired sql.NullBool
	var username sql.NullString
	var avatarURL sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id::text, email, name, COALESCE(username, ''), COALESCE(avatar_url, ''),
		       is_service_account, email_verified, password_hash, password_reset_required, created_at
		FROM users
		WHERE id = $1
	`, id).Scan(&u.ID, &u.Email, &u.Name, &username, &avatarURL,
		&u.IsServiceAccount, &u.EmailVerified, &passwordHash, &resetRequired, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if passwordHash.Valid {
		u.PasswordHash = passwordHash.String
	}
	if resetRequired.Valid {
		u.PasswordResetRequired = resetRequired.Bool
	}
	if username.Valid {
		u.Username = username.String
	}
	if avatarURL.Valid {
		u.AvatarURL = avatarURL.String
	}
	return &u, nil
}

func (s *PostgresUserStore) VerifyPassword(userID, passwordHash string) (bool, error) {
	user, err := s.GetUser(userID)
	if err != nil || user == nil {
		return false, err
	}
	if user.PasswordHash == "" {
		return false, nil
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(passwordHash))
	return err == nil, nil
}

func (s *PostgresUserStore) SetPassword(userID, passwordHash string, resetRequired bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET password_hash = $1, password_reset_required = $2
		WHERE id = $3
	`, passwordHash, resetRequired, userID)
	return err
}

func generateRandomPassword() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:24] // 24 chars, URL-safe
}

func (s *PostgresUserStore) ListOrgUsers(orgID string) ([]OrgUser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id::text, u.email, u.name, u.is_service_account, u.email_verified, u.created_at, ou.role
		FROM org_users ou
		JOIN users u ON u.id = ou.user_id
		WHERE ou.org_id = $1::uuid
		ORDER BY u.email ASC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []OrgUser
	for rows.Next() {
		var u OrgUser
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.IsServiceAccount, &u.EmailVerified, &u.CreatedAt, &u.Role); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *PostgresUserStore) AddOrgUser(orgID, userID, role string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if strings.TrimSpace(role) == "" {
		role = "member"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO org_users (org_id, user_id, role)
		VALUES ($1::uuid, $2::uuid, $3)
		ON CONFLICT (org_id, user_id) DO UPDATE SET
		  role = EXCLUDED.role
	`, orgID, userID, role)
	return err
}

func (s *PostgresUserStore) RemoveOrgUser(orgID, userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := s.db.ExecContext(ctx, `
		DELETE FROM org_users
		WHERE org_id = $1::uuid AND user_id = $2::uuid
	`, orgID, userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows // Indicate no rows were deleted
	}

	return nil
}

func (s *PostgresUserStore) GetOrgUserRole(orgID, userID string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var role string
	err := s.db.QueryRowContext(ctx, `
		SELECT role
		FROM org_users
		WHERE org_id = $1::uuid AND user_id = $2::uuid
	`, orgID, userID).Scan(&role)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return role, true, nil
}

func (s *PostgresUserStore) GetUserOrgID(userID string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A user may belong to several orgs; always return the one they joined first so
	// login and API-key resolution are deterministic across requests.
	var orgID string
	err := s.db.QueryRowContext(ctx, `
		SELECT ou.org_id::text
		FROM org_users ou
		JOIN organizations o ON o.id = ou.org_id
		WHERE ou.user_id = $1::uuid
		ORDER BY ou.created_at ASC, ou.org_id ASC
		LIMIT 1
	`, userID).Scan(&orgID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return orgID, nil
}

func (s *PostgresUserStore) UpdateUserServiceAccount(userID string, isServiceAccount bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET is_service_account = $1
		WHERE id = $2
	`, isServiceAccount, userID)
	return err
}

func (s *PostgresUserStore) CreateSession(userID, tokenHash string, expiresAt time.Time) (*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, id, userID, tokenHash, expiresAt)
	if err != nil {
		return nil, err
	}
	return &Session{
		ID:        id,
		UserID:    userID,
		TokenHash: tokenHash,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
	}, nil
}

func (s *PostgresUserStore) GetSessionByHash(tokenHash string) (*Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var srow Session
	err := s.db.QueryRowContext(ctx, `
		SELECT id::text, user_id::text, token_hash, created_at, expires_at
		FROM sessions
		WHERE token_hash = $1
	`, tokenHash).Scan(&srow.ID, &srow.UserID, &srow.TokenHash, &srow.CreatedAt, &srow.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &srow, nil
}

func (s *PostgresUserStore) CreateEmailVerificationToken(email, tokenHash string, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO email_verification_tokens (id, email, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, id, email, tokenHash, expiresAt)
	return err
}

func (s *PostgresUserStore) VerifyEmailToken(tokenHash string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var email string
	var usedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT email, used_at
		FROM email_verification_tokens
		WHERE token_hash = $1 AND expires_at > now()
	`, tokenHash).Scan(&email, &usedAt)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	// Check if already used
	if usedAt.Valid {
		return "", fmt.Errorf("token already used")
	}

	// Mark as used
	_, err = s.db.ExecContext(ctx, `
		UPDATE email_verification_tokens
		SET used_at = now()
		WHERE token_hash = $1
	`, tokenHash)
	if err != nil {
		return "", err
	}

	return email, nil
}

func (s *PostgresUserStore) MarkEmailVerified(userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET email_verified = true
		WHERE id = $1
	`, userID)
	return err
}

func (s *PostgresUserStore) UpdateProfile(userID string, name, username, avatarURL *string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Build dynamic SET clauses
	setClauses := []string{}
	args := []interface{}{}
	argIdx := 1

	if name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *name)
		argIdx++
	}
	if username != nil {
		setClauses = append(setClauses, fmt.Sprintf("username = $%d", argIdx))
		args = append(args, *username)
		argIdx++
	}
	if avatarURL != nil {
		setClauses = append(setClauses, fmt.Sprintf("avatar_url = $%d", argIdx))
		args = append(args, *avatarURL)
		argIdx++
	}

	if len(setClauses) == 0 {
		return nil
	}

	args = append(args, userID)
	query := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", strings.Join(setClauses, ", "), argIdx)
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func (s *PostgresUserStore) GetOAuthAccount(provider, providerID string) (*OAuthAccount, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var a OAuthAccount
	err := s.db.QueryRowContext(ctx, `
		SELECT id::text, user_id::text, provider, provider_id, email, name, avatar_url, created_at
		FROM user_oauth_accounts
		WHERE provider = $1 AND provider_id = $2
	`, provider, providerID).Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderID, &a.Email, &a.Name, &a.AvatarURL, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *PostgresUserStore) CreateOAuthAccount(account *OAuthAccount) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_oauth_accounts (id, user_id, provider, provider_id, email, name, avatar_url)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, id, account.UserID, account.Provider, account.ProviderID, account.Email, account.Name, account.AvatarURL)
	return err
}

func (s *PostgresUserStore) LinkOAuthAccount(userID, provider, providerID, email, name, avatarURL string) error {
	return s.CreateOAuthAccount(&OAuthAccount{
		UserID:     userID,
		Provider:   provider,
		ProviderID: providerID,
		Email:      email,
		Name:       name,
		AvatarURL:  avatarURL,
	})
}

var _ UserStore = (*PostgresUserStore)(nil)

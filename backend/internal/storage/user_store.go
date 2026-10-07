package storage

import "time"

type User struct {
	ID                    string    `json:"id"`
	Email                 string    `json:"email"`
	Name                  string    `json:"name"`
	Username              string    `json:"username,omitempty"`
	AvatarURL             string    `json:"avatar_url,omitempty"`
	IsServiceAccount      bool      `json:"is_service_account"`
	EmailVerified         bool      `json:"email_verified"`
	PasswordHash          string    `json:"-"` // Never expose in JSON
	PasswordResetRequired bool      `json:"password_reset_required,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
}

type OAuthAccount struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Provider   string    `json:"provider"`
	ProviderID string    `json:"provider_id"`
	Email      string    `json:"email"`
	Name       string    `json:"name"`
	AvatarURL  string    `json:"avatar_url"`
	CreatedAt  time.Time `json:"created_at"`
}

type EmailVerificationToken struct {
	ID        string
	Email     string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

type OrgUser struct {
	User
	Role string `json:"role"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TokenHash string    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type UserStore interface {
	CreateUser(email, name string) (*User, error)
	CreateUserWithPassword(email, name, passwordHash string) (*User, bool, error) // Returns (user, wasCreated, error)
	CreateServiceAccount(email, name string) (*User, error)                       // Creates a user with is_service_account=true
	GetUserByEmail(email string) (*User, error)
	GetUser(id string) (*User, error)
	VerifyPassword(userID, passwordHash string) (bool, error)
	SetPassword(userID, passwordHash string, resetRequired bool) error
	ListOrgUsers(orgID string) ([]OrgUser, error)
	AddOrgUser(orgID, userID, role string) error
	RemoveOrgUser(orgID, userID string) error
	GetOrgUserRole(orgID, userID string) (string, bool, error)
	GetUserOrgID(userID string) (string, error)
	UpdateUserServiceAccount(userID string, isServiceAccount bool) error
	CreateSession(userID, tokenHash string, expiresAt time.Time) (*Session, error)
	GetSessionByHash(tokenHash string) (*Session, error)
	// Profile
	UpdateProfile(userID string, name, username, avatarURL *string) error

	// Email verification
	CreateEmailVerificationToken(email, tokenHash string, expiresAt time.Time) error
	VerifyEmailToken(tokenHash string) (string, error) // Returns email if valid
	MarkEmailVerified(userID string) error

	// OAuth
	GetOAuthAccount(provider, providerID string) (*OAuthAccount, error)
	CreateOAuthAccount(account *OAuthAccount) error
	LinkOAuthAccount(userID, provider, providerID, email, name, avatarURL string) error
}

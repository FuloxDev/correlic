package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/storage"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// GoogleAuthHandler handles Google OAuth sign-in.
// The frontend sends the Google ID token (from Google Sign-In JS SDK),
// the backend verifies it with Google's tokeninfo endpoint, then creates
// or links the user account.
type GoogleAuthHandler struct {
	store    storage.UserStore
	clientID string // Google OAuth client ID for audience verification
}

func NewGoogleAuthHandler(store storage.UserStore, googleClientID string) *GoogleAuthHandler {
	return &GoogleAuthHandler{store: store, clientID: googleClientID}
}

type googleTokenInfo struct {
	Sub           string `json:"sub"` // Unique Google user ID
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"` // "true" or "false"
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Aud           string `json:"aud"` // Must match our client ID
}

func (h *GoogleAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		MethodNotAllowed(w, http.MethodPost)
		return
	}

	var req struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		BadRequest(w, "invalid payload")
		return
	}
	if strings.TrimSpace(req.IDToken) == "" {
		BadRequest(w, "id_token required")
		return
	}

	// Verify the token with Google
	info, err := verifyGoogleToken(req.IDToken)
	if err != nil {
		Unauthorized(w, fmt.Sprintf("invalid google token: %v", err))
		return
	}

	// Verify audience matches our client ID
	if h.clientID != "" && info.Aud != h.clientID {
		Unauthorized(w, "token audience mismatch")
		return
	}

	if info.Email == "" || info.Sub == "" {
		Unauthorized(w, "missing email or sub in token")
		return
	}
	if info.EmailVerified != "true" {
		Unauthorized(w, "google account email is not verified")
		return
	}

	// Check if OAuth account already exists
	oauthAccount, err := h.store.GetOAuthAccount("google", info.Sub)
	if err != nil {
		Internal(w)
		return
	}

	var user *storage.User

	if oauthAccount != nil {
		// Existing Google account — get the linked user
		user, err = h.store.GetUser(oauthAccount.UserID)
		if err != nil || user == nil {
			Internal(w)
			return
		}
	} else {
		// New Google sign-in — check if user with this email already exists
		user, err = h.store.GetUserByEmail(info.Email)
		if err != nil {
			Internal(w)
			return
		}

		if user == nil {
			// Create new user (Google-verified, no password)
			randomPw := uuid.New().String()
			hash, _ := bcrypt.GenerateFromPassword([]byte(randomPw), bcrypt.DefaultCost)
			user, _, err = h.store.CreateUserWithPassword(info.Email, info.Name, string(hash))
			if err != nil {
				Internal(w)
				return
			}
			// Google-verified users are immediately email-verified
			_ = h.store.MarkEmailVerified(user.ID)
			user.EmailVerified = true

			// Set avatar from Google
			if info.Picture != "" {
				_ = h.store.UpdateProfile(user.ID, nil, nil, &info.Picture)
				user.AvatarURL = info.Picture
			}
		}

		// Link Google account to user
		if err := h.store.LinkOAuthAccount(user.ID, "google", info.Sub, info.Email, info.Name, info.Picture); err != nil {
			// Ignore duplicate link errors
			if !strings.Contains(err.Error(), "user_oauth_provider_idx") {
				Internal(w)
				return
			}
		}

		// If existing user wasn't verified, verify them now (Google verified the email)
		if !user.EmailVerified {
			_ = h.store.MarkEmailVerified(user.ID)
			user.EmailVerified = true
		}
	}

	// Get user's org
	orgID, err := h.store.GetUserOrgID(user.ID)
	if err != nil || orgID == "" {
		// User has no org — they can still sign in, but won't have org context
		// The frontend will handle this case
	}

	// Create session
	token := strings.ReplaceAll(uuid.New().String(), "-", "")
	hashBytes := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hashBytes[:])
	session, err := h.store.CreateSession(user.ID, tokenHash, time.Now().UTC().Add(24*time.Hour))
	if err != nil {
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":   token,
		"session": session,
		"user":    user,
	})
}

// verifyGoogleToken validates a Google ID token using Google's tokeninfo endpoint.
func verifyGoogleToken(idToken string) (*googleTokenInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm("https://oauth2.googleapis.com/tokeninfo", url.Values{"id_token": {idToken}})
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token verification failed: %s", string(body))
	}

	var info googleTokenInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to parse token info: %w", err)
	}

	return &info, nil
}

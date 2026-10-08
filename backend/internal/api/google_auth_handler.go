package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
//
// The handler must only be registered when GOOGLE_CLIENT_ID is configured:
// without a client ID the audience of the token cannot be verified and any
// Google-issued token for any application would be accepted.
type GoogleAuthHandler struct {
	store    storage.UserStore
	clientID string // Google OAuth client ID for audience verification
	// verify validates an ID token; overridable in tests.
	verify func(idToken string) (*googleTokenInfo, error)
}

func NewGoogleAuthHandler(store storage.UserStore, googleClientID string) *GoogleAuthHandler {
	return &GoogleAuthHandler{
		store:    store,
		clientID: strings.TrimSpace(googleClientID),
		verify:   verifyGoogleToken,
	}
}

type googleTokenInfo struct {
	Sub           string `json:"sub"` // Unique Google user ID
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"` // "true" or "false"
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Aud           string `json:"aud"` // Must match our client ID
	Iss           string `json:"iss"` // Must be a Google issuer
}

// googleIssuers are the issuer values Google uses for ID tokens.
var googleIssuers = map[string]struct{}{
	"accounts.google.com":         {},
	"https://accounts.google.com": {},
}

var errGoogleTokenRejected = errors.New("google token rejected")

func (h *GoogleAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		MethodNotAllowed(w, http.MethodPost)
		return
	}
	if h.clientID == "" {
		NotImplemented(w, "google sign-in is not configured")
		return
	}

	var req struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		BadRequest(w, "invalid payload")
		return
	}
	if strings.TrimSpace(req.IDToken) == "" {
		BadRequest(w, "id_token required")
		return
	}

	// Verify the token with Google. Details are logged, never echoed.
	info, err := h.verify(req.IDToken)
	if err != nil {
		log.Printf("[google-auth] token verification failed: %v", err)
		Unauthorized(w, "invalid google token")
		return
	}

	// The audience must always equal our client ID and the issuer must be Google.
	if info.Aud != h.clientID {
		log.Printf("[google-auth] token audience mismatch")
		Unauthorized(w, "invalid google token")
		return
	}
	if _, ok := googleIssuers[info.Iss]; !ok {
		log.Printf("[google-auth] token issuer not trusted")
		Unauthorized(w, "invalid google token")
		return
	}

	if info.Email == "" || info.Sub == "" {
		Unauthorized(w, "invalid google token")
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

// verifyGoogleToken validates a Google ID token using Google's tokeninfo
// endpoint. Google's response body is never included in the returned error.
func verifyGoogleToken(idToken string) (*googleTokenInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm("https://oauth2.googleapis.com/tokeninfo", url.Values{"id_token": {idToken}})
	if err != nil {
		return nil, fmt.Errorf("tokeninfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("tokeninfo read failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: tokeninfo status %d", errGoogleTokenRejected, resp.StatusCode)
	}

	var info googleTokenInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("tokeninfo parse failed: %w", err)
	}

	return &info, nil
}

package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
)

type EmailVerificationHandler struct {
	store   storage.UserStore
	baseURL string // Frontend base URL for verification links
}

func NewEmailVerificationHandler(store storage.UserStore, baseURL string) *EmailVerificationHandler {
	return &EmailVerificationHandler{store: store, baseURL: baseURL}
}

// SendVerification creates a verification token and sends it via email.
// POST /auth/email/send-verification
func (h *EmailVerificationHandler) SendVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		MethodNotAllowed(w, http.MethodPost)
		return
	}

	var req struct {
		Email string `json:"email"`
	}

	// If authenticated, use actor context to get email
	_, actorID, authOK := middleware.ActorFromContext(r.Context())
	if authOK && actorID != "" {
		user, err := h.store.GetUser(actorID)
		if err != nil || user == nil {
			Unauthorized(w, "user not found")
			return
		}
		req.Email = user.Email
	} else {
		// Unauthenticated — email must be in body
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			BadRequest(w, "invalid payload")
			return
		}
	}

	email := strings.TrimSpace(req.Email)
	if email == "" {
		BadRequest(w, "email required")
		return
	}

	user, err := h.store.GetUserByEmail(email)
	if err != nil {
		Internal(w)
		return
	}
	if user == nil {
		// Don't reveal whether the email exists
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"message": "if the email exists, a verification link has been sent",
		})
		return
	}

	if user.EmailVerified {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"message": "email already verified",
		})
		return
	}

	// Generate token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		Internal(w)
		return
	}
	rawToken := hex.EncodeToString(tokenBytes)
	hashBytes := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hashBytes[:])

	// Store token (24h expiry)
	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	if err := h.store.CreateEmailVerificationToken(email, tokenHash, expiresAt); err != nil {
		Internal(w)
		return
	}

	// Send email
	verifyURL := fmt.Sprintf("%s/auth/verify-email?token=%s", h.baseURL, rawToken)
	if err := sendVerificationEmail(email, verifyURL); err != nil {
		log.Printf("WARNING: Failed to send verification email to %s: %v", email, err)
		// Still return success — don't reveal email sending issues to user
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "if the email exists, a verification link has been sent",
	})
}

// VerifyEmail verifies an email token.
// POST /auth/email/verify
func (h *EmailVerificationHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		MethodNotAllowed(w, http.MethodPost)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		BadRequest(w, "invalid payload")
		return
	}

	token := strings.TrimSpace(req.Token)
	if token == "" {
		BadRequest(w, "token required")
		return
	}

	hashBytes := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hashBytes[:])

	email, err := h.store.VerifyEmailToken(tokenHash)
	if err != nil {
		BadRequest(w, "invalid or expired token")
		return
	}
	if email == "" {
		BadRequest(w, "invalid or expired token")
		return
	}

	// Mark user as verified
	user, err := h.store.GetUserByEmail(email)
	if err != nil || user == nil {
		BadRequest(w, "user not found")
		return
	}

	if err := h.store.MarkEmailVerified(user.ID); err != nil {
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "email verified successfully",
		"email":   email,
	})
}

// sendVerificationEmail sends a verification email via SMTP.
// Requires SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM env vars.
func sendVerificationEmail(to, verifyURL string) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")
	from := os.Getenv("SMTP_FROM")

	if host == "" {
		log.Printf("SMTP not configured — verification URL for %s: %s", to, verifyURL)
		return nil // Silent success — log the URL for dev/testing
	}

	if port == "" {
		port = "587"
	}
	if from == "" {
		from = user
	}

	subject := "Verify your Correlic email"
	body := fmt.Sprintf(`Hello,

Please verify your email address by clicking the link below:

%s

This link expires in 24 hours.

If you didn't create a Correlic account, you can safely ignore this email.

— Correlic Security Platform`, verifyURL)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		from, to, subject, body)

	auth := smtp.PlainAuth("", user, pass, host)
	addr := fmt.Sprintf("%s:%s", host, port)
	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
}

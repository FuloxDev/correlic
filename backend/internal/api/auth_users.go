package api

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
	"github.com/google/uuid"
)

type UsersHandler struct {
	store      storage.UserStore
	agentStore storage.AgentStore
	audit      storage.AuditStore
}

func NewUsersHandler(store storage.UserStore, agentStore storage.AgentStore, auditStore storage.AuditStore) *UsersHandler {
	return &UsersHandler{store: store, agentStore: agentStore, audit: auditStore}
}

func (h *UsersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}
	if h.store == nil {
		NotImplemented(w, "user store not enabled")
		return
	}

	switch r.Method {
	case http.MethodGet:
		users, err := h.store.ListOrgUsers(orgID)
		if err != nil {
			Internal(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(users)
		return

	case http.MethodPost:
		var req struct {
			Email            string `json:"email"`
			Name             string `json:"name"`
			Role             string `json:"role"`
			IsServiceAccount bool   `json:"is_service_account"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			BadRequest(w, "invalid payload")
			return
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
		var generatedPassword string
		userWasNew := false

		if user == nil {
			if req.IsServiceAccount {
				// Create service account (no password)
				createdUser, err := h.store.CreateServiceAccount(email, strings.TrimSpace(req.Name))
				if err != nil {
					Internal(w)
					return
				}
				user = createdUser
				userWasNew = true
			} else {
				// Generate password before creating regular user
				randomPassword := generateRandomPassword()
				hash, err := bcrypt.GenerateFromPassword([]byte(randomPassword), bcrypt.DefaultCost)
				if err != nil {
					Internal(w)
					return
				}
				createdUser, wasCreated, err := h.store.CreateUserWithPassword(email, strings.TrimSpace(req.Name), string(hash))
				if err != nil {
					Internal(w)
					return
				}
				user = createdUser
				userWasNew = wasCreated
				if wasCreated {
					generatedPassword = randomPassword
					// Admin-created users are treated as verified for now
					_ = h.store.MarkEmailVerified(user.ID)
					user.EmailVerified = true
				}
			}
		} else {
			// User already exists - update is_service_account if needed
			if req.IsServiceAccount && !user.IsServiceAccount {
				// Update existing user to be a service account
				if err := h.store.UpdateUserServiceAccount(user.ID, true); err != nil {
					Internal(w)
					return
				}
				// Refresh user data
				user, err = h.store.GetUser(user.ID)
				if err != nil {
					Internal(w)
					return
				}
			} else if !req.IsServiceAccount && user.IsServiceAccount {
				// Cannot convert service account to regular user (would need password)
				BadRequest(w, "cannot convert service account to regular user")
				return
			}
		}

		if err := h.store.AddOrgUser(orgID, user.ID, strings.TrimSpace(req.Role)); err != nil {
			Internal(w)
			return
		}
		if h.audit != nil {
			if actorType, actorID, ok := middleware.ActorFromContext(r.Context()); ok {
				_ = h.audit.InsertEvent(&storage.AuditEvent{
					OrgID:      orgID,
					ActorType:  actorType,
					ActorID:    actorID,
					Action:     "user.add",
					TargetType: "user",
					TargetID:   user.ID,
					Meta: map[string]any{
						"email":              user.Email,
						"role":               strings.TrimSpace(req.Role),
						"is_service_account": user.IsServiceAccount,
					},
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"id":                 user.ID,
			"email":              user.Email,
			"name":               user.Name,
			"is_service_account": user.IsServiceAccount,
		}
		// Only include password if regular user was newly created
		if userWasNew && generatedPassword != "" && !user.IsServiceAccount {
			resp["password"] = generatedPassword // Only returned on creation
			resp["password_reset_required"] = true
		}
		_ = json.NewEncoder(w).Encode(resp)
		return

	case http.MethodDelete:
		// Extract user ID from query parameter or path
		userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
		if userID == "" {
			BadRequest(w, "user_id required")
			return
		}

		// Verify user exists in org
		_, exists, err := h.store.GetOrgUserRole(orgID, userID)
		if err != nil {
			Internal(w)
			return
		}
		if !exists {
			BadRequest(w, "user not found in organization")
			return
		}

		// Get user info for audit log
		user, err := h.store.GetUser(userID)
		if err != nil {
			Internal(w)
			return
		}
		if user == nil {
			BadRequest(w, "user not found")
			return
		}

		// Safety check: prevent deletion if user has agents attached
		if h.agentStore != nil {
			agentCount, err := h.agentStore.CountAgentsByUserID(userID)
			if err != nil {
				Internal(w)
				return
			}
			if agentCount > 0 {
				BadRequest(w, fmt.Sprintf("cannot remove user: %d agent(s) are still attached. Please remove or reassign agents first", agentCount))
				return
			}
		}

		// Remove user from organization
		if err := h.store.RemoveOrgUser(orgID, userID); err != nil {
			if err == sql.ErrNoRows {
				BadRequest(w, "user not found in organization")
				return
			}
			Internal(w)
			return
		}

		// Audit log
		if h.audit != nil {
			if actorType, actorID, ok := middleware.ActorFromContext(r.Context()); ok {
				_ = h.audit.InsertEvent(&storage.AuditEvent{
					OrgID:      orgID,
					ActorType:  actorType,
					ActorID:    actorID,
					Action:     "user.remove",
					TargetType: "user",
					TargetID:   userID,
					Meta: map[string]any{
						"email": user.Email,
					},
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"message": "user removed from organization",
		})
		return

	case http.MethodPut:
		// Update user (name, role only - email and is_service_account cannot be changed)
		userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
		if userID == "" {
			BadRequest(w, "user_id required")
			return
		}

		var req struct {
			Name string `json:"name"`
			Role string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			BadRequest(w, "invalid payload")
			return
		}

		// Verify user exists in org
		_, exists, err := h.store.GetOrgUserRole(orgID, userID)
		if err != nil {
			Internal(w)
			return
		}
		if !exists {
			BadRequest(w, "user not found in organization")
			return
		}

		// Update user name if provided
		if req.Name != "" {
			// Note: We'd need an UpdateUser method in UserStore to update name
			// For now, we'll just update the role
		}

		// Update role if provided
		if req.Role != "" {
			if err := h.store.AddOrgUser(orgID, userID, strings.TrimSpace(req.Role)); err != nil {
				Internal(w)
				return
			}
		}

		// Get updated user info
		user, err := h.store.GetUser(userID)
		if err != nil {
			Internal(w)
			return
		}
		if user == nil {
			BadRequest(w, "user not found")
			return
		}

		role, _, _ := h.store.GetOrgUserRole(orgID, userID)

		// Audit log
		if h.audit != nil {
			if actorType, actorID, ok := middleware.ActorFromContext(r.Context()); ok {
				_ = h.audit.InsertEvent(&storage.AuditEvent{
					OrgID:      orgID,
					ActorType:  actorType,
					ActorID:    actorID,
					Action:     "user.update",
					TargetType: "user",
					TargetID:   userID,
					Meta: map[string]any{
						"email": user.Email,
						"role":  role,
					},
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":                 user.ID,
			"email":              user.Email,
			"name":               user.Name,
			"is_service_account": user.IsServiceAccount,
			"role":               role,
		})
		return

	default:
		MethodNotAllowed(w, http.MethodGet+", "+http.MethodPost+", "+http.MethodPut+", "+http.MethodDelete)
	}
}

type SessionsHandler struct {
	store storage.UserStore
	audit storage.AuditStore
}

func NewSessionsHandler(store storage.UserStore, auditStore storage.AuditStore) *SessionsHandler {
	return &SessionsHandler{store: store, audit: auditStore}
}

func (h *SessionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Login endpoint: org context is optional (user may not be authenticated yet)
	// We'll get org from user after validating credentials
	orgID, _ := middleware.OrgFromContext(r.Context())

	if h.store == nil {
		NotImplemented(w, "user store not enabled")
		return
	}

	if r.Method != http.MethodPost {
		MethodNotAllowed(w, http.MethodPost)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TTLHours int    `json:"ttl_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		BadRequest(w, "invalid payload")
		return
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
		// Same response as a wrong password so the endpoint cannot be used to
		// enumerate accounts.
		Unauthorized(w, "invalid credentials")
		return
	}

	// Service accounts cannot log in with passwords - they must use API keys
	if user.IsServiceAccount {
		Unauthorized(w, "service accounts cannot log in with passwords; use API keys instead")
		return
	}
	if !user.EmailVerified {
		Unauthorized(w, "email not verified")
		return
	}

	// Get user's org (required for session creation and audit logging)
	if orgID == "" {
		orgID, err = h.store.GetUserOrgID(user.ID)
		if err != nil || orgID == "" {
			Unauthorized(w, "user not associated with any organization")
			return
		}
	}

	// A password is always required. (An earlier "admin creates session"
	// flow issued sessions without one; it has been removed.)
	if req.Password == "" {
		Unauthorized(w, "password required")
		return
	}
	if user.PasswordHash == "" {
		Unauthorized(w, "invalid credentials")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		Unauthorized(w, "invalid credentials")
		return
	}

	ttl := req.TTLHours
	if ttl <= 0 || ttl > 720 {
		ttl = 24
	}
	token := randomToken()
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])
	session, err := h.store.CreateSession(user.ID, tokenHash, time.Now().UTC().Add(time.Duration(ttl)*time.Hour))
	if err != nil {
		Internal(w)
		return
	}
	if h.audit != nil {
		if actorType, actorID, ok := middleware.ActorFromContext(r.Context()); ok {
			_ = h.audit.InsertEvent(&storage.AuditEvent{
				OrgID:      orgID,
				ActorType:  actorType,
				ActorID:    actorID,
				Action:     "session.create",
				TargetType: "user",
				TargetID:   user.ID,
				Meta: map[string]any{
					"email": user.Email,
					"ttl":   ttl,
				},
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":   token,
		"session": session,
		"user":    user,
	})
}

func randomToken() string {
	return strings.ReplaceAll(uuidNew(), "-", "")
}

func uuidNew() string {
	return uuid.New().String()
}

func generateRandomPassword() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:24] // 24 chars, URL-safe
}

// PasswordResetHandler handles password reset requests
type PasswordResetHandler struct {
	store storage.UserStore
	audit storage.AuditStore
}

func NewPasswordResetHandler(store storage.UserStore, auditStore storage.AuditStore) *PasswordResetHandler {
	return &PasswordResetHandler{store: store, audit: auditStore}
}

func (h *PasswordResetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		MethodNotAllowed(w, http.MethodPost)
		return
	}

	var req struct {
		Email       string `json:"email"`
		OldPassword string `json:"old_password,omitempty"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		BadRequest(w, "invalid payload")
		return
	}

	email := strings.TrimSpace(req.Email)
	newPassword := strings.TrimSpace(req.NewPassword)
	if email == "" || newPassword == "" {
		BadRequest(w, "email and new_password required")
		return
	}
	if len(newPassword) < 8 {
		BadRequest(w, "password must be at least 8 characters")
		return
	}

	user, err := h.store.GetUserByEmail(email)
	if err != nil {
		Internal(w)
		return
	}
	if user == nil {
		BadRequest(w, "user not found")
		return
	}

	if strings.TrimSpace(req.OldPassword) == "" {
		BadRequest(w, "old_password required")
		return
	}
	if user.PasswordHash == "" {
		Unauthorized(w, "password not set")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		Unauthorized(w, "invalid old password")
		return
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		Internal(w)
		return
	}

	// Update password and clear reset required flag
	if err := h.store.SetPassword(user.ID, string(hash), false); err != nil {
		Internal(w)
		return
	}

	orgID, _ := middleware.OrgFromContext(r.Context())
	if h.audit != nil && orgID != "" {
		if actorType, actorID, ok := middleware.ActorFromContext(r.Context()); ok {
			_ = h.audit.InsertEvent(&storage.AuditEvent{
				OrgID:      orgID,
				ActorType:  actorType,
				ActorID:    actorID,
				Action:     "password.reset",
				TargetType: "user",
				TargetID:   user.ID,
				Meta: map[string]any{
					"email": user.Email,
				},
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "password updated",
	})
}

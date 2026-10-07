package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
)

type ProfileHandler struct {
	store storage.UserStore
}

func NewProfileHandler(store storage.UserStore) *ProfileHandler {
	return &ProfileHandler{store: store}
}

// GetProfile returns the current user's profile.
// GET /auth/profile
func (h *ProfileHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		MethodNotAllowed(w, http.MethodGet)
		return
	}

	_, actorID, ok := middleware.ActorFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing actor context")
		return
	}

	orgID, _ := middleware.OrgFromContext(r.Context())

	// For session-based auth, actorID is the user ID
	user, err := h.store.GetUser(actorID)
	if err != nil || user == nil {
		// Try by email header fallback
		Unauthorized(w, "user not found")
		return
	}

	// Get role if org context available
	role := ""
	if orgID != "" {
		role, _, _ = h.store.GetOrgUserRole(orgID, user.ID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":             user.ID,
		"email":          user.Email,
		"name":           user.Name,
		"username":       user.Username,
		"avatar_url":     user.AvatarURL,
		"email_verified": user.EmailVerified,
		"role":           role,
		"created_at":     user.CreatedAt,
	})
}

// UpdateProfile updates the current user's profile fields.
// PUT /auth/profile
func (h *ProfileHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		MethodNotAllowed(w, http.MethodPut)
		return
	}

	_, actorID, ok := middleware.ActorFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing actor context")
		return
	}

	user, err := h.store.GetUser(actorID)
	if err != nil || user == nil {
		Unauthorized(w, "user not found")
		return
	}

	var req struct {
		Name      *string `json:"name"`
		Username  *string `json:"username"`
		AvatarURL *string `json:"avatar_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		BadRequest(w, "invalid payload")
		return
	}

	// Validate username if provided
	if req.Username != nil {
		u := strings.TrimSpace(*req.Username)
		req.Username = &u
		if u != "" {
			if len(u) < 3 {
				BadRequest(w, "username must be at least 3 characters")
				return
			}
			if len(u) > 30 {
				BadRequest(w, "username must be at most 30 characters")
				return
			}
			// Check for valid characters (alphanumeric, underscore, hyphen)
			for _, c := range u {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
					BadRequest(w, "username may only contain letters, numbers, underscores, and hyphens")
					return
				}
			}
		}
	}

	if req.Name != nil {
		n := strings.TrimSpace(*req.Name)
		req.Name = &n
	}

	if err := h.store.UpdateProfile(user.ID, req.Name, req.Username, req.AvatarURL); err != nil {
		if strings.Contains(err.Error(), "users_username_unique") {
			BadRequest(w, "username already taken")
			return
		}
		Internal(w)
		return
	}

	// Return updated user
	updated, err := h.store.GetUser(user.ID)
	if err != nil || updated == nil {
		Internal(w)
		return
	}

	orgID, _ := middleware.OrgFromContext(r.Context())
	role := ""
	if orgID != "" {
		role, _, _ = h.store.GetOrgUserRole(orgID, updated.ID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":             updated.ID,
		"email":          updated.Email,
		"name":           updated.Name,
		"username":       updated.Username,
		"avatar_url":     updated.AvatarURL,
		"email_verified": updated.EmailVerified,
		"role":           role,
		"created_at":     updated.CreatedAt,
	})
}

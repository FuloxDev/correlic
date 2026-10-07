package middleware

import (
	"log"
	"net/http"
	"strings"

	"github.com/correlic/correlic-backend/internal/storage"
)

type RoleGuard struct {
	users storage.UserStore
}

func NewRoleGuard(users storage.UserStore) *RoleGuard {
	return &RoleGuard{users: users}
}

func (g *RoleGuard) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actorType, actorID, ok := ActorFromContext(r.Context())
			log.Printf("[RoleGuard] RequireRole(%s) - actorType=%s actorID=%s ok=%v", role, actorType, actorID, ok)

			// Check if actor role is already in context (from API key)
			actorRole, hasRole := ActorRoleFromContext(r.Context())
			if hasRole {
				log.Printf("[RoleGuard] Actor role from context: %s", actorRole)
				if actorRole == role {
					log.Printf("[RoleGuard] Allowing request through (role match from context)")
					next.ServeHTTP(w, r)
					return
				}
				log.Printf("[RoleGuard] Rejecting: role mismatch (context role: %s, required: %s)", actorRole, role)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			// Legacy: API key / mTLS callers without user_id are treated as admin by default
			// (for backward compatibility with old API keys created before user_id migration)
			if actorType == "api_key" || actorType == "mtls" {
				log.Printf("[RoleGuard] Allowing API key/mTLS request through (legacy mode)")
				next.ServeHTTP(w, r)
				return
			}

			// User session: check via X-User-Email header
			email := strings.TrimSpace(r.Header.Get("X-User-Email"))
			log.Printf("[RoleGuard] Checking user email: %s (users store: %v)", email, g.users != nil)
			if email == "" || g.users == nil {
				log.Printf("[RoleGuard] Rejecting: no email or no user store")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			orgID, ok := OrgFromContext(r.Context())
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			user, err := g.users.GetUserByEmail(email)
			if err != nil || user == nil {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			rp, ok, err := g.users.GetOrgUserRole(orgID, user.ID)
			if err != nil || !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			log.Printf("[RoleGuard] User role: %s, required: %s", rp, role)
			if rp != role {
				log.Printf("[RoleGuard] Rejecting: role mismatch")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			log.Printf("[RoleGuard] Allowing request through")
			next.ServeHTTP(w, r)
		})
	}
}

// IsAdminRequest returns true if the request is considered admin.
func IsAdminRequest(r *http.Request, users storage.UserStore) bool {
	// Check context role first (from API key)
	actorRole, hasRole := ActorRoleFromContext(r.Context())
	if hasRole {
		return actorRole == "admin"
	}

	// Legacy: API key / mTLS without user_id = admin
	actorType, _, _ := ActorFromContext(r.Context())
	if actorType == "api_key" || actorType == "mtls" {
		return true
	}

	if users == nil {
		return false
	}
	email := strings.TrimSpace(r.Header.Get("X-User-Email"))
	if email == "" {
		return false
	}
	orgID, ok := OrgFromContext(r.Context())
	if !ok {
		return false
	}
	user, err := users.GetUserByEmail(email)
	if err != nil || user == nil {
		return false
	}
	role, ok, err := users.GetOrgUserRole(orgID, user.ID)
	if err != nil || !ok {
		return false
	}
	return role == "admin"
}

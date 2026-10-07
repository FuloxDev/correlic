package middleware

import (
	"log"
	"net/http"

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

			// No role in the request context: deny. Identity comes from the
			// authenticated session or key only, never from request headers.
			http.Error(w, "forbidden", http.StatusForbidden)
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

	return false
}

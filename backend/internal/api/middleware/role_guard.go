package middleware

import (
	"net/http"

	"github.com/correlic/correlic-backend/internal/storage"
)

// RoleGuard builds role-checking middlewares. Roles come exclusively from the
// request context populated by AuthMiddleware; there is no fallback for
// callers without a role.
type RoleGuard struct{}

// NewRoleGuard creates a RoleGuard. The user store argument is accepted for
// call-site compatibility but is not needed: roles are resolved at auth time.
func NewRoleGuard(_ storage.UserStore) *RoleGuard {
	return &RoleGuard{}
}

// RequireRole allows only actors whose context role equals role.
func (g *RoleGuard) RequireRole(role string) func(http.Handler) http.Handler {
	return RequireAnyRole(role)
}

// RequireAnyRole allows only actors whose context role is one of roles.
// Requests without a role are denied.
func RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := ActorRoleFromContext(r.Context())
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if _, permitted := allowed[role]; !permitted {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AdminForWrites lets any authenticated role perform safe methods (GET, HEAD,
// OPTIONS) but restricts every other method to the admin role.
func AdminForWrites() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			if !IsAdminRequest(r, nil) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// DenyRole rejects actors whose context role equals role and lets every
// other request through. It is used to keep agent credentials off
// human/query routes.
func DenyRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if actorRole, ok := ActorRoleFromContext(r.Context()); ok && actorRole == role {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IsAdminRequest reports whether the request's actor has the admin role.
// The user store argument is unused; it is kept for call-site compatibility.
func IsAdminRequest(r *http.Request, _ storage.UserStore) bool {
	role, ok := ActorRoleFromContext(r.Context())
	return ok && role == RoleAdmin
}

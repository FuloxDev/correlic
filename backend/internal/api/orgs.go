package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
)

type OrgsHandler struct {
	store storage.OrgStore
}

func NewOrgsHandler(store storage.OrgStore) *OrgsHandler {
	return &OrgsHandler{store: store}
}

func (h *OrgsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		log.Printf("[OrgsHandler] missing org context for %s %s", r.Method, r.URL.Path)
		Unauthorized(w, "missing org context")
		return
	}
	log.Printf("[OrgsHandler] org_id=%s method=%s path=%s", orgID, r.Method, r.URL.Path)
	if h.store == nil {
		NotImplemented(w, "org store not enabled")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/orgs")
	if path == "/me" || path == "/me/" {
		if r.Method != http.MethodGet {
			MethodNotAllowed(w, http.MethodGet)
			return
		}
		org, err := h.store.Get(orgID)
		if err != nil {
			Internal(w)
			return
		}
		if org == nil {
			NotFound(w, "org not found")
			return
		}
		role, _ := middleware.ActorRoleFromContext(r.Context())
		actorType, actorID, _ := middleware.ActorFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         org.ID,
			"name":       org.Name,
			"created_at": org.CreatedAt,
			"role":       role,
			"actor_type": actorType,
			"actor_id":   actorID,
		})
		return
	}

	BadRequest(w, "invalid org path")
}

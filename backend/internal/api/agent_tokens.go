package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
	"github.com/google/uuid"
)

// AgentTokensHandler creates agent tokens for the signed-in user.
type AgentTokensHandler struct {
	db        *sql.DB
	userStore storage.UserStore
	audit     storage.AuditStore
}

func NewAgentTokensHandler(db *sql.DB, userStore storage.UserStore, auditStore storage.AuditStore) *AgentTokensHandler {
	return &AgentTokensHandler{db: db, userStore: userStore, audit: auditStore}
}

func (h *AgentTokensHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		MethodNotAllowed(w, http.MethodPost)
		return
	}

	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	actorType, actorID, ok := middleware.ActorFromContext(r.Context())
	if !ok || actorType != "user_session" || actorID == "" {
		Forbidden(w, "agent tokens can only be created by signed-in users")
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		BadRequest(w, "invalid payload")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Agent Token"
	}

	// Verify user exists in org
	if _, exists, err := h.userStore.GetOrgUserRole(orgID, actorID); err != nil {
		Internal(w)
		return
	} else if !exists {
		Forbidden(w, "user not found in organization")
		return
	}

	rawKey, err := generateRawAPIKey()
	if err != nil {
		Internal(w)
		return
	}
	keyHash := sha256Hex(rawKey)

	keyID := uuid.New().String()
	_, err = h.db.Exec(`
		INSERT INTO api_keys (id, org_id, user_id, key_hash, key_type, name, description, created_at)
		VALUES ($1, $2, $3, $4, 'agent', $5, $6, now())
	`, keyID, orgID, actorID, keyHash, name, strings.TrimSpace(req.Description))
	if err != nil {
		Internal(w)
		return
	}

	if h.audit != nil {
		_ = h.audit.InsertEvent(&storage.AuditEvent{
			OrgID:      orgID,
			ActorType:  actorType,
			ActorID:    actorID,
			Action:     "agent_token.create",
			TargetType: "api_key",
			TargetID:   keyID,
			Meta: map[string]any{
				"user_id": actorID,
				"name":    name,
				"type":    "agent",
			},
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":      keyID,
		"api_key": rawKey,
		"name":    name,
		"type":    "agent",
	})
}

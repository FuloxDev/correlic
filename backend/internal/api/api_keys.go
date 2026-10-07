package api

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
	"github.com/google/uuid"
)

// APIKeysHandler manages API keys for service accounts
type APIKeysHandler struct {
	db        *sql.DB
	userStore storage.UserStore
	audit     storage.AuditStore
}

func NewAPIKeysHandler(db *sql.DB, userStore storage.UserStore, auditStore storage.AuditStore) *APIKeysHandler {
	return &APIKeysHandler{
		db:        db,
		userStore: userStore,
		audit:     auditStore,
	}
}

func (h *APIKeysHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.listAPIKeys(w, r, orgID)
	case http.MethodPost:
		h.createAPIKey(w, r, orgID)
	case http.MethodDelete:
		h.revokeAPIKey(w, r, orgID)
	default:
		MethodNotAllowed(w, http.MethodGet+", "+http.MethodPost+", "+http.MethodDelete)
	}
}

func (h *APIKeysHandler) listAPIKeys(w http.ResponseWriter, r *http.Request, orgID string) {
	rows, err := h.db.Query(`
		SELECT 
			ak.id::text,
			ak.user_id::text,
			u.email,
			u.name,
			u.is_service_account,
			ak.key_type,
			ak.name,
			ak.description,
			ak.created_at,
			ak.revoked_at
		FROM api_keys ak
		LEFT JOIN users u ON ak.user_id = u.id
		WHERE ak.org_id = $1::uuid
		ORDER BY ak.created_at DESC
	`, orgID)
	if err != nil {
		http.Error(w, "internal server error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type APIKeyInfo struct {
		ID               string  `json:"id"`
		UserID           *string `json:"user_id"`
		UserEmail        *string `json:"user_email"`
		UserName         *string `json:"user_name"`
		IsServiceAccount bool    `json:"is_service_account"`
		KeyType          string  `json:"key_type"`
		Name             string  `json:"name"`
		Description      string  `json:"description"`
		CreatedAt        string  `json:"created_at"`
		RevokedAt        *string `json:"revoked_at"`
	}

	var keys []APIKeyInfo
	for rows.Next() {
		var k APIKeyInfo
		var userID, email, name sql.NullString
		var revokedAt sql.NullString
		var isServiceAccount sql.NullBool
		err := rows.Scan(
			&k.ID,
			&userID,
			&email,
			&name,
			&isServiceAccount,
			&k.KeyType,
			&k.Name,
			&k.Description,
			&k.CreatedAt,
			&revokedAt,
		)
		if err != nil {
			Internal(w)
			return
		}
		if userID.Valid {
			k.UserID = &userID.String
		}
		if email.Valid {
			k.UserEmail = &email.String
		}
		if name.Valid {
			k.UserName = &name.String
		}
		if isServiceAccount.Valid {
			k.IsServiceAccount = isServiceAccount.Bool
		}
		if revokedAt.Valid {
			k.RevokedAt = &revokedAt.String
		}
		keys = append(keys, k)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "internal server error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(keys); err != nil {
		http.Error(w, "internal server error: failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (h *APIKeysHandler) createAPIKey(w http.ResponseWriter, r *http.Request, orgID string) {
	var req struct {
		UserID      string `json:"user_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		BadRequest(w, "invalid payload")
		return
	}

	userID := strings.TrimSpace(req.UserID)
	name := strings.TrimSpace(req.Name)
	if userID == "" || name == "" {
		BadRequest(w, "user_id and name required")
		return
	}

	// Verify user exists and is in the org
	role, exists, err := h.userStore.GetOrgUserRole(orgID, userID)
	if err != nil {
		Internal(w)
		return
	}
	if !exists {
		BadRequest(w, "user not found in organization")
		return
	}

	// Generate API key
	rawKey, err := generateRawAPIKey()
	if err != nil {
		Internal(w)
		return
	}
	keyHash := sha256Hex(rawKey)

	keyID := uuid.New().String()
	_, err = h.db.Exec(`
		INSERT INTO api_keys (id, org_id, user_id, key_hash, key_type, name, description, created_at)
		VALUES ($1, $2, $3, $4, 'service', $5, $6, now())
	`, keyID, orgID, userID, keyHash, name, req.Description)
	if err != nil {
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
				Action:     "api_key.create",
				TargetType: "api_key",
				TargetID:   keyID,
				Meta: map[string]any{
					"user_id": userID,
					"name":    name,
					"role":    role,
				},
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":      keyID,
		"api_key": rawKey, // Only returned on creation
		"name":    name,
	})
}

func (h *APIKeysHandler) revokeAPIKey(w http.ResponseWriter, r *http.Request, orgID string) {
	keyID := strings.TrimSpace(r.URL.Query().Get("key_id"))
	if keyID == "" {
		BadRequest(w, "key_id required")
		return
	}

	res, err := h.db.Exec(`
		UPDATE api_keys 
		SET revoked_at = now() 
		WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL
	`, keyID, orgID)
	if err != nil {
		Internal(w)
		return
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		BadRequest(w, "no active key found")
		return
	}

	// Audit log
	if h.audit != nil {
		if actorType, actorID, ok := middleware.ActorFromContext(r.Context()); ok {
			_ = h.audit.InsertEvent(&storage.AuditEvent{
				OrgID:      orgID,
				ActorType:  actorType,
				ActorID:    actorID,
				Action:     "api_key.revoke",
				TargetType: "api_key",
				TargetID:   keyID,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "API key revoked",
	})
}

// generateRawAPIKey generates a random 256-bit API key
func generateRawAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sha256Hex hashes the API key using SHA-256
func sha256Hex(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

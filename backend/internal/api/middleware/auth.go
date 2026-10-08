package middleware

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/correlic/correlic-backend/internal/storage"
)

type contextKey string

const orgIDContextKey contextKey = "org_id"
const actorTypeContextKey contextKey = "actor_type"
const actorIDContextKey contextKey = "actor_id"
const actorRoleContextKey contextKey = "actor_role"

// Actor roles. Sessions and service API keys carry the user's org_users.role
// (admin or member). Agent API keys and mTLS-only callers are always "agent".
const (
	RoleAdmin  = "admin"
	RoleMember = "member"
	RoleAgent  = "agent"
)

// Actor types set by the auth middleware.
const (
	ActorTypeAPIKey      = "api_key"
	ActorTypeUserSession = "user_session"
	ActorTypeMTLS        = "mtls"
)

// ErrNoRoleMessage is returned (401) for a service API key whose owner has no
// org_users row. There is no implicit "legacy admin" fallback.
const ErrNoRoleMessage = "api key has no role; recreate it with correlic-admin create-api-key"

// WithOrg injects the org ID into the context
func WithOrg(ctx context.Context, orgID string) context.Context {
	return context.WithValue(ctx, orgIDContextKey, orgID)
}

// OrgFromContext extracts the org ID from the context
func OrgFromContext(ctx context.Context) (string, bool) {
	orgID, ok := ctx.Value(orgIDContextKey).(string)
	return orgID, ok
}

// WithActor injects actor identity into context.
func WithActor(ctx context.Context, actorType string, actorID string) context.Context {
	ctx = context.WithValue(ctx, actorTypeContextKey, actorType)
	return context.WithValue(ctx, actorIDContextKey, actorID)
}

// WithActorRole injects actor role into context.
func WithActorRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, actorRoleContextKey, role)
}

// ActorFromContext extracts actor identity from context.
func ActorFromContext(ctx context.Context) (string, string, bool) {
	t, ok := ctx.Value(actorTypeContextKey).(string)
	if !ok || t == "" {
		return "", "", false
	}
	id, _ := ctx.Value(actorIDContextKey).(string)
	return t, id, true
}

// ActorRoleFromContext extracts actor role from context.
func ActorRoleFromContext(ctx context.Context) (string, bool) {
	role, ok := ctx.Value(actorRoleContextKey).(string)
	return role, ok && role != ""
}

// cachedKeyValidation stores the result of a remote key validation.
type cachedKeyValidation struct {
	Valid       bool
	UserID      string
	ExpiresAt   *time.Time // nil = no expiry
	ValidatedAt time.Time  // when the remote key server last answered for this key
}

// Remote key cache tuning. The cache never holds plaintext keys: entries are
// keyed by SHA-256(key) and re-validation happens on the request path only.
const (
	remoteCacheMaxEntries  = 1000
	remoteCachePositiveTTL = 5 * time.Minute  // re-check a valid key after this
	remoteCacheNegativeTTL = 30 * time.Second // re-check a rejected key after this
	remoteGracePeriod      = 48 * time.Hour   // tolerate an unreachable key server this long
)

type AuthMiddleware struct {
	// apiKeyStore is the store of API keys
	apiKeyStore storage.APIKeyStore
	// clientCertStore maps an enrolled mTLS fingerprint to org_id (optional).
	clientCertStore storage.ClientCertStore
	// userStore holds user sessions (optional).
	userStore       storage.UserStore
	allowAPIKeyAuth bool
	// correlicAPIURL is an optional remote key-validation server; empty disables it
	correlicAPIURL string
	// defaultOrgID is the org UUID assigned to remotely validated keys
	defaultOrgID string
	// validatedKeys is a bounded cache of remote validation results keyed by key hash.
	validatedKeys   map[string]*cachedKeyValidation
	validatedKeysMu sync.Mutex
	// httpClient talks to the remote key server.
	httpClient *http.Client
	// now is the clock (overridable in tests).
	now func() time.Time
}

func NewAuthMiddleware(apiKeyStore storage.APIKeyStore, clientCertStore storage.ClientCertStore, userStore storage.UserStore, db *sql.DB) *AuthMiddleware {
	allow := true
	if v := strings.TrimSpace(strings.ToLower(os.Getenv("ALLOW_API_KEY_AUTH"))); v != "" {
		if v == "0" || v == "false" || v == "no" {
			allow = false
		}
	}

	// Resolve DEFAULT_ORG_ID — if "default" or empty, query the first org from the database
	defaultOrgID := os.Getenv("DEFAULT_ORG_ID")
	if (defaultOrgID == "" || defaultOrgID == "default") && db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var id string
		if err := db.QueryRowContext(ctx, "SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&id); err == nil && id != "" {
			defaultOrgID = id
			log.Printf("[AUTH] Resolved DEFAULT_ORG_ID from database: %s", defaultOrgID)
		} else {
			log.Printf("[AUTH] WARNING: Could not resolve DEFAULT_ORG_ID from database: %v", err)
		}
	}

	return &AuthMiddleware{
		apiKeyStore:     apiKeyStore,
		clientCertStore: clientCertStore,
		userStore:       userStore,
		allowAPIKeyAuth: allow,
		// Optional remote key-validation server. Empty (the default) disables
		// remote validation entirely: only keys and sessions in the local
		// database are accepted.
		correlicAPIURL: strings.TrimSpace(os.Getenv("CORRELIC_API_URL")),
		defaultOrgID:   defaultOrgID,
		validatedKeys:  make(map[string]*cachedKeyValidation),
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		now:            func() time.Time { return time.Now().UTC() },
	}
}

// callCorrelicVerify calls {CORRELIC_API_URL}/keys/verify and returns the result, or nil on network error.
func (m *AuthMiddleware) callCorrelicVerify(apiKey string) *cachedKeyValidation {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/keys/verify", m.correlicAPIURL), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("x-api-key", apiKey)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		log.Printf("[AUTH] remote key server unreachable: %v", err)
		return nil // network error — let grace period handle it
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	now := m.now()

	if resp.StatusCode != http.StatusOK {
		// Key rejected by server (revoked, expired, invalid)
		return &cachedKeyValidation{Valid: false, ValidatedAt: now}
	}

	var result struct {
		Valid     bool    `json:"valid"`
		UserID    string  `json:"userId"`
		ExpiresAt *string `json:"expiresAt"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return &cachedKeyValidation{Valid: false, ValidatedAt: now}
	}

	cached := &cachedKeyValidation{
		Valid:       result.Valid,
		UserID:      result.UserID,
		ValidatedAt: now,
	}
	if result.ExpiresAt != nil {
		if t, err := time.Parse(time.RFC3339, *result.ExpiresAt); err == nil {
			cached.ExpiresAt = &t
		}
	}

	return cached
}

// storeValidation inserts a validation result, evicting stale or oldest
// entries so the cache never exceeds remoteCacheMaxEntries.
func (m *AuthMiddleware) storeValidation(hash string, v *cachedKeyValidation) {
	m.validatedKeysMu.Lock()
	defer m.validatedKeysMu.Unlock()

	if _, exists := m.validatedKeys[hash]; !exists && len(m.validatedKeys) >= remoteCacheMaxEntries {
		m.evictLocked(v.ValidatedAt)
	}
	m.validatedKeys[hash] = v
}

// evictLocked drops entries that can no longer be useful (rejected entries past
// the negative TTL, valid entries past the grace period) and, if the cache is
// still full, the single oldest entry. Caller must hold validatedKeysMu.
func (m *AuthMiddleware) evictLocked(now time.Time) {
	for h, e := range m.validatedKeys {
		age := now.Sub(e.ValidatedAt)
		if (!e.Valid && age >= remoteCacheNegativeTTL) || (e.Valid && age >= remoteGracePeriod) {
			delete(m.validatedKeys, h)
		}
	}
	if len(m.validatedKeys) < remoteCacheMaxEntries {
		return
	}
	var oldestHash string
	var oldest time.Time
	for h, e := range m.validatedKeys {
		if oldestHash == "" || e.ValidatedAt.Before(oldest) {
			oldestHash, oldest = h, e.ValidatedAt
		}
	}
	if oldestHash != "" {
		delete(m.validatedKeys, oldestHash)
	}
}

// validateKeyAgainstCorrelic validates an API key against the remote key
// server with a bounded TTL cache (5 min positive, 30 s negative) and a 48 h
// grace period when the server is unreachable.
// Returns the cached validation result and whether the key is valid.
func (m *AuthMiddleware) validateKeyAgainstCorrelic(apiKey string) (*cachedKeyValidation, bool) {
	if m.correlicAPIURL == "" {
		return nil, false
	}

	hash := hashAPIKey(apiKey)
	now := m.now()

	m.validatedKeysMu.Lock()
	cached, hasCached := m.validatedKeys[hash]
	m.validatedKeysMu.Unlock()

	if hasCached {
		if cached.Valid && cached.ExpiresAt != nil && now.After(*cached.ExpiresAt) {
			// Key expired since last validation — record the rejection.
			expired := &cachedKeyValidation{Valid: false, ExpiresAt: cached.ExpiresAt, ValidatedAt: now}
			m.storeValidation(hash, expired)
			return expired, false
		}
		age := now.Sub(cached.ValidatedAt)
		if cached.Valid && age < remoteCachePositiveTTL {
			return cached, true
		}
		if !cached.Valid && age < remoteCacheNegativeTTL {
			return cached, false
		}
	}

	// Call the remote key server
	if result := m.callCorrelicVerify(apiKey); result != nil {
		m.storeValidation(hash, result)
		if !result.Valid {
			log.Printf("[AUTH] key rejected by remote key server")
		}
		return result, result.Valid
	}

	// Network error — apply grace period to a previously valid entry.
	if hasCached && cached.Valid {
		if now.Sub(cached.ValidatedAt) < remoteGracePeriod {
			log.Printf("[AUTH] remote key server unreachable — using cached validation (grace period: %v remaining)",
				remoteGracePeriod-now.Sub(cached.ValidatedAt))
			return cached, true
		}
		log.Printf("[AUTH] remote key server unreachable for >%v — lockout", remoteGracePeriod)
		return cached, false
	}

	// No cache, no server — reject
	return nil, false
}

// extractAPIKeyFromAuthorizationHeader extracts the API key from the authorization header
func extractAPIKeyFromAuthorizationHeader(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	parts := strings.Fields(raw)
	switch len(parts) {
	case 1:
		return parts[0], true
	case 2:
		switch strings.ToLower(parts[0]) {
		case "bearer", "apikey":
			if parts[1] == "" {
				return "", false
			}
			return parts[1], true
		default:
			return "", false
		}
	default:
		return "", false
	}
}

// hashAPIKey hashes the API key using SHA-256
func hashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// writeUnauthorizedJSON writes a 401 with a machine-readable code.
func writeUnauthorizedJSON(w http.ResponseWriter, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "unauthorized",
		"code":    code,
		"message": message,
	})
}

// Wrap wraps the next handler with the authentication middleware
func (m *AuthMiddleware) Wrap(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Optional API key auth.
		raw := r.Header.Get("Authorization")
		apiKey, hasAPIKey := extractAPIKeyFromAuthorizationHeader(raw)
		if hasAPIKey && (m == nil || !m.allowAPIKeyAuth) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Optional mTLS auth (requires enrollment store to derive org).
		fp, hasFP := ClientCertFingerprintFromContext(r.Context())
		if !hasFP {
			fp, hasFP = clientCertFingerprintFromRequest(r)
		}

		var orgID string
		var actorType string
		var actorID string
		var actorRole string
		var centrallyValidated bool

		if hasAPIKey {
			tokenHash := hashAPIKey(apiKey)

			if m.apiKeyStore != nil {
				// Try local API key lookup first
				keyInfo, err := m.apiKeyStore.LookupKeyInfo(tokenHash)
				if err == nil && keyInfo != nil {
					orgID = keyInfo.OrgID
					actorType = ActorTypeAPIKey
					actorID = keyInfo.UserID
					if actorID == "" {
						actorID = tokenHash
					}
					switch {
					case keyInfo.KeyType == storage.APIKeyTypeAgent:
						// Agent keys act as the agent role regardless of any org_users row.
						actorRole = RoleAgent
					case keyInfo.Role != "":
						actorRole = keyInfo.Role
					default:
						// Service key whose owner has no org_users row: reject.
						log.Printf("[AUTH] api key without org role rejected: org=%s remote=%s", orgID, r.RemoteAddr)
						writeUnauthorizedJSON(w, "KEY_NO_ROLE", ErrNoRoleMessage)
						return
					}
				} else if err != nil && err != sql.ErrNoRows {
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
			}

			if orgID == "" && m.userStore != nil {
				session, err := m.userStore.GetSessionByHash(tokenHash)
				if err != nil && err != sql.ErrNoRows {
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
				if session != nil {
					if m.now().After(session.ExpiresAt) {
						log.Printf("[AUTH] session expired user_id=%s remote=%s", session.UserID, r.RemoteAddr)
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					oid, err := m.userStore.GetUserOrgID(session.UserID)
					if err != nil || oid == "" {
						log.Printf("[AUTH] no org for user_id=%s remote=%s err=%v", session.UserID, r.RemoteAddr, err)
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					// Role comes from org_users only.
					role, found, err := m.userStore.GetOrgUserRole(oid, session.UserID)
					if err != nil {
						http.Error(w, "internal server error", http.StatusInternalServerError)
						return
					}
					if !found || role == "" {
						log.Printf("[AUTH] session user without org role rejected user_id=%s org=%s", session.UserID, oid)
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					orgID = oid
					actorType = ActorTypeUserSession
					actorID = session.UserID
					actorRole = role
				}
			}

			// Optional remote key server (CORRELIC_API_URL). Only consulted when
			// configured and only after every local lookup has failed, so local
			// session tokens are never sent anywhere.
			if orgID == "" && m.correlicAPIURL != "" {
				if cached, valid := m.validateKeyAgainstCorrelic(apiKey); valid && cached != nil {
					orgID = m.defaultOrgID
					actorType = ActorTypeAPIKey
					centrallyValidated = true
					actorID = cached.UserID
					if actorID == "" {
						actorID = tokenHash
					}
					// Centrally validated keys are never implicitly admin: they
					// get "member" unless a local org_users row says otherwise.
					actorRole = RoleMember
					if m.userStore != nil && cached.UserID != "" {
						if role, found, err := m.userStore.GetOrgUserRole(orgID, cached.UserID); err == nil && found && role != "" {
							actorRole = role
						}
					}
				} else if cached != nil && !cached.Valid {
					// Key explicitly rejected (expired or revoked)
					if cached.ExpiresAt != nil && m.now().After(*cached.ExpiresAt) {
						writeUnauthorizedJSON(w, "KEY_EXPIRED", "API key expired")
						return
					}
				}
			}

			if orgID == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// If the request also presents a client cert, require it to map to the same org.
			// Skip this check for remotely validated keys — the cert may not be enrolled locally.
			if hasFP && m.clientCertStore != nil && !centrallyValidated {
				oid2, err := m.clientCertStore.LookupOrgIDByFingerprint(fp)
				if err != nil {
					if err == sql.ErrNoRows {
						MTLSUnenrolledCertTotal.Add(1)
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
				if oid2 != orgID {
					log.Printf("[AUTH] org mismatch: api_key org=%s cert org=%s remote=%s", orgID, oid2, r.RemoteAddr)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
		} else {
			// No API key: allow mTLS-only if we can map fingerprint -> org.
			// An enrolled client certificate on its own identifies an agent.
			if !hasFP || m.clientCertStore == nil {
				http.Error(w, "missing credentials", http.StatusUnauthorized)
				return
			}
			oid, err := m.clientCertStore.LookupOrgIDByFingerprint(fp)
			if err != nil {
				if err == sql.ErrNoRows {
					MTLSUnenrolledCertTotal.Add(1)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			orgID = oid
			actorType = ActorTypeMTLS
			actorID = fp
			actorRole = RoleAgent
		}

		ctx := WithOrg(r.Context(), orgID)
		if actorType != "" {
			ctx = WithActor(ctx, actorType, actorID)
		}
		if actorRole != "" {
			ctx = WithActorRole(ctx, actorRole)
		}
		// serve the request
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

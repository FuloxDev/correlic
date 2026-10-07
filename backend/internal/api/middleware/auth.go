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
	return role, ok
}

// cachedKeyValidation stores the result of a remote key validation with TTL.
type cachedKeyValidation struct {
	Valid       bool
	UserID      string
	ExpiresAt   *time.Time // nil = no expiry
	ValidatedAt time.Time  // when the remote key server last confirmed this key
}

const (
	cacheRevalidateInterval = 6 * time.Hour  // re-check the remote key server every 6h
	gracePeriod             = 48 * time.Hour // allow offline for up to 48h
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
	// validatedKeys caches centrally validated keys with TTL
	validatedKeys   map[string]*cachedKeyValidation
	validatedKeysMu sync.RWMutex
	// rawKeys maps hash → plaintext for background re-validation
	rawKeys   map[string]string
	rawKeysMu sync.RWMutex
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

	m := &AuthMiddleware{
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
		rawKeys:        make(map[string]string),
	}

	// Start background re-validation goroutine
	if m.correlicAPIURL != "" {
		go m.backgroundRevalidation()
	}

	return m
}

// backgroundRevalidation periodically re-validates all cached keys against the remote key server.
func (m *AuthMiddleware) backgroundRevalidation() {
	ticker := time.NewTicker(cacheRevalidateInterval)
	defer ticker.Stop()
	for range ticker.C {
		m.rawKeysMu.RLock()
		keys := make(map[string]string, len(m.rawKeys))
		for hash, raw := range m.rawKeys {
			keys[hash] = raw
		}
		m.rawKeysMu.RUnlock()

		for hash, rawKey := range keys {
			result := m.callCorrelicVerify(rawKey)
			m.validatedKeysMu.Lock()
			if result != nil {
				m.validatedKeys[hash] = result
				if !result.Valid {
					log.Printf("[AUTH] background re-validation: key %s…  is now INVALID", hash[:12])
				}
			}
			m.validatedKeysMu.Unlock()
		}
	}
}

// callCorrelicVerify calls {CORRELIC_API_URL}/keys/verify and returns the result, or nil on network error.
func (m *AuthMiddleware) callCorrelicVerify(apiKey string) *cachedKeyValidation {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/keys/verify", m.correlicAPIURL), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("x-api-key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[AUTH] remote key server unreachable: %v", err)
		return nil // network error — let grace period handle it
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	now := time.Now().UTC()

	if resp.StatusCode != 200 {
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

// validateKeyAgainstCorrelic validates an API key with TTL cache and 48h grace period.
// Returns the cached validation result and whether the key is valid.
func (m *AuthMiddleware) validateKeyAgainstCorrelic(apiKey string) (*cachedKeyValidation, bool) {
	if m.correlicAPIURL == "" {
		return nil, false
	}

	hash := hashAPIKey(apiKey)
	now := time.Now().UTC()

	// Check cache — if fresh enough and key not expired, return cached
	m.validatedKeysMu.RLock()
	cached, hasCached := m.validatedKeys[hash]
	m.validatedKeysMu.RUnlock()

	if hasCached && cached.Valid {
		// Check if key has expired since last validation
		if cached.ExpiresAt != nil && now.After(*cached.ExpiresAt) {
			// Key expired — invalidate cache
			m.validatedKeysMu.Lock()
			cached.Valid = false
			m.validatedKeysMu.Unlock()
			return cached, false
		}
		// If validated recently, use cache
		if now.Sub(cached.ValidatedAt) < cacheRevalidateInterval {
			return cached, true
		}
	}

	// Call the remote key server
	result := m.callCorrelicVerify(apiKey)

	if result != nil {
		// Server responded — update cache
		m.validatedKeysMu.Lock()
		m.validatedKeys[hash] = result
		m.validatedKeysMu.Unlock()

		// Store raw key for background re-validation
		m.rawKeysMu.Lock()
		m.rawKeys[hash] = apiKey
		m.rawKeysMu.Unlock()

		if result.Valid {
			log.Printf("[AUTH] key validated via remote key server (expires: %v)", result.ExpiresAt)
		} else {
			log.Printf("[AUTH] key rejected by remote key server")
		}
		return result, result.Valid
	}

	// Network error — apply grace period
	if hasCached && cached.Valid {
		if now.Sub(cached.ValidatedAt) < gracePeriod {
			log.Printf("[AUTH] remote key server unreachable — using cached validation (grace period: %v remaining)",
				gracePeriod-now.Sub(cached.ValidatedAt))
			return cached, true
		}
		// Grace period exceeded
		log.Printf("[AUTH] remote key server unreachable for >48h — lockout")
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
					actorType = "api_key"
					actorID = keyInfo.UserID
					if actorID == "" {
						actorID = tokenHash
					}
					actorRole = keyInfo.Role
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
					if time.Now().UTC().After(session.ExpiresAt) {
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
					// Get role from org_users
					role, found, err := m.userStore.GetOrgUserRole(oid, session.UserID)
					if err != nil {
						http.Error(w, "internal server error", http.StatusInternalServerError)
						return
					}
					orgID = oid
					actorType = "user_session"
					actorID = session.UserID
					if found {
						actorRole = role
					}
				}
			}

			// Optional remote key server (CORRELIC_API_URL). Only consulted when
			// configured and only after every local lookup has failed, so local
			// session tokens are never sent anywhere.
			if orgID == "" && m.correlicAPIURL != "" {
				if cached, valid := m.validateKeyAgainstCorrelic(apiKey); valid && cached != nil {
					orgID = m.defaultOrgID
					actorType = "api_key"
					centrallyValidated = true
					actorID = cached.UserID
					if actorID == "" {
						actorID = tokenHash
					}
					actorRole = "admin"
				} else if cached != nil && !cached.Valid {
					// Key explicitly rejected (expired or revoked)
					if cached.ExpiresAt != nil && time.Now().UTC().After(*cached.ExpiresAt) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusUnauthorized)
						w.Write([]byte(`{"error":"unauthorized","code":"KEY_EXPIRED","message":"API key expired"}`))
						return
					}
				}
			}

			if orgID == "" {
				// log.Printf("[AUTH DEBUG] Authorization token not found in API keys or sessions")
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
			if !hasFP || m.clientCertStore == nil {
				log.Printf("!!! [AUTH DEBUG] No API key and no mTLS fp. Rejecting! !!!")
				http.Error(w, "missing credentials", http.StatusUnauthorized)
				return
			}
			oid, err := m.clientCertStore.LookupOrgIDByFingerprint(fp)
			if err != nil {
				if err == sql.ErrNoRows {
					log.Printf("!!! [AUTH DEBUG] mTLS fingerprint not enrolled in client_certs: %s !!!", fp)
					MTLSUnenrolledCertTotal.Add(1)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			orgID = oid
			actorType = "mtls"
			actorID = fp
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

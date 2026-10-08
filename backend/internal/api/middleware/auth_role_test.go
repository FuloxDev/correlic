package middleware

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/storage"
)

// fakeKeyInfoStore returns a fixed APIKeyInfo for any hash.
type fakeKeyInfoStore struct {
	info *storage.APIKeyInfo
	err  error
}

func (s *fakeKeyInfoStore) LookupOrgID(string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.info == nil {
		return "", sql.ErrNoRows
	}
	return s.info.OrgID, nil
}

func (s *fakeKeyInfoStore) LookupKeyInfo(string) (*storage.APIKeyInfo, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.info == nil {
		return nil, sql.ErrNoRows
	}
	cp := *s.info
	return &cp, nil
}

// fakeUserStore implements only the UserStore methods the auth middleware
// touches; everything else panics through the embedded nil interface.
type fakeUserStore struct {
	storage.UserStore
	session *storage.Session
	orgID   string
	role    string
	hasRole bool
}

func (s *fakeUserStore) GetSessionByHash(string) (*storage.Session, error) {
	return s.session, nil
}

func (s *fakeUserStore) GetUserOrgID(string) (string, error) {
	return s.orgID, nil
}

func (s *fakeUserStore) GetOrgUserRole(string, string) (string, bool, error) {
	return s.role, s.hasRole, nil
}

// captureHandler records the org, actor and role the middleware injected.
type captured struct {
	org, actorType, actorID, role string
	hasRole                       bool
}

func captureHandler(got *captured) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.org, _ = OrgFromContext(r.Context())
		got.actorType, got.actorID, _ = ActorFromContext(r.Context())
		got.role, got.hasRole = ActorRoleFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

func TestAuth_AgentKeyGetsAgentRole(t *testing.T) {
	t.Setenv("ALLOW_API_KEY_AUTH", "true")
	keys := &fakeKeyInfoStore{info: &storage.APIKeyInfo{OrgID: "org1", UserID: "user-1", Role: "admin", KeyType: storage.APIKeyTypeAgent}}
	m := NewAuthMiddleware(keys, &fakeClientCertStore{orgID: "org1"}, nil, nil)

	var got captured
	req := httptest.NewRequest(http.MethodPost, "/heartbeat", nil)
	req.Header.Set("Authorization", "Bearer agentkey")
	rr := httptest.NewRecorder()
	m.Wrap(captureHandler(&got)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rr.Code)
	}
	// Even though the owner is an org admin, an agent key is always "agent".
	if got.role != RoleAgent || got.org != "org1" || got.actorType != ActorTypeAPIKey || got.actorID != "user-1" {
		t.Fatalf("got %+v", got)
	}
}

func TestAuth_ServiceKeyUsesOrgRole(t *testing.T) {
	t.Setenv("ALLOW_API_KEY_AUTH", "true")
	keys := &fakeKeyInfoStore{info: &storage.APIKeyInfo{OrgID: "org1", UserID: "user-2", Role: "member", KeyType: storage.APIKeyTypeService}}
	m := NewAuthMiddleware(keys, nil, nil, nil)

	var got captured
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	req.Header.Set("Authorization", "svckey")
	rr := httptest.NewRecorder()
	m.Wrap(captureHandler(&got)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || got.role != RoleMember {
		t.Fatalf("status=%d role=%q want 200/member", rr.Code, got.role)
	}
}

func TestAuth_ServiceKeyWithoutRoleIsRejected(t *testing.T) {
	t.Setenv("ALLOW_API_KEY_AUTH", "true")
	keys := &fakeKeyInfoStore{info: &storage.APIKeyInfo{OrgID: "org1", UserID: "", Role: "", KeyType: storage.APIKeyTypeService}}
	m := NewAuthMiddleware(keys, nil, nil, nil)

	called := false
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	req.Header.Set("Authorization", "legacykey")
	rr := httptest.NewRecorder()
	m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })).ServeHTTP(rr, req)

	if called {
		t.Fatalf("handler must not run for a role-less key")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rr.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rr.Body.String())
	}
	if body["message"] != ErrNoRoleMessage || body["code"] != "KEY_NO_ROLE" {
		t.Fatalf("unexpected body: %v", body)
	}
}

func TestAuth_MTLSOnlyIsAgent(t *testing.T) {
	t.Setenv("ALLOW_API_KEY_AUTH", "true")
	m := NewAuthMiddleware(&fakeKeyInfoStore{}, &fakeClientCertStore{orgID: "org-cert"}, nil, nil)

	var got captured
	req := httptest.NewRequest(http.MethodPost, "/ingest/events", nil)
	req = req.WithContext(WithClientCertFingerprint(req.Context(), "deadbeef"))
	rr := httptest.NewRecorder()
	m.Wrap(captureHandler(&got)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rr.Code)
	}
	if got.role != RoleAgent || got.actorType != ActorTypeMTLS || got.actorID != "deadbeef" || got.org != "org-cert" {
		t.Fatalf("got %+v", got)
	}
}

func TestAuth_SessionUsesOrgRole(t *testing.T) {
	t.Setenv("ALLOW_API_KEY_AUTH", "true")
	users := &fakeUserStore{
		session: &storage.Session{ID: "s1", UserID: "user-9", ExpiresAt: time.Now().Add(time.Hour)},
		orgID:   "org1",
		role:    "admin",
		hasRole: true,
	}
	m := NewAuthMiddleware(&fakeKeyInfoStore{}, nil, users, nil)

	var got captured
	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	req.Header.Set("Authorization", "Bearer sessiontoken")
	rr := httptest.NewRecorder()
	m.Wrap(captureHandler(&got)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || got.role != RoleAdmin || got.actorType != ActorTypeUserSession || got.actorID != "user-9" {
		t.Fatalf("status=%d got=%+v", rr.Code, got)
	}
}

func TestAuth_SessionWithoutOrgRoleIsRejected(t *testing.T) {
	t.Setenv("ALLOW_API_KEY_AUTH", "true")
	users := &fakeUserStore{
		session: &storage.Session{ID: "s1", UserID: "user-9", ExpiresAt: time.Now().Add(time.Hour)},
		orgID:   "org1",
		hasRole: false,
	}
	m := NewAuthMiddleware(&fakeKeyInfoStore{}, nil, users, nil)

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	req.Header.Set("Authorization", "Bearer sessiontoken")
	rr := httptest.NewRecorder()
	m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rr.Code)
	}
}

func TestAuth_RemoteKeyIsMemberNotAdmin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys/verify" || r.Header.Get("x-api-key") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprint(w, `{"valid":true,"userId":"remote-user"}`)
	}))
	defer srv.Close()

	t.Setenv("ALLOW_API_KEY_AUTH", "true")
	t.Setenv("CORRELIC_API_URL", srv.URL)
	t.Setenv("DEFAULT_ORG_ID", "org-remote")
	m := NewAuthMiddleware(&fakeKeyInfoStore{}, nil, nil, nil)

	var got captured
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	req.Header.Set("Authorization", "Bearer remotekey")
	rr := httptest.NewRecorder()
	m.Wrap(captureHandler(&got)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rr.Code)
	}
	if got.role != RoleMember || got.org != "org-remote" || got.actorID != "remote-user" {
		t.Fatalf("got %+v", got)
	}
	if len(m.validatedKeys) != 1 {
		t.Fatalf("expected one cached validation, got %d", len(m.validatedKeys))
	}
	for hash := range m.validatedKeys {
		if strings.Contains(hash, "remotekey") {
			t.Fatalf("cache must be keyed by hash, not plaintext")
		}
	}
}

func TestAuth_RemoteCacheIsBounded(t *testing.T) {
	m := &AuthMiddleware{
		validatedKeys: make(map[string]*cachedKeyValidation),
		now:           func() time.Time { return time.Now().UTC() },
	}
	base := time.Now().UTC()
	for i := 0; i < remoteCacheMaxEntries+50; i++ {
		m.storeValidation(fmt.Sprintf("hash-%d", i), &cachedKeyValidation{Valid: true, ValidatedAt: base.Add(time.Duration(i) * time.Millisecond)})
	}
	if len(m.validatedKeys) > remoteCacheMaxEntries {
		t.Fatalf("cache grew to %d entries, max %d", len(m.validatedKeys), remoteCacheMaxEntries)
	}
	// The newest entry must survive eviction; the oldest must be gone.
	if _, ok := m.validatedKeys[fmt.Sprintf("hash-%d", remoteCacheMaxEntries+49)]; !ok {
		t.Fatalf("newest entry evicted")
	}
	if _, ok := m.validatedKeys["hash-0"]; ok {
		t.Fatalf("oldest entry not evicted")
	}
}

func TestAuth_RemoteCacheTTLs(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = fmt.Fprint(w, `{"valid":true}`)
	}))
	defer srv.Close()

	now := time.Now().UTC()
	m := &AuthMiddleware{
		correlicAPIURL: srv.URL,
		validatedKeys:  make(map[string]*cachedKeyValidation),
		httpClient:     srv.Client(),
		now:            func() time.Time { return now },
	}

	if _, ok := m.validateKeyAgainstCorrelic("k"); !ok || calls != 1 {
		t.Fatalf("first validation: ok=%v calls=%d", ok, calls)
	}
	// Within the positive TTL: served from cache.
	now = now.Add(remoteCachePositiveTTL - time.Second)
	if _, ok := m.validateKeyAgainstCorrelic("k"); !ok || calls != 1 {
		t.Fatalf("cached validation: ok=%v calls=%d", ok, calls)
	}
	// Past the positive TTL: re-validated.
	now = now.Add(2 * time.Second)
	if _, ok := m.validateKeyAgainstCorrelic("k"); !ok || calls != 2 {
		t.Fatalf("re-validation: ok=%v calls=%d", ok, calls)
	}
}

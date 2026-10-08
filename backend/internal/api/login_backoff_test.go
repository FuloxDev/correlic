package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/correlic/correlic-backend/internal/storage"
)

func TestLoginBackoff_LocksAfterThresholdAndResets(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := newLoginBackoff()
	b.now = func() time.Time { return now }

	for i := 0; i < loginBackoffMaxFailures-1; i++ {
		b.RecordFailure("User@Example.com")
		if blocked, _ := b.Blocked("user@example.com"); blocked {
			t.Fatalf("blocked after %d failures", i+1)
		}
	}
	b.RecordFailure("user@example.com")
	blocked, retry := b.Blocked("USER@example.com")
	if !blocked || retry <= 0 || retry > loginBackoffLockout {
		t.Fatalf("expected lockout after %d failures, blocked=%v retry=%v", loginBackoffMaxFailures, blocked, retry)
	}

	// Still blocked just before the lockout ends, free right after.
	now = now.Add(loginBackoffLockout - time.Second)
	if blocked, _ := b.Blocked("user@example.com"); !blocked {
		t.Fatalf("lockout ended early")
	}
	now = now.Add(2 * time.Second)
	if blocked, _ := b.Blocked("user@example.com"); blocked {
		t.Fatalf("lockout did not expire")
	}

	// A successful login clears the slate.
	b.RecordFailure("user@example.com")
	b.Reset("user@example.com")
	if _, ok := b.entries["user@example.com"]; ok {
		t.Fatalf("Reset did not clear entry")
	}
}

func TestLoginBackoff_WindowExpiryResetsCount(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := newLoginBackoff()
	b.now = func() time.Time { return now }

	for i := 0; i < loginBackoffMaxFailures-1; i++ {
		b.RecordFailure("a@example.com")
	}
	// Failures older than the window do not count towards the threshold.
	now = now.Add(loginBackoffWindow + time.Minute)
	b.RecordFailure("a@example.com")
	if blocked, _ := b.Blocked("a@example.com"); blocked {
		t.Fatalf("stale failures counted towards lockout")
	}
	if b.entries["a@example.com"].failures != 1 {
		t.Fatalf("failures=%d want 1", b.entries["a@example.com"].failures)
	}
}

func TestLoginBackoff_Bounded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := newLoginBackoff()
	b.maxEntries = 3
	b.now = func() time.Time { return now }

	for i, email := range []string{"a@x", "b@x", "c@x", "d@x", "e@x"} {
		now = now.Add(time.Second)
		b.RecordFailure(email)
		if len(b.entries) > b.maxEntries {
			t.Fatalf("after %d inserts: %d entries, max %d", i+1, len(b.entries), b.maxEntries)
		}
	}
	if _, ok := b.entries["e@x"]; !ok {
		t.Fatalf("newest entry evicted")
	}
	if _, ok := b.entries["a@x"]; ok {
		t.Fatalf("oldest entry retained")
	}
}

// fakeSessionUserStore implements the UserStore methods the sessions handler
// uses; everything else panics through the embedded nil interface.
type fakeSessionUserStore struct {
	storage.UserStore
	user     *storage.User
	sessions []*storage.Session
}

func (s *fakeSessionUserStore) GetUserByEmail(email string) (*storage.User, error) {
	if s.user != nil && s.user.Email == email {
		return s.user, nil
	}
	return nil, nil
}

func (s *fakeSessionUserStore) GetUserOrgID(string) (string, error) { return "org1", nil }

func (s *fakeSessionUserStore) CreateSession(userID, tokenHash string, expiresAt time.Time) (*storage.Session, error) {
	sess := &storage.Session{ID: "s1", UserID: userID, TokenHash: tokenHash, CreatedAt: time.Now().UTC(), ExpiresAt: expiresAt}
	s.sessions = append(s.sessions, sess)
	return sess, nil
}

func (s *fakeSessionUserStore) GetSessionByHash(hash string) (*storage.Session, error) {
	for _, sess := range s.sessions {
		if sess.TokenHash == hash {
			return sess, nil
		}
	}
	return nil, nil
}

type fakeRevoker struct{ deleted []string }

func (r *fakeRevoker) DeleteSessionByTokenHash(h string) error {
	r.deleted = append(r.deleted, h)
	return nil
}

func newSessionsFixture(t *testing.T) (*SessionsHandler, *fakeSessionUserStore, *fakeRevoker) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	users := &fakeSessionUserStore{user: &storage.User{
		ID:            "user-1",
		Email:         "u@example.com",
		EmailVerified: true,
		PasswordHash:  string(hash),
	}}
	revoker := &fakeRevoker{}
	return NewSessionsHandler(users, revoker, nil), users, revoker
}

func postLogin(h http.Handler, email, password string, ttl int) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"email": email, "password": password, "ttl_hours": ttl})
	req := httptest.NewRequest(http.MethodPost, "/auth/sessions", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestSessionsHandler_BackoffReturns429(t *testing.T) {
	h, _, _ := newSessionsFixture(t)

	for i := 0; i < loginBackoffMaxFailures; i++ {
		if rr := postLogin(h, "u@example.com", "wrong", 0); rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d want 401", i+1, rr.Code)
		}
	}
	rr := postLogin(h, "u@example.com", "correct horse", 0)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("locked account: status=%d want 429 (body %s)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatalf("missing Retry-After")
	}
	// Another account is unaffected.
	if rr := postLogin(h, "other@example.com", "x", 0); rr.Code != http.StatusUnauthorized {
		t.Fatalf("other account: status=%d want 401", rr.Code)
	}
}

func TestSessionsHandler_LoginCapsTTL(t *testing.T) {
	h, users, _ := newSessionsFixture(t)

	rr := postLogin(h, "u@example.com", "correct horse", 1000)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(users.sessions) != 1 {
		t.Fatalf("sessions=%d want 1", len(users.sessions))
	}
	ttl := time.Until(users.sessions[0].ExpiresAt)
	if ttl > time.Duration(sessionTTLMaxHours)*time.Hour || ttl < time.Duration(sessionTTLMaxHours-1)*time.Hour {
		t.Fatalf("ttl=%v want ~%dh", ttl, sessionTTLMaxHours)
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || resp.Token == "" {
		t.Fatalf("bad login response: %v %s", err, rr.Body.String())
	}

	// Default TTL when none requested.
	users.sessions = nil
	if rr := postLogin(h, "u@example.com", "correct horse", 0); rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	ttl = time.Until(users.sessions[0].ExpiresAt)
	if ttl > time.Duration(sessionTTLDefaultHours)*time.Hour || ttl < time.Duration(sessionTTLDefaultHours-1)*time.Hour {
		t.Fatalf("default ttl=%v want ~%dh", ttl, sessionTTLDefaultHours)
	}
}

func TestSessionsHandler_DeleteRevokesPresentedToken(t *testing.T) {
	h, users, revoker := newSessionsFixture(t)

	rr := postLogin(h, "u@example.com", "correct horse", 0)
	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	sum := sha256.Sum256([]byte(resp.Token))
	wantHash := hex.EncodeToString(sum[:])
	if users.sessions[0].TokenHash != wantHash {
		t.Fatalf("fixture mismatch")
	}

	req := httptest.NewRequest(http.MethodDelete, "/auth/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d want 204", rr.Code)
	}
	if len(revoker.deleted) != 1 || revoker.deleted[0] != wantHash {
		t.Fatalf("revoked=%v want [%s]", revoker.deleted, wantHash)
	}

	// No token → 401, nothing revoked.
	req = httptest.NewRequest(http.MethodDelete, "/auth/sessions", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || len(revoker.deleted) != 1 {
		t.Fatalf("status=%d revoked=%v", rr.Code, revoker.deleted)
	}
}

func TestNormalizeUserRole(t *testing.T) {
	cases := []struct {
		in, def string
		want    string
		ok      bool
	}{
		{"admin", "", "admin", true},
		{" Member ", "", "member", true},
		{"", "member", "member", true},
		{"", "", "", false},
		{"agent", "", "", false},
		{"owner", "member", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeUserRole(tc.in, tc.def)
		if got != tc.want || ok != tc.ok {
			t.Errorf("normalizeUserRole(%q,%q)=(%q,%v) want (%q,%v)", tc.in, tc.def, got, ok, tc.want, tc.ok)
		}
	}
}

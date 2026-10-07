package middleware

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/correlic/correlic-backend/internal/storage"
)

type fakeAPIKeyStore struct {
	orgID string
	err   error
}

func (s *fakeAPIKeyStore) LookupOrgID(keyHash string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return s.orgID, nil
}
func (s *fakeAPIKeyStore) LookupKeyInfo(keyHash string) (*storage.APIKeyInfo, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &storage.APIKeyInfo{OrgID: s.orgID}, nil
}

type fakeClientCertStore struct {
	orgID string
	err   error
}

func (s *fakeClientCertStore) IsEnrolled(orgID string, fingerprint string) (bool, error) {
	return true, nil
}
func (s *fakeClientCertStore) Enroll(orgID string, name string, fingerprint string) error { return nil }
func (s *fakeClientCertStore) Revoke(orgID string, fingerprint string) (bool, error) {
	return true, nil
}
func (s *fakeClientCertStore) LookupOrgIDByFingerprint(fingerprint string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.orgID == "" {
		return "", sql.ErrNoRows
	}
	return s.orgID, nil
}
func (s *fakeClientCertStore) List(orgID string, limit int, includeRevoked bool) ([]storage.ClientCertRecord, error) {
	return nil, nil
}

func TestAuthMiddleware_DisableAPIKeyAuth_RejectsAuthorizationHeader(t *testing.T) {
	t.Setenv("ALLOW_API_KEY_AUTH", "false")

	m := NewAuthMiddleware(&fakeAPIKeyStore{orgID: "org1"}, &fakeClientCertStore{orgID: "org1"}, nil, nil)
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "abc")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddleware_DisableAPIKeyAuth_AllowsMTLSOnly(t *testing.T) {
	t.Setenv("ALLOW_API_KEY_AUTH", "0")

	m := NewAuthMiddleware(&fakeAPIKeyStore{orgID: "org1"}, &fakeClientCertStore{orgID: "org1"}, nil, nil)
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := OrgFromContext(r.Context()); !ok {
			t.Fatalf("expected org in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req = req.WithContext(WithClientCertFingerprint(req.Context(), "deadbeef"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusOK)
	}
}

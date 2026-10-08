package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func requestWithRole(method, role string) *http.Request {
	req := httptest.NewRequest(method, "/x", nil)
	if role != "" {
		req = req.WithContext(WithActorRole(req.Context(), role))
	}
	return req
}

func TestAdminForWrites(t *testing.T) {
	h := AdminForWrites()(okHandler())
	cases := []struct {
		method, role string
		want         int
	}{
		{http.MethodGet, RoleMember, http.StatusOK},
		{http.MethodHead, RoleMember, http.StatusOK},
		{http.MethodOptions, RoleAgent, http.StatusOK},
		{http.MethodGet, "", http.StatusOK},
		{http.MethodPost, RoleMember, http.StatusForbidden},
		{http.MethodPut, RoleMember, http.StatusForbidden},
		{http.MethodPatch, RoleAgent, http.StatusForbidden},
		{http.MethodDelete, "", http.StatusForbidden},
		{http.MethodPost, RoleAdmin, http.StatusOK},
		{http.MethodDelete, RoleAdmin, http.StatusOK},
	}
	for _, tc := range cases {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, requestWithRole(tc.method, tc.role))
		if rr.Code != tc.want {
			t.Errorf("%s role=%q: status=%d want %d", tc.method, tc.role, rr.Code, tc.want)
		}
	}
}

func TestDenyRole(t *testing.T) {
	h := DenyRole(RoleAgent)(okHandler())
	cases := []struct {
		role string
		want int
	}{
		{RoleAgent, http.StatusForbidden},
		{RoleMember, http.StatusOK},
		{RoleAdmin, http.StatusOK},
		{"", http.StatusOK},
	}
	for _, tc := range cases {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, requestWithRole(http.MethodGet, tc.role))
		if rr.Code != tc.want {
			t.Errorf("role=%q: status=%d want %d", tc.role, rr.Code, tc.want)
		}
	}
}

func TestRequireAnyRole_NoLegacyFallback(t *testing.T) {
	h := RequireAnyRole(RoleAdmin, RoleMember)(okHandler())
	cases := []struct {
		role      string
		actorType string
		want      int
	}{
		{RoleAdmin, "", http.StatusOK},
		{RoleMember, "", http.StatusOK},
		{RoleAgent, "", http.StatusForbidden},
		// An api_key / mtls actor with no role used to be treated as admin;
		// it must now be denied.
		{"", ActorTypeAPIKey, http.StatusForbidden},
		{"", ActorTypeMTLS, http.StatusForbidden},
		{"", "", http.StatusForbidden},
	}
	for _, tc := range cases {
		req := requestWithRole(http.MethodGet, tc.role)
		if tc.actorType != "" {
			req = req.WithContext(WithActor(req.Context(), tc.actorType, "id"))
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Errorf("role=%q actor=%q: status=%d want %d", tc.role, tc.actorType, rr.Code, tc.want)
		}
	}
}

func TestIsAdminRequest(t *testing.T) {
	if !IsAdminRequest(requestWithRole(http.MethodGet, RoleAdmin), nil) {
		t.Fatalf("admin role not recognised")
	}
	if IsAdminRequest(requestWithRole(http.MethodGet, RoleMember), nil) {
		t.Fatalf("member treated as admin")
	}
	req := requestWithRole(http.MethodGet, "")
	req = req.WithContext(WithActor(req.Context(), ActorTypeAPIKey, "k"))
	if IsAdminRequest(req, nil) {
		t.Fatalf("role-less api_key treated as admin (legacy fallback must be gone)")
	}
}

func TestSecurityHeaders(t *testing.T) {
	for _, hsts := range []bool{true, false} {
		rr := httptest.NewRecorder()
		SecurityHeaders(hsts)(okHandler()).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
		h := rr.Header()
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("Cache-Control") != "no-store" {
			t.Fatalf("hsts=%v missing hygiene headers: %v", hsts, h)
		}
		if got := h.Get("Strict-Transport-Security"); (got != "") != hsts {
			t.Fatalf("hsts=%v got HSTS=%q", hsts, got)
		}
	}
}

func TestRateLimiter_UnauthenticatedKeyedByIP(t *testing.T) {
	t.Setenv("TRUST_PROXY_HEADERS", "")
	rl := NewRateLimiter(2, 0) // window 0 is fine for a single burst
	rl.window = 60e9
	h := rl.WrapUnauthenticated(okHandler())

	// Different Authorization headers must NOT yield different buckets.
	for i, auth := range []string{"Bearer a", "Bearer b", "Bearer c"} {
		req := httptest.NewRequest(http.MethodPost, "/auth/sessions", nil)
		req.RemoteAddr = "203.0.113.7:1234"
		req.Header.Set("Authorization", auth)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		want := http.StatusOK
		if i == 2 {
			want = http.StatusTooManyRequests
		}
		if rr.Code != want {
			t.Fatalf("request %d: status=%d want %d", i, rr.Code, want)
		}
	}

	// A different peer gets its own bucket.
	req := httptest.NewRequest(http.MethodPost, "/auth/sessions", nil)
	req.RemoteAddr = "203.0.113.8:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("other peer: status=%d want 200", rr.Code)
	}
}

func TestClientIP_ProxyHeaderOnlyWhenTrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	req.Header.Set("X-Forwarded-For", "198.51.100.9, 10.0.0.1")

	if got := ClientIP(req, false); got != "10.0.0.1" {
		t.Fatalf("untrusted: got %q want RemoteAddr host", got)
	}
	if got := ClientIP(req, true); got != "198.51.100.9" {
		t.Fatalf("trusted: got %q want first XFF hop", got)
	}
	req.Header.Set("X-Forwarded-For", "garbage")
	if got := ClientIP(req, true); got != "10.0.0.1" {
		t.Fatalf("unparseable XFF: got %q want RemoteAddr host", got)
	}
}

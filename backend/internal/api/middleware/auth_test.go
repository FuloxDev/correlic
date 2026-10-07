package middleware

import "testing"

func TestExtractAPIKeyFromAuthorizationHeader(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "empty", raw: "", want: "", ok: false},
		{name: "raw_key", raw: "abc", want: "abc", ok: true},
		{name: "raw_key_with_spaces", raw: "  abc  ", want: "abc", ok: true},
		{name: "bearer", raw: "Bearer abc", want: "abc", ok: true},
		{name: "apikey", raw: "ApiKey abc", want: "abc", ok: true},
		{name: "unknown_scheme", raw: "Token abc", want: "", ok: false},
		{name: "too_many_parts", raw: "Bearer a b", want: "", ok: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := extractAPIKeyFromAuthorizationHeader(tc.raw)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("extractAPIKeyFromAuthorizationHeader(%q)=(%q,%v) want (%q,%v)", tc.raw, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestHashAPIKey_StableAndNonEmpty(t *testing.T) {
	t.Parallel()

	h1 := hashAPIKey("abc")
	h2 := hashAPIKey("abc")
	if h1 == "" || h2 == "" {
		t.Fatalf("expected non-empty hash")
	}
	if h1 != h2 {
		t.Fatalf("hash not stable: %q vs %q", h1, h2)
	}
	if h1 == "abc" {
		t.Fatalf("hash should not equal raw key")
	}
}

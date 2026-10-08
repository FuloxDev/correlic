package middleware

import "net/http"

// SecurityHeaders sets response hygiene headers on every response:
//
//   - X-Content-Type-Options: nosniff  (never MIME-sniff JSON/text bodies)
//   - Referrer-Policy: no-referrer     (API URLs carry IDs; do not leak them)
//   - Cache-Control: no-store          (API responses are per-actor and must
//     not be cached by browsers or intermediaries)
//   - Strict-Transport-Security        (only when hsts is true, i.e. the
//     server is serving TLS)
//
// Headers are set before the wrapped handler runs so they are present even
// when the handler writes its own status code.
func SecurityHeaders(hsts bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cache-Control", "no-store")
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=31536000")
			}
			next.ServeHTTP(w, r)
		})
	}
}

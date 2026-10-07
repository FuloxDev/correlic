package middleware

import (
	"log"
	"net/http"
)

// RequireMTLS rejects requests that do not present a verified client certificate.
// This is an application-level guard; the server may be configured to *request*
// client certificates (VerifyClientCertIfGiven) and rely on this middleware to
// enforce mTLS on selected routes.
func RequireMTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			log.Printf("[RequireMTLS] Request has no TLS connection")
			MTLSMissingCertTotal.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if len(r.TLS.PeerCertificates) == 0 {
			log.Printf("[RequireMTLS] Request has TLS but no peer certificates")
			MTLSMissingCertTotal.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// mTLS success log removed — fires on every request
		next.ServeHTTP(w, r)
	})
}

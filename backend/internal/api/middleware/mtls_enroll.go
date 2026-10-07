package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
)

type mtlsContextKey string

const clientCertFPContextKey mtlsContextKey = "client_cert_fingerprint"

// ClientCertFingerprintFromContext returns the mTLS client certificate fingerprint, if present.
func ClientCertFingerprintFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	v, ok := ctx.Value(clientCertFPContextKey).(string)
	return v, ok && v != ""
}

// WithClientCertFingerprint sets the client cert fingerprint in context (mainly for tests).
func WithClientCertFingerprint(ctx context.Context, fp string) context.Context {
	return context.WithValue(ctx, clientCertFPContextKey, fp)
}

// clientCertFingerprint returns hex(SHA-256(leaf_cert_DER)).
func clientCertFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func clientCertFingerprintFromRequest(r *http.Request) (string, bool) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	fp := clientCertFingerprint(r.TLS.PeerCertificates[0])
	return fp, fp != ""
}

// MTLSFingerprintMiddleware extracts the mTLS client certificate fingerprint (if present)
// and attaches it to the request context. It does NOT do enrollment checks.
type MTLSFingerprintMiddleware struct{}

func NewMTLSFingerprintMiddleware() *MTLSFingerprintMiddleware { return &MTLSFingerprintMiddleware{} }

func (m *MTLSFingerprintMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fp, ok := clientCertFingerprintFromRequest(r); ok {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientCertFPContextKey, fp)))
			return
		}
		next.ServeHTTP(w, r)
	})
}

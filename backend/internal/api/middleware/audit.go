package middleware

import (
	//"log"
	"net/http"
	//"time"
)

// statusWriter is a wrapper around the http.ResponseWriter that tracks the status code
type statusWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader writes the status code to the response writer and tracks the status code
func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Flush forwards the flush call to the underlying ResponseWriter if it supports it.
// This is required for SSE (Server-Sent Events) streaming to work through the audit middleware.
func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Audit wraps the next handler with audit logging
func Audit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: 200}
		//start := time.Now()

		// serve the request
		next.ServeHTTP(sw, r)

		// get the org ID from the context
		// orgID, _ := OrgFromContext(r.Context())
		// fp, _ := ClientCertFingerprintFromContext(r.Context())

		// log.Printf(
		// 	"audit method=%s path=%s org=%s mTLS_fp=%s status=%d duration_ms=%d remote=%s",
		// 	r.Method,
		// 	r.URL.Path,
		// 	orgID,
		// 	fp,
		// 	sw.status,
		// 	time.Since(start).Milliseconds(),
		// 	r.RemoteAddr,
		// )
	})
}

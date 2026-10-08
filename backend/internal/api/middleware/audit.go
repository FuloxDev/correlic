package middleware

import (
	"log"
	"net/http"
	"time"
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

// Audit logs every state-changing request (anything other than GET, HEAD or
// OPTIONS) at INFO with the method, path, actor identity, role, response
// status and duration. It must run after AuthMiddleware so the actor is
// available in the request context. Read-only requests are not logged to
// keep the log volume proportional to meaningful activity.
func Audit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()

		next.ServeHTTP(sw, r)

		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			return
		}

		orgID, _ := OrgFromContext(r.Context())
		actorType, actorID, _ := ActorFromContext(r.Context())
		role, _ := ActorRoleFromContext(r.Context())

		log.Printf(
			"INFO audit method=%s path=%s org=%s actor_type=%s actor_id=%s role=%s status=%d duration_ms=%d remote=%s",
			r.Method,
			r.URL.Path,
			orgID,
			actorType,
			actorID,
			role,
			sw.status,
			time.Since(start).Milliseconds(),
			r.RemoteAddr,
		)
	})
}

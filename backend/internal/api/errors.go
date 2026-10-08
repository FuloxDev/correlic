package api

import (
	"encoding/json"
	"log"
	"net/http"
)

// ErrorResponse is the standard API error payload.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// writeError writes an error response to the response writer
func writeError(w http.ResponseWriter, status int, code string, msg string) {
	// set the content type and write the status code
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Error: msg,
		Code:  code,
	})
}

// BadRequest writes a bad request error response to the response writer
func BadRequest(w http.ResponseWriter, msg string) {
	writeError(w, http.StatusBadRequest, "bad_request", msg)
}

// Unauthorized writes an unauthorized error response to the response writer
func Unauthorized(w http.ResponseWriter, msg string) {
	if msg == "" {
		msg = "unauthorized"
	}
	log.Printf("[Unauthorized] %s", msg)
	writeError(w, http.StatusUnauthorized, "unauthorized", msg)
}

// NotFound writes a not found error response to the response writer
func NotFound(w http.ResponseWriter, msg string) {
	if msg == "" {
		msg = "not found"
	}
	writeError(w, http.StatusNotFound, "not_found", msg)
}

// MethodNotAllowed writes a method not allowed error response to the response writer
func MethodNotAllowed(w http.ResponseWriter, allow string) {
	if allow != "" {
		w.Header().Set("Allow", allow)
	}
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

// PayloadTooLarge writes a payload too large error response to the response writer
func PayloadTooLarge(w http.ResponseWriter, msg string) {
	if msg == "" {
		msg = "request too large"
	}
	writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", msg)
}

// Internal writes an internal server error response to the response writer
func Internal(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, "internal", "internal server error")
}

// InternalErr logs err under op and writes a generic 500. Use it wherever a
// handler used to echo err.Error() to the client: internal details (SQL,
// Neo4j, file paths, upstream responses) belong in the server log only.
func InternalErr(w http.ResponseWriter, op string, err error) {
	log.Printf("ERROR: %s: %v", op, err)
	Internal(w)
}

// Forbidden writes a forbidden error response to the response writer
func Forbidden(w http.ResponseWriter, msg string) {
	if msg == "" {
		msg = "forbidden"
	}
	writeError(w, http.StatusForbidden, "forbidden", msg)
}

// NotImplemented writes a not implemented error response to the response writer
func NotImplemented(w http.ResponseWriter, msg string) {
	if msg == "" {
		msg = "not implemented"
	}
	writeError(w, http.StatusNotImplemented, "not_implemented", msg)
}

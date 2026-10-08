package transport

import (
	"errors"
	"net/http"
)

// StatusOf returns the HTTP status carried by a BackendError, or 0 for any
// other error (network failures, timeouts, marshal errors).
func StatusOf(err error) int {
	var be *BackendError
	if errors.As(err, &be) {
		return be.Status
	}
	return 0
}

// IsAuthError reports whether the backend rejected the request as
// unauthenticated or forbidden (401/403). Such failures are permanent until
// the API key is fixed and must be surfaced rather than retried.
func IsAuthError(err error) bool {
	switch StatusOf(err) {
	case http.StatusUnauthorized, http.StatusForbidden:
		return true
	}
	return false
}

// IsPermanent reports whether a delivery error will not succeed on retry:
// any 4xx except 408 (request timeout) and 429 (rate limited). Network errors
// and 5xx responses are transient.
func IsPermanent(err error) bool {
	status := StatusOf(err)
	if status == 0 {
		return false
	}
	if status >= 500 {
		return false
	}
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests {
		return false
	}
	return status >= 400 && status < 500
}

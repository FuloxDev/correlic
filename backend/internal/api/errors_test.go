package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMethodNotAllowed_SetsAllowAndJSONBody(t *testing.T) {
	t.Parallel()

	rr := httptest.NewRecorder()
	MethodNotAllowed(rr, http.MethodGet)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusMethodNotAllowed)
	}
	if got := rr.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow=%q want %q", got, http.MethodGet)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q want application/json", got)
	}

	var body ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body.Error == "" || body.Code == "" {
		t.Fatalf("expected error and code to be set, got %+v", body)
	}
}

func TestInternal_ReturnsNormalizedMessage(t *testing.T) {
	t.Parallel()

	rr := httptest.NewRecorder()
	Internal(rr)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusInternalServerError)
	}
	var body ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body.Error != "internal server error" {
		t.Fatalf("error=%q want %q", body.Error, "internal server error")
	}
	if body.Code != "internal" {
		t.Fatalf("code=%q want %q", body.Code, "internal")
	}
}

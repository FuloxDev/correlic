package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apierrors "github.com/correlic/correlic-backend/internal/api"
	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/storage"
)

type fakeTelemetryStore struct {
	events []model.TelemetryEvent
	err    error
}

func (s *fakeTelemetryStore) InsertEvents(orgID string, events []model.TelemetryEvent) error {
	s.events = append(s.events, events...)
	return s.err
}

func (s *fakeTelemetryStore) ListRecent(orgID string, agentID string, limit int) ([]model.TelemetryEvent, error) {
	return nil, nil
}

func (s *fakeTelemetryStore) ListRange(orgID string, agentID string, eventType string, from, to time.Time, limit int) ([]model.TelemetryEvent, error) {
	return nil, nil
}

func (s *fakeTelemetryStore) ListByIDs(orgID string, agentID string, ids []string, limit int) ([]model.TelemetryEvent, error) {
	return nil, nil
}

func (s *fakeTelemetryStore) ListAll(orgID string, eventType string, limit int, offset int) ([]model.TelemetryEvent, error) {
	return nil, nil
}

func (s *fakeTelemetryStore) ListFiltered(orgID string, f storage.TelemetryListFilter) ([]model.TelemetryEvent, error) {
	return nil, nil
}

func (s *fakeTelemetryStore) CountFiltered(orgID string, f storage.TelemetryListFilter) (int, error) {
	return 0, nil
}

func (s *fakeTelemetryStore) CountToday(orgID string) (int, error) {
	return 0, nil
}

func (s *fakeTelemetryStore) CountByEventType(orgID string, since time.Time) (map[string]int, int, error) {
	return nil, 0, nil
}

func decodeError(t *testing.T, rr *httptest.ResponseRecorder) apierrors.ErrorResponse {
	t.Helper()
	var e apierrors.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error response: %v body=%q", err, rr.Body.String())
	}
	return e
}

func TestIngestHandler_UnauthorizedWithoutOrg(t *testing.T) {
	store := &fakeTelemetryStore{}
	h := NewIngestHandler(store, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewBufferString(`{"events":[]}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusUnauthorized)
	}
	_ = decodeError(t, rr)
}

func TestIngestHandler_BadRequestMissingFields(t *testing.T) {
	store := &fakeTelemetryStore{}
	h := NewIngestHandler(store, nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewBufferString(`{"events":[{}]}`))
	req = req.WithContext(middleware.WithOrg(context.Background(), "org1"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusBadRequest)
	}
	_ = decodeError(t, rr)
}

func TestIngestHandler_AcceptsValidBatch(t *testing.T) {
	store := &fakeTelemetryStore{}
	h := NewIngestHandler(store, nil, nil)

	payload := `{"events":[{"agent_id":"a1","event_type":"agent_log","timestamp":"2026-01-01T00:00:00Z","payload":{"msg":"hello"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewBufferString(payload))
	req = req.WithContext(middleware.WithOrg(context.Background(), "org1"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status=%d want %d body=%q", rr.Code, http.StatusAccepted, rr.Body.String())
	}
	if len(store.events) != 1 {
		t.Fatalf("expected 1 event stored, got %d", len(store.events))
	}
	if store.events[0].EventType != "agent_log" {
		t.Fatalf("event_type=%q want %q", store.events[0].EventType, "agent_log")
	}
	if store.events[0].Timestamp.IsZero() || store.events[0].Timestamp.After(time.Now().Add(10*time.Minute)) {
		t.Fatalf("unexpected timestamp: %v", store.events[0].Timestamp)
	}
}

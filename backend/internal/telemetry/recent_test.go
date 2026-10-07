package telemetry

import (
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

type fakeRecentStore struct {
	events []model.TelemetryEvent
	err    error
	orgID  string
	agent  string
	limit  int
}

func (s *fakeRecentStore) InsertEvents(orgID string, events []model.TelemetryEvent) error {
	return nil
}

func (s *fakeRecentStore) ListRecent(orgID string, agentID string, limit int) ([]model.TelemetryEvent, error) {
	s.orgID = orgID
	s.agent = agentID
	s.limit = limit
	return s.events, s.err
}

func (s *fakeRecentStore) ListRange(orgID string, agentID string, eventType string, from, to time.Time, limit int) ([]model.TelemetryEvent, error) {
	return nil, nil
}

func (s *fakeRecentStore) ListByIDs(orgID string, agentID string, ids []string, limit int) ([]model.TelemetryEvent, error) {
	return nil, nil
}

func (s *fakeRecentStore) ListAll(orgID string, eventType string, limit int, offset int) ([]model.TelemetryEvent, error) {
	return nil, nil
}

func (s *fakeRecentStore) ListFiltered(orgID string, f storage.TelemetryListFilter) ([]model.TelemetryEvent, error) {
	return nil, nil
}

func (s *fakeRecentStore) CountFiltered(orgID string, f storage.TelemetryListFilter) (int, error) {
	return 0, nil
}

func (s *fakeRecentStore) CountToday(orgID string) (int, error) {
	return 0, nil
}

func (s *fakeRecentStore) CountByEventType(orgID string, since time.Time) (map[string]int, int, error) {
	return nil, 0, nil
}

func decodeErr(t *testing.T, rr *httptest.ResponseRecorder) apierrors.ErrorResponse {
	t.Helper()
	var e apierrors.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode: %v body=%q", err, rr.Body.String())
	}
	return e
}

func TestRecentHandler_UnauthorizedWithoutOrg(t *testing.T) {
	h := NewRecentHandler(&fakeRecentStore{})
	req := httptest.NewRequest(http.MethodGet, "/telemetry/recent?agent_id=a1", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusUnauthorized)
	}
	_ = decodeErr(t, rr)
}

func TestRecentHandler_BadRequestMissingAgentID(t *testing.T) {
	h := NewRecentHandler(&fakeRecentStore{})
	req := httptest.NewRequest(http.MethodGet, "/telemetry/recent", nil)
	req = req.WithContext(middleware.WithOrg(context.Background(), "org1"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusBadRequest)
	}
	_ = decodeErr(t, rr)
}

func TestRecentHandler_OK(t *testing.T) {
	store := &fakeRecentStore{
		events: []model.TelemetryEvent{
			{
				AgentID:   "a1",
				EventType: "agent_log",
				Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Payload:   json.RawMessage(`{"msg":"hi"}`),
			},
		},
	}
	h := NewRecentHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/telemetry/recent?agent_id=a1&limit=5", nil)
	req = req.WithContext(middleware.WithOrg(context.Background(), "org1"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%q", rr.Code, http.StatusOK, rr.Body.String())
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("expected application/json")
	}
	if store.orgID != "org1" || store.agent != "a1" || store.limit != 5 {
		t.Fatalf("store called with org=%q agent=%q limit=%d", store.orgID, store.agent, store.limit)
	}
	var out []model.TelemetryEvent
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	if len(out) != 1 || out[0].EventType != "agent_log" {
		t.Fatalf("unexpected response: %+v", out)
	}
}

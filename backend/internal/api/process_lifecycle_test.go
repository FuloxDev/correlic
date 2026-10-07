package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/storage/eventstore"
)

type processLifecycleTestStore struct {
	events []event.Event
}

func (s *processLifecycleTestStore) Append(ctx context.Context, evt event.Event) error {
	s.events = append(s.events, evt)
	return nil
}
func (s *processLifecycleTestStore) AppendIdempotent(ctx context.Context, evt event.Event) error {
	for _, e := range s.events {
		if e.ID == evt.ID {
			return nil
		}
	}
	s.events = append(s.events, evt)
	return nil
}
func (s *processLifecycleTestStore) GetByID(ctx context.Context, id string) (*event.Event, error) {
	for i := range s.events {
		if s.events[i].ID == id {
			e := s.events[i]
			return &e, nil
		}
	}
	return nil, nil
}
func (s *processLifecycleTestStore) GetRange(ctx context.Context, hostID string, from, to time.Time) ([]event.Event, error) {
	var out []event.Event
	for _, e := range s.events {
		if e.HostID != hostID {
			continue
		}
		if (e.Timestamp.Equal(from) || e.Timestamp.After(from)) && !e.Timestamp.After(to) {
			out = append(out, e)
		}
	}
	return out, nil
}

var _ eventstore.EventStore = (*processLifecycleTestStore)(nil)

func TestProcessLifecyclesHandler_ReturnsLifecycles(t *testing.T) {
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	store := &processLifecycleTestStore{
		events: []event.Event{
			{
				ID: "e1", HostID: "host1", Timestamp: base, Type: "process_exec", SchemaVersion: 1,
				Process: &event.ActorStruct{PID: 100, PPID: 1, ExePath: "/bin/sleep"},
			},
			{
				ID: "x1", HostID: "host1", Timestamp: base.Add(150 * time.Millisecond), Type: "process_exit", SchemaVersion: 1,
				Process: &event.ActorStruct{PID: 100, PPID: 1},
				Context: map[string]any{"exit_code": 0},
			},
		},
	}
	handler := ProcessLifecyclesHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/process/lifecycles?host_id=host1&since=2025-01-31T12:00:00Z&until=2025-01-31T12:01:00Z", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp ProcessLifecyclesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.HostID != "host1" {
		t.Errorf("expected host_id host1, got %s", resp.HostID)
	}
	if len(resp.Lifecycles) != 1 {
		t.Fatalf("expected 1 lifecycle, got %d", len(resp.Lifecycles))
	}
	lc := resp.Lifecycles[0]
	if lc.PID != 100 || lc.Running {
		t.Errorf("expected pid 100 running=false, got pid=%d running=%v", lc.PID, lc.Running)
	}
	if lc.DurationMs == nil || *lc.DurationMs != 150 {
		t.Errorf("expected duration_ms 150, got %v", lc.DurationMs)
	}
}

func TestProcessLifecyclesHandler_400MissingHostID(t *testing.T) {
	store := &processLifecycleTestStore{}
	handler := ProcessLifecyclesHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/process/lifecycles?since=2025-01-31T12:00:00Z", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestProcessLifecyclesHandler_400MissingSince(t *testing.T) {
	store := &processLifecycleTestStore{}
	handler := ProcessLifecyclesHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/process/lifecycles?host_id=host1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestProcessLifecyclesHandler_EmptyLifecycles(t *testing.T) {
	store := &processLifecycleTestStore{}
	handler := ProcessLifecyclesHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/process/lifecycles?host_id=host1&since=2025-01-31T12:00:00Z&until=2025-01-31T12:01:00Z", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp ProcessLifecyclesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Lifecycles == nil {
		t.Error("expected lifecycles to be non-nil array")
	}
	if len(resp.Lifecycles) != 0 {
		t.Errorf("expected 0 lifecycles, got %d", len(resp.Lifecycles))
	}
}

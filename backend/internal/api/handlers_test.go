package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/ingest"
	"github.com/correlic/correlic-backend/internal/model"
	"github.com/correlic/correlic-backend/internal/service"
	"github.com/correlic/correlic-backend/internal/storage"
)

type fakeAgentStore struct {
	getFn    func(orgID, agentID string) (*model.Agent, error)
	upsertFn func(orgID string, agent *model.Agent) error
	listFn   func(orgID string, userID *string) ([]*model.Agent, error)
}

func (f *fakeAgentStore) UpsertAgent(orgID string, agent *model.Agent) error {
	if f.upsertFn != nil {
		return f.upsertFn(orgID, agent)
	}
	return nil
}
func (f *fakeAgentStore) GetAgent(orgID, agentID string) (*model.Agent, error) {
	if f.getFn != nil {
		return f.getFn(orgID, agentID)
	}
	return nil, nil
}
func (f *fakeAgentStore) ListAgents(orgID string, userID *string) ([]*model.Agent, error) {
	if f.listFn != nil {
		return f.listFn(orgID, userID)
	}
	return nil, nil
}
func (f *fakeAgentStore) GetAgentsByUserID(orgID, userID string) ([]*model.Agent, error) {
	return f.ListAgents(orgID, &userID)
}
func (f *fakeAgentStore) CountAgentsByUserID(userID string) (int, error) {
	return 0, nil
}

var _ storage.AgentStore = (*fakeAgentStore)(nil)

type fakeAgentCertStore struct {
	err error
}

func (s *fakeAgentCertStore) EnsureBound(orgID string, agentID string, fingerprint string) error {
	return s.err
}
func (s *fakeAgentCertStore) Revoke(orgID string, agentID string) (bool, error) { return false, nil }
func (s *fakeAgentCertStore) List(orgID string, limit int, includeRevoked bool) ([]storage.AgentCertRecord, error) {
	return nil, nil
}

type fakeAgentIdentityStore struct {
	listFn func(orgID, agentID, kind string, limit int) ([]storage.AgentIdentityRecord, error)
}

func (s *fakeAgentIdentityStore) UpsertSeen(orgID, agentID, kind string, values []string, seenAt time.Time, sourceEventType string, sourceEventID string, meta any) ([]string, error) {
	return nil, nil
}

func (s *fakeAgentIdentityStore) ListByAgent(orgID, agentID, kind string, limit int) ([]storage.AgentIdentityRecord, error) {
	if s.listFn != nil {
		return s.listFn(orgID, agentID, kind, limit)
	}
	return nil, nil
}

var _ storage.AgentIdentityStore = (*fakeAgentIdentityStore)(nil)

func decodeErrorResponse(t *testing.T, rr *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var e ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("failed to decode error response: %v body=%q", err, rr.Body.String())
	}
	return e
}

func TestHealthHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	HealthHandler(true, false)(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusMethodNotAllowed)
	}
	_ = decodeErrorResponse(t, rr)
}

func TestListAgentsHandler_MissingOrgContext(t *testing.T) {
	t.Parallel()

	h := NewListAgentsHandler(service.NewAgentInventoryService(&fakeAgentStore{}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusUnauthorized)
	}
	_ = decodeErrorResponse(t, rr)
}

func TestListAgentsHandler_OK(t *testing.T) {
	t.Parallel()

	store := &fakeAgentStore{
		listFn: func(orgID string, userID *string) ([]*model.Agent, error) {
			return []*model.Agent{
				{
					AgentID:     "a1",
					Hostname:    "h",
					OS:          "linux",
					Profile:     "developer",
					Version:     "1",
					State:       "running",
					FirstSeenAt: time.Now().UTC().Add(-10 * time.Minute),
					LastSeenAt:  time.Now().UTC(),
				},
			}, nil
		},
	}
	h := NewListAgentsHandler(service.NewAgentInventoryService(store))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	req = req.WithContext(middleware.WithOrg(context.Background(), "org1"))
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusOK)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("expected application/json")
	}
	var out []model.AgentDTO
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(out) != 1 || out[0].AgentID != "a1" {
		t.Fatalf("unexpected response: %+v", out)
	}
}

func TestGetAgentHandler_NotFound(t *testing.T) {
	t.Parallel()

	store := &fakeAgentStore{
		getFn: func(orgID, agentID string) (*model.Agent, error) { return nil, nil },
	}
	h := NewGetAgentHandler(service.NewAgentInventoryService(store))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents/a1", nil)
	req = req.WithContext(middleware.WithOrg(context.Background(), "org1"))
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusNotFound)
	}
	_ = decodeErrorResponse(t, rr)
}

func TestAgentsRouter_Identity_OK(t *testing.T) {
	t.Parallel()

	store := &fakeAgentStore{
		getFn: func(orgID, agentID string) (*model.Agent, error) {
			return &model.Agent{AgentID: agentID, Hostname: "h", OS: "linux", Profile: "developer", Version: "1", State: "running", FirstSeenAt: time.Now().UTC().Add(-time.Minute), LastSeenAt: time.Now().UTC()}, nil
		},
	}
	identity := &fakeAgentIdentityStore{
		listFn: func(orgID, agentID, kind string, limit int) ([]storage.AgentIdentityRecord, error) {
			return []storage.AgentIdentityRecord{
				{
					Kind:        "ssh_key_fingerprint",
					Value:       "deadbeef",
					FirstSeenAt: time.Now().UTC().Add(-time.Hour),
					LastSeenAt:  time.Now().UTC(),
					SeenCount:   2,
				},
			}, nil
		},
	}
	h := NewAgentsRouter(service.NewAgentInventoryService(store), identity)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/agents/a1/identity", nil)
	req = req.WithContext(middleware.WithOrg(context.Background(), "org1"))
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want %d body=%q", rr.Code, http.StatusOK, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["agent_id"] != "a1" {
		t.Fatalf("agent_id=%v want a1", out["agent_id"])
	}
}

func TestHeartbeatHandler_InvalidTransition_Returns400(t *testing.T) {
	t.Parallel()

	store := &fakeAgentStore{
		getFn: func(orgID, agentID string) (*model.Agent, error) {
			return &model.Agent{AgentID: agentID, State: "stopped"}, nil
		},
	}
	svc := ingest.NewHeartbeatService(store)
	h := NewHeartbeatHandler(svc, nil, nil)

	payload := `{"agent_id":"a1","hostname":"h","os":"linux","profile":"developer","version":"1","state":"running","timestamp":"2026-01-01T00:00:00Z"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/heartbeat", bytes.NewBufferString(payload))
	req = req.WithContext(middleware.WithOrg(context.Background(), "org1"))
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want %d body=%q", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
	e := decodeErrorResponse(t, rr)
	if e.Code != "bad_request" {
		t.Fatalf("code=%q want bad_request", e.Code)
	}
}

func TestHeartbeatHandler_StoreError_Returns500(t *testing.T) {
	t.Parallel()

	store := &fakeAgentStore{
		getFn: func(orgID, agentID string) (*model.Agent, error) { return nil, errors.New("db down") },
	}
	svc := ingest.NewHeartbeatService(store)
	h := NewHeartbeatHandler(svc, nil, nil)

	payload := `{"agent_id":"a1","hostname":"h","os":"linux","profile":"developer","version":"1","state":"starting","timestamp":"2026-01-01T00:00:00Z"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/heartbeat", bytes.NewBufferString(payload))
	req = req.WithContext(middleware.WithOrg(context.Background(), "org1"))
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want %d body=%q", rr.Code, http.StatusInternalServerError, rr.Body.String())
	}
	e := decodeErrorResponse(t, rr)
	if e.Code != "internal" {
		t.Fatalf("code=%q want internal", e.Code)
	}
}

func TestHeartbeatHandler_mTLSBindingMismatch_Returns401(t *testing.T) {
	t.Parallel()

	store := &fakeAgentStore{
		getFn:    func(orgID, agentID string) (*model.Agent, error) { return nil, nil },
		upsertFn: func(orgID string, agent *model.Agent) error { return nil },
	}
	svc := ingest.NewHeartbeatService(store)
	certStore := &fakeAgentCertStore{err: storage.ErrAgentCertMismatch}
	h := NewHeartbeatHandler(svc, certStore, nil)

	payload := `{"agent_id":"a1","hostname":"h","os":"linux","profile":"developer","version":"1","state":"starting","timestamp":"2026-01-01T00:00:00Z"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/heartbeat", bytes.NewBufferString(payload))
	ctx := middleware.WithOrg(context.Background(), "org1")
	ctx = middleware.WithClientCertFingerprint(ctx, "deadbeef")
	req = req.WithContext(ctx)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d body=%q", rr.Code, http.StatusUnauthorized, rr.Body.String())
	}
}

package heartbeat

import (
	"context"
	"sync"
	"testing"

	"github.com/correlic/correlic-agent/internal/model"
)

type recordingTransport struct {
	mu  sync.Mutex
	hbs []model.Heartbeat
}

func (t *recordingTransport) SendHeartbeat(ctx context.Context, hb model.Heartbeat) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hbs = append(t.hbs, hb)
	return nil
}

func (t *recordingTransport) SendTelemetryBatch(ctx context.Context, batch model.TelemetryBatch) error {
	return nil
}

func (t *recordingTransport) ListApprovals(ctx context.Context, status string, agentID string, limit int) ([]model.Approval, error) {
	return nil, nil
}

func (t *recordingTransport) DecideApproval(ctx context.Context, approvalID string, status string, reason string) error {
	return nil
}

func (t *recordingTransport) CheckApproval(ctx context.Context, agentID string, kind string, subject map[string]any) (*model.ApprovalCheckResponse, error) {
	return &model.ApprovalCheckResponse{Allowed: true}, nil
}

func (t *recordingTransport) Heartbeats() []model.Heartbeat {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]model.Heartbeat, len(t.hbs))
	copy(out, t.hbs)
	return out
}

func TestRunnerShutdown_SendsStoppingThenStopped_WhenRunning(t *testing.T) {
	rt := &recordingTransport{}
	r := &Runner{
		AgentID:   "a1",
		Profile:   "developer",
		Version:   "0.1.0",
		State:     model.StateRunning,
		Transport: rt,
	}

	r.shutdown(context.Background(), "host")

	hbs := rt.Heartbeats()
	if len(hbs) != 2 {
		t.Fatalf("expected 2 shutdown heartbeats, got %d", len(hbs))
	}
	if hbs[0].State != model.StateStopping {
		t.Fatalf("first state=%q want %q", hbs[0].State, model.StateStopping)
	}
	if hbs[1].State != model.StateStopped {
		t.Fatalf("second state=%q want %q", hbs[1].State, model.StateStopped)
	}
}

func TestRunnerShutdown_SkipsStopHeartbeats_WhenStarting(t *testing.T) {
	rt := &recordingTransport{}
	r := &Runner{
		AgentID:   "a1",
		Profile:   "developer",
		Version:   "0.1.0",
		State:     model.StateStarting,
		Transport: rt,
	}

	r.shutdown(context.Background(), "host")

	hbs := rt.Heartbeats()
	if len(hbs) != 0 {
		t.Fatalf("expected 0 shutdown heartbeats, got %d", len(hbs))
	}
}

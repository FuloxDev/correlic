package approvals

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/model"
)

type fakeT struct {
	items []model.Approval
}

func (t *fakeT) SendHeartbeat(ctx context.Context, hb model.Heartbeat) error              { return nil }
func (t *fakeT) SendTelemetryBatch(ctx context.Context, batch model.TelemetryBatch) error { return nil }
func (t *fakeT) ListApprovals(ctx context.Context, status string, agentID string, limit int) ([]model.Approval, error) {
	return t.items, nil
}
func (t *fakeT) DecideApproval(ctx context.Context, approvalID string, status string, reason string) error {
	return nil
}
func (t *fakeT) CheckApproval(ctx context.Context, agentID string, kind string, subject map[string]any) (*model.ApprovalCheckResponse, error) {
	return &model.ApprovalCheckResponse{Allowed: true}, nil
}

func TestApprovalSummary(t *testing.T) {
	t.Parallel()
	a := model.Approval{
		Kind:    "git_clone",
		Subject: json.RawMessage(`{"remote_url":"https://github.com/org/repo.git"}`),
	}
	s := approvalSummary(a)
	if s == "" {
		t.Fatalf("expected non-empty")
	}
}

func TestWatcher_Dedupe(t *testing.T) {
	t.Parallel()
	ft := &fakeT{
		items: []model.Approval{
			{ID: "a1", Kind: "git_clone"},
			{ID: "a1", Kind: "git_clone"},
		},
	}
	w := NewWatcher(ft, "agent-1", 1*time.Millisecond, "http://127.0.0.1:8787/approvals")
	// call poll twice and ensure it doesn't grow unbounded for same ID
	w.pollOnce(context.Background())
	w.pollOnce(context.Background())
	if len(w.seen) != 1 {
		t.Fatalf("seen=%d want 1", len(w.seen))
	}
}

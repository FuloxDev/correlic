package telemetry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/model"
	"github.com/correlic/correlic-agent/internal/transport"
)

type fakeTransport struct {
	mu     sync.Mutex
	batches []model.TelemetryBatch
	ch     chan model.TelemetryBatch
	errs   []error
}

func (t *fakeTransport) SendHeartbeat(ctx context.Context, hb model.Heartbeat) error {
	return nil
}

func (t *fakeTransport) SendTelemetryBatch(ctx context.Context, batch model.TelemetryBatch) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.batches = append(t.batches, batch)
	if t.ch != nil {
		t.ch <- batch
	}
	if len(t.errs) > 0 {
		err := t.errs[0]
		t.errs = t.errs[1:]
		return err
	}
	return nil
}

func (t *fakeTransport) ListApprovals(ctx context.Context, status string, agentID string, limit int) ([]model.Approval, error) {
	return nil, nil
}

func (t *fakeTransport) DecideApproval(ctx context.Context, approvalID string, status string, reason string) error {
	return nil
}

func (t *fakeTransport) CheckApproval(ctx context.Context, agentID string, kind string, subject map[string]any) (*model.ApprovalCheckResponse, error) {
	return &model.ApprovalCheckResponse{Allowed: true}, nil
}

func TestBatcher_FlushesOnMaxBatch(t *testing.T) {
	ft := &fakeTransport{ch: make(chan model.TelemetryBatch, 1)}
	b := NewBatcher("agent-1", ft)
	b.maxBatch = 2
	b.flushInterval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Start(ctx)

	if ok := b.Enqueue("agent_log", map[string]any{"msg": "one"}); !ok {
		t.Fatalf("enqueue failed")
	}
	if ok := b.Enqueue("agent_log", map[string]any{"msg": "two"}); !ok {
		t.Fatalf("enqueue failed")
	}

	select {
	case batch := <-ft.ch:
		if len(batch.Events) != 2 {
			t.Fatalf("expected 2 events, got %d", len(batch.Events))
		}
		if batch.Events[0].AgentID != "agent-1" {
			t.Fatalf("agent_id=%q want %q", batch.Events[0].AgentID, "agent-1")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for batch flush")
	}
}

func TestBatcher_RetriesTransientFailure(t *testing.T) {
	ft := &fakeTransport{
		ch:   make(chan model.TelemetryBatch, 5),
		errs: []error{errors.New("dial tcp: connection refused"), nil},
	}
	b := NewBatcher("agent-1", ft)
	b.maxBatch = 2
	b.flushInterval = 20 * time.Millisecond
	b.minBackoff = 10 * time.Millisecond
	b.maxBackoff = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Start(ctx)

	_ = b.Enqueue("agent_log", map[string]any{"msg": "one"})
	_ = b.Enqueue("agent_log", map[string]any{"msg": "two"})

	// We expect at least one flush attempt quickly, then a retry that succeeds.
	deadline := time.After(500 * time.Millisecond)
	flushes := 0
	for {
		select {
		case <-ft.ch:
			flushes++
			if flushes >= 2 {
				return
			}
		case <-deadline:
			t.Fatalf("expected retry flushes, got %d", flushes)
		}
	}
}

func TestBatcher_DropsOnPermanentBackendError(t *testing.T) {
	ft := &fakeTransport{
		ch:   make(chan model.TelemetryBatch, 5),
		errs: []error{&transport.BackendError{Status: 400, Code: "bad_request", Msg: "invalid payload"}, nil},
	}
	b := NewBatcher("agent-1", ft)
	b.maxBatch = 2
	b.flushInterval = 20 * time.Millisecond
	b.minBackoff = 10 * time.Millisecond
	b.maxBackoff = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Start(ctx)

	_ = b.Enqueue("agent_log", map[string]any{"msg": "one"})
	_ = b.Enqueue("agent_log", map[string]any{"msg": "two"})

	// First flush happens and is dropped (permanent). No retry expected unless new events come in.
	select {
	case <-ft.ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected flush attempt")
	}

	select {
	case <-ft.ch:
		t.Fatalf("did not expect retry after permanent error without new events")
	case <-time.After(150 * time.Millisecond):
		// ok
	}
}

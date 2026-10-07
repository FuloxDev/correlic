package correlation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

// mockProcessTreePersister implements ProcessTreePersister for testing
type mockProcessTreePersister struct {
	upsertCalls    []*event.Event
	propagateCalls []string
	upsertErr      error
	propagateCount int
	propagateErr   error
}

func (m *mockProcessTreePersister) UpsertProcessAndLink(ctx context.Context, evt *event.Event) error {
	m.upsertCalls = append(m.upsertCalls, evt)
	return m.upsertErr
}

func (m *mockProcessTreePersister) PropagateAILabels(ctx context.Context, hostID string) (int, error) {
	m.propagateCalls = append(m.propagateCalls, hostID)
	return m.propagateCount, m.propagateErr
}

func TestProcessTreeWriter_IngestExec(t *testing.T) {
	mock := &mockProcessTreePersister{}
	writer := NewProcessTreeWriter(mock)

	evt := &event.Event{
		ID:     "evt-1",
		Type:   "process_exec",
		HostID: "host-1",
		Process: &event.ActorStruct{
			PID:     1234,
			PPID:    1,
			Comm:    "bash",
			ExePath: "/usr/bin/bash",
		},
		Timestamp: time.Now(),
	}

	err := writer.IngestProcess(context.Background(), evt)
	if err != nil {
		t.Fatalf("IngestProcess failed: %v", err)
	}

	if len(mock.upsertCalls) != 1 {
		t.Fatalf("expected 1 upsert call, got %d", len(mock.upsertCalls))
	}
	if mock.upsertCalls[0].ID != "evt-1" {
		t.Errorf("expected event ID evt-1, got %s", mock.upsertCalls[0].ID)
	}
	if len(mock.propagateCalls) != 1 {
		t.Fatalf("expected 1 propagate call, got %d", len(mock.propagateCalls))
	}
	if mock.propagateCalls[0] != "host-1" {
		t.Errorf("expected host-1, got %s", mock.propagateCalls[0])
	}
}

func TestProcessTreeWriter_IngestExit_NoOp(t *testing.T) {
	mock := &mockProcessTreePersister{}
	writer := NewProcessTreeWriter(mock)

	evt := &event.Event{
		ID:     "evt-2",
		Type:   "process_exit",
		HostID: "host-1",
		Process: &event.ActorStruct{
			PID:  1234,
			PPID: 1,
		},
		Timestamp: time.Now(),
	}

	err := writer.IngestProcess(context.Background(), evt)
	if err != nil {
		t.Fatalf("IngestProcess for exit should not error: %v", err)
	}

	if len(mock.upsertCalls) != 0 {
		t.Errorf("expected 0 upsert calls for process_exit, got %d", len(mock.upsertCalls))
	}
}

func TestProcessTreeWriter_NilEvent(t *testing.T) {
	mock := &mockProcessTreePersister{}
	writer := NewProcessTreeWriter(mock)

	// nil event
	if err := writer.IngestProcess(context.Background(), nil); err != nil {
		t.Errorf("nil event should not error: %v", err)
	}

	// nil process
	evt := &event.Event{ID: "evt-3", Type: "process_exec"}
	if err := writer.IngestProcess(context.Background(), evt); err != nil {
		t.Errorf("nil process should not error: %v", err)
	}

	if len(mock.upsertCalls) != 0 {
		t.Errorf("expected 0 upsert calls, got %d", len(mock.upsertCalls))
	}
}

func TestProcessTreeWriter_UpsertError(t *testing.T) {
	mock := &mockProcessTreePersister{
		upsertErr: fmt.Errorf("neo4j down"),
	}
	writer := NewProcessTreeWriter(mock)

	evt := &event.Event{
		ID:     "evt-4",
		Type:   "process_exec",
		HostID: "host-1",
		Process: &event.ActorStruct{
			PID:  1234,
			PPID: 1,
		},
		Timestamp: time.Now(),
	}

	err := writer.IngestProcess(context.Background(), evt)
	if err == nil {
		t.Fatal("expected error when upsert fails")
	}

	// Should not propagate labels if upsert fails
	if len(mock.propagateCalls) != 0 {
		t.Errorf("expected 0 propagate calls after upsert error, got %d", len(mock.propagateCalls))
	}
}

func TestIsProcessTreeEvent(t *testing.T) {
	cases := []struct {
		eventType string
		want      bool
	}{
		{"process_exec", true},
		{"process_exit", true},
		{"process_fork", true},
		{"net_connect", false},
		{"file_open", false},
		{"container_start", false},
	}
	for _, tc := range cases {
		if got := isProcessTreeEvent(tc.eventType); got != tc.want {
			t.Errorf("isProcessTreeEvent(%q) = %v, want %v", tc.eventType, got, tc.want)
		}
	}
}

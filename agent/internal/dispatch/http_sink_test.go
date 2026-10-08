package dispatch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/transport"
)

type scriptedClient struct {
	mu       sync.Mutex
	errs     []error // consumed in order; nil means success
	received [][]event.Event
	done     chan struct{}
	wantSent int
}

func (c *scriptedClient) SendCanonicalEvents(ctx context.Context, events []event.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	if len(c.errs) > 0 {
		err, c.errs = c.errs[0], c.errs[1:]
	}
	if err == nil {
		c.received = append(c.received, events)
		if c.done != nil && len(c.received) == c.wantSent {
			close(c.done)
		}
	}
	return err
}

func (c *scriptedClient) batches() [][]event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]event.Event(nil), c.received...)
}

func evt(id string) event.Event { return event.Event{ID: id, Type: "process_exec"} }

func TestHTTPSink_RetriesTransientThenDelivers(t *testing.T) {
	client := &scriptedClient{
		errs:     []error{&transport.BackendError{Status: 503}, errors.New("dial tcp: refused"), nil},
		done:     make(chan struct{}),
		wantSent: 1,
	}
	s := NewHTTPSink(client, 2)
	s.minBackoff, s.maxBackoff = time.Millisecond, 5*time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx)

	_ = s.Dispatch(ctx, evt("a"))
	_ = s.Dispatch(ctx, evt("b"))

	select {
	case <-client.done:
	case <-time.After(5 * time.Second):
		t.Fatal("batch was never delivered after transient failures")
	}
	got := client.batches()
	if len(got) != 1 || len(got[0]) != 2 || got[0][0].ID != "a" || got[0][1].ID != "b" {
		t.Fatalf("delivered batches = %v", got)
	}
	if sent, dropped, _ := s.Stats(); sent != 1 || dropped != 0 {
		t.Errorf("stats sent=%d dropped=%d", sent, dropped)
	}
}

func TestHTTPSink_AuthErrorDropsBatchAndContinues(t *testing.T) {
	client := &scriptedClient{
		errs:     []error{&transport.BackendError{Status: 401}, nil},
		done:     make(chan struct{}),
		wantSent: 1,
	}
	s := NewHTTPSink(client, 1)
	s.minBackoff, s.maxBackoff = time.Millisecond, time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx)

	_ = s.Dispatch(ctx, evt("rejected"))
	_ = s.Dispatch(ctx, evt("ok"))

	select {
	case <-client.done:
	case <-time.After(5 * time.Second):
		t.Fatal("second batch never delivered after a 401 on the first")
	}
	got := client.batches()
	if len(got) != 1 || got[0][0].ID != "ok" {
		t.Fatalf("delivered = %v, want only the second batch", got)
	}
	if _, droppedBatches, droppedEvents := s.Stats(); droppedBatches != 1 || droppedEvents != 1 {
		t.Errorf("dropped batches=%d events=%d, want 1/1", droppedBatches, droppedEvents)
	}
}

func TestHTTPSink_QueueBoundDropsOldest(t *testing.T) {
	// No sender running: everything accumulates in the queue.
	s := NewHTTPSink(&scriptedClient{}, 1)
	s.maxQueue = 3
	ctx := context.Background()
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		_ = s.Dispatch(ctx, evt(id))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) != 3 {
		t.Fatalf("queue len = %d, want 3", len(s.queue))
	}
	if s.queue[0][0].ID != "3" || s.queue[2][0].ID != "5" {
		t.Errorf("oldest batches should be dropped, queue = %v", s.queue)
	}
	if s.droppedBatches.Load() != 2 {
		t.Errorf("dropped = %d, want 2", s.droppedBatches.Load())
	}
}

func TestHTTPSink_FlushesPartialBatchOnShutdown(t *testing.T) {
	client := &scriptedClient{done: make(chan struct{}), wantSent: 1}
	s := NewHTTPSink(client, 100)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { s.Start(ctx); close(stopped) }()
	_ = s.Dispatch(ctx, evt("partial"))
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("sink did not stop")
	}
	if got := client.batches(); len(got) != 1 || got[0][0].ID != "partial" {
		t.Fatalf("shutdown flush delivered %v", got)
	}
}

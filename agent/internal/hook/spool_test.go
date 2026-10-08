package hook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/transport"
)

type fakeSender struct {
	batches [][]event.Event
	errs    []error // consumed in order; nil = success
}

func (f *fakeSender) SendCanonicalEvents(_ context.Context, events []event.Event) error {
	f.batches = append(f.batches, events)
	if len(f.errs) == 0 {
		return nil
	}
	err := f.errs[0]
	f.errs = f.errs[1:]
	return err
}

func spoolEvent(i int, ts time.Time) event.Event {
	return event.Event{SchemaVersion: 1, ID: fmt.Sprintf("evt-%03d", i), HostID: "h", Timestamp: ts.Add(time.Duration(i) * time.Millisecond), Source: "hook", Type: "ai_tool_call"}
}

func TestSpool_AddDrainAndRetry(t *testing.T) {
	s := NewSpool(t.TempDir(), discardLogger())
	now := time.Now()
	for i := 0; i < 3; i++ {
		if err := s.Add(spoolEvent(i, now)); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if s.Len() != 3 {
		t.Fatalf("len = %d", s.Len())
	}

	// Transient failure keeps everything.
	sender := &fakeSender{errs: []error{errors.New("connection refused")}}
	if n := s.Drain(context.Background(), sender, now); n != 0 || s.Len() != 3 {
		t.Fatalf("transient: sent=%d len=%d", n, s.Len())
	}
	// Next invocation succeeds: oldest first, one batch, files removed.
	sender = &fakeSender{}
	if n := s.Drain(context.Background(), sender, now); n != 3 || s.Len() != 0 {
		t.Fatalf("retry: sent=%d len=%d", n, s.Len())
	}
	if len(sender.batches) != 1 || sender.batches[0][0].ID != "evt-000" || sender.batches[0][2].ID != "evt-002" {
		t.Errorf("batches = %+v", sender.batches)
	}
	if n := s.Drain(context.Background(), sender, now); n != 0 {
		t.Errorf("empty drain sent %d", n)
	}
}

func TestSpool_PermanentRejectionDropsAndOldEventsExpire(t *testing.T) {
	s := NewSpool(t.TempDir(), discardLogger())
	now := time.Now()
	s.Add(spoolEvent(1, now))
	s.Add(spoolEvent(2, now.Add(-8*24*time.Hour))) // older than the backend accepts
	sender := &fakeSender{errs: []error{&transport.BackendError{Status: http.StatusBadRequest}}}
	if n := s.Drain(context.Background(), sender, now); n != 0 || s.Len() != 0 {
		t.Fatalf("permanent: sent=%d len=%d", n, s.Len())
	}
	if len(sender.batches) != 1 || len(sender.batches[0]) != 1 || sender.batches[0][0].ID != "evt-001" {
		t.Errorf("expired event must not be sent: %+v", sender.batches)
	}

	// Auth errors drop too.
	s.Add(spoolEvent(3, now))
	sender = &fakeSender{errs: []error{&transport.BackendError{Status: http.StatusUnauthorized}}}
	if n := s.Drain(context.Background(), sender, now); n != 0 || s.Len() != 0 {
		t.Fatalf("auth: sent=%d len=%d", n, s.Len())
	}
}

func TestSpool_BoundedAndCorruptFiles(t *testing.T) {
	dir := t.TempDir()
	s := NewSpool(dir, discardLogger())
	now := time.Now()
	for i := 0; i < SpoolMaxFiles+5; i++ {
		if err := s.Add(spoolEvent(i, now)); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}
	if s.Len() != SpoolMaxFiles {
		t.Fatalf("len = %d, want %d", s.Len(), SpoolMaxFiles)
	}
	names, _ := s.list()
	if filepath.Base(names[0]) == "" || !containsID(names[0], "evt-005") {
		t.Errorf("oldest files must be dropped first, first=%s", names[0])
	}

	os.WriteFile(filepath.Join(s.Dir, "00000000000000000000-corrupt.json"), []byte("{"), 0o600)
	sender := &fakeSender{}
	n := s.Drain(context.Background(), sender, now)
	if n != SpoolMaxFiles || s.Len() != 0 {
		t.Fatalf("drain: sent=%d len=%d", n, s.Len())
	}
	if len(sender.batches) != 6 { // 501 files (500 + corrupt) / 100 per batch
		t.Errorf("batches = %d", len(sender.batches))
	}
}

func TestSpool_StopsAtDeadline(t *testing.T) {
	s := NewSpool(t.TempDir(), discardLogger())
	now := time.Now()
	for i := 0; i < 250; i++ {
		s.Add(spoolEvent(i, now))
	}
	ctx, cancel := context.WithCancel(context.Background())
	sender := &cancelAfterFirst{cancel: cancel}
	n := s.Drain(ctx, sender, now)
	if n != 100 || s.Len() != 150 {
		t.Fatalf("sent=%d len=%d", n, s.Len())
	}
}

type cancelAfterFirst struct{ cancel context.CancelFunc }

func (c *cancelAfterFirst) SendCanonicalEvents(context.Context, []event.Event) error {
	c.cancel()
	return nil
}

func containsID(name, id string) bool {
	return len(name) > 0 && filepath.Ext(name) == ".json" && (filepath.Base(name)[21:21+len(id)] == id)
}

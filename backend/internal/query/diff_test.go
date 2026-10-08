package query

import (
	"context"
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/storage/eventstore"
)

type memStore struct {
	events []event.Event
}

func (m *memStore) Append(ctx context.Context, evt event.Event) error {
	m.events = append(m.events, evt)
	return nil
}

func (m *memStore) AppendIdempotent(ctx context.Context, evt event.Event) error {
	for _, e := range m.events {
		if e.ID == evt.ID {
			return nil
		}
	}
	m.events = append(m.events, evt)
	return nil
}

func (m *memStore) GetByID(ctx context.Context, id string) (*event.Event, error) {
	for i := range m.events {
		if m.events[i].ID == id {
			e := m.events[i]
			return &e, nil
		}
	}
	return nil, nil
}

func (m *memStore) GetRange(ctx context.Context, hostID string, from, to time.Time) ([]event.Event, error) {
	var out []event.Event
	for _, e := range m.events {
		if e.HostID != hostID {
			continue
		}
		if !e.Timestamp.Before(from) && !e.Timestamp.After(to) {
			out = append(out, e)
		}
	}
	return out, nil
}

var _ eventstore.EventStore = (*memStore)(nil)

func TestDiffProcessesByExecutable_AddedRemoved(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	hostID := "h1"
	baseSince := time.Now().UTC().Add(-2 * time.Hour)
	baseUntil := baseSince.Add(1 * time.Hour)
	compareSince := baseUntil
	compareUntil := compareSince.Add(1 * time.Hour)

	// Base window: /usr/bin/foo, /usr/bin/bar. Compare window: /usr/bin/foo, /usr/bin/baz.
	// Expected: Added = [baz], Removed = [bar]
	store := &memStore{
		events: []event.Event{
			{ID: "e1", HostID: hostID, Timestamp: baseSince.Add(10 * time.Minute), Type: "process_exec", Process: &event.ActorStruct{ExePath: "/usr/bin/foo", PID: 1}},
			{ID: "e2", HostID: hostID, Timestamp: baseSince.Add(20 * time.Minute), Type: "process_exec", Process: &event.ActorStruct{ExePath: "/usr/bin/bar", PID: 2}},
			{ID: "e3", HostID: hostID, Timestamp: compareSince.Add(10 * time.Minute), Type: "process_exec", Process: &event.ActorStruct{ExePath: "/usr/bin/foo", PID: 3}},
			{ID: "e4", HostID: hostID, Timestamp: compareSince.Add(20 * time.Minute), Type: "process_exec", Process: &event.ActorStruct{ExePath: "/usr/bin/baz", PID: 4}},
		},
	}
	svc := NewService(store)

	res, err := svc.DiffProcessesByExecutable(ctx, hostID, baseSince, baseUntil, compareSince, compareUntil)
	if err != nil {
		t.Fatalf("DiffProcessesByExecutable: %v", err)
	}
	if len(res.Added) != 1 {
		t.Errorf("len(Added) = %d want 1", len(res.Added))
	} else if res.Added[0].ExePath != "/usr/bin/baz" {
		t.Errorf("Added[0].ExePath = %q want /usr/bin/baz", res.Added[0].ExePath)
	}
	if len(res.Removed) != 1 {
		t.Errorf("len(Removed) = %d want 1", len(res.Removed))
	} else if res.Removed[0].ExePath != "/usr/bin/bar" {
		t.Errorf("Removed[0].ExePath = %q want /usr/bin/bar", res.Removed[0].ExePath)
	}
}

func TestDiffExternalConnections_AddedRemoved(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	hostID := "h1"
	baseSince := time.Now().UTC().Add(-2 * time.Hour)
	baseUntil := baseSince.Add(1 * time.Hour)
	compareSince := baseUntil
	compareUntil := compareSince.Add(1 * time.Hour)

	store := &memStore{
		events: []event.Event{
			{ID: "c1", HostID: hostID, Timestamp: baseSince.Add(10 * time.Minute), Type: "net_connect", Target: &event.TargetStruct{IP: "1.2.3.4", Port: 443}},
			{ID: "c2", HostID: hostID, Timestamp: baseSince.Add(20 * time.Minute), Type: "net_connect", Target: &event.TargetStruct{IP: "5.6.7.8", Port: 80}},
			{ID: "c3", HostID: hostID, Timestamp: compareSince.Add(10 * time.Minute), Type: "net_connect", Target: &event.TargetStruct{IP: "1.2.3.4", Port: 443}},
			{ID: "c4", HostID: hostID, Timestamp: compareSince.Add(20 * time.Minute), Type: "net_connect", Target: &event.TargetStruct{IP: "9.10.11.12", Port: 22}},
		},
	}
	svc := NewService(store)

	res, err := svc.DiffExternalConnections(ctx, hostID, baseSince, baseUntil, compareSince, compareUntil)
	if err != nil {
		t.Fatalf("DiffExternalConnections: %v", err)
	}
	if len(res.Added) != 1 {
		t.Errorf("len(Added) = %d want 1", len(res.Added))
	} else if res.Added[0].IP != "9.10.11.12" || res.Added[0].Port != 22 {
		t.Errorf("Added[0] = %s:%d want 9.10.11.12:22", res.Added[0].IP, res.Added[0].Port)
	}
	if len(res.Removed) != 1 {
		t.Errorf("len(Removed) = %d want 1", len(res.Removed))
	} else if res.Removed[0].IP != "5.6.7.8" || res.Removed[0].Port != 80 {
		t.Errorf("Removed[0] = %s:%d want 5.6.7.8:80", res.Removed[0].IP, res.Removed[0].Port)
	}
}

func TestDiffOpenPorts_AddedRemoved(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	hostID := "h1"
	baseSince := time.Now().UTC().Add(-2 * time.Hour)
	baseUntil := baseSince.Add(1 * time.Hour)
	compareSince := baseUntil
	compareUntil := compareSince.Add(1 * time.Hour)

	store := &memStore{
		events: []event.Event{
			{ID: "p1", HostID: hostID, Timestamp: baseSince.Add(10 * time.Minute), Type: "net_listen", Target: &event.TargetStruct{Port: 8080}},
			{ID: "p2", HostID: hostID, Timestamp: baseSince.Add(20 * time.Minute), Type: "net_listen", Target: &event.TargetStruct{Port: 9090}},
			{ID: "p3", HostID: hostID, Timestamp: compareSince.Add(10 * time.Minute), Type: "net_listen", Target: &event.TargetStruct{Port: 8080}},
			{ID: "p4", HostID: hostID, Timestamp: compareSince.Add(20 * time.Minute), Type: "net_listen", Target: &event.TargetStruct{Port: 3000}},
		},
	}
	svc := NewService(store)

	res, err := svc.DiffOpenPorts(ctx, hostID, baseSince, baseUntil, compareSince, compareUntil)
	if err != nil {
		t.Fatalf("DiffOpenPorts: %v", err)
	}
	if len(res.Added) != 1 {
		t.Errorf("len(Added) = %d want 1", len(res.Added))
	} else if res.Added[0].Port != 3000 {
		t.Errorf("Added[0].Port = %d want 3000", res.Added[0].Port)
	}
	if len(res.Removed) != 1 {
		t.Errorf("len(Removed) = %d want 1", len(res.Removed))
	} else if res.Removed[0].Port != 9090 {
		t.Errorf("Removed[0].Port = %d want 9090", res.Removed[0].Port)
	}
}

func (m *memStore) AppendIdempotentForOrg(ctx context.Context, _ string, evt event.Event) error {
	return m.AppendIdempotent(ctx, evt)
}
func (m *memStore) GetByIDForOrg(ctx context.Context, _ string, id string) (*event.Event, error) {
	return m.GetByID(ctx, id)
}
func (m *memStore) GetRangeForOrg(ctx context.Context, _ string, hostID string, from, to time.Time) ([]event.Event, error) {
	return m.GetRange(ctx, hostID, from, to)
}

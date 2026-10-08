package detection

import (
	"context"
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

func TestAttributionCacheBoundedAndTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := NewAttributionCache(3, time.Hour)
	c.now = func() time.Time { return now }

	c.Put("h", 1, "cursor")
	c.Put("h", 2, "")
	c.Put("h", 3, "claude")
	if c.Len() != 3 {
		t.Fatalf("len = %d, want 3", c.Len())
	}
	if got, ok := c.Get("h", 2); !ok || got != "ai-agent" {
		t.Fatalf("empty ai_type should default to ai-agent, got %q ok=%v", got, ok)
	}

	// Inserting a 4th evicts the oldest (pid 1).
	c.Put("h", 4, "copilot")
	if c.Len() != 3 {
		t.Fatalf("len after eviction = %d, want 3", c.Len())
	}
	if _, ok := c.Get("h", 1); ok {
		t.Fatalf("oldest entry should have been evicted")
	}
	if got, ok := c.Get("h", 4); !ok || got != "copilot" {
		t.Fatalf("newest entry missing: %q ok=%v", got, ok)
	}

	// Re-putting pid 2 with a concrete type upgrades the generic fallback.
	c.Put("h", 2, "cursor")
	if got, _ := c.Get("h", 2); got != "cursor" {
		t.Fatalf("expected upgrade from ai-agent to cursor, got %q", got)
	}

	// Entries expire after the TTL.
	now = now.Add(2 * time.Hour)
	if _, ok := c.Get("h", 3); ok {
		t.Fatalf("entry should have expired")
	}

	// Nil cache is a no-op.
	var nilCache *AttributionCache
	nilCache.Put("h", 1, "x")
	if _, ok := nilCache.Get("h", 1); ok {
		t.Fatalf("nil cache must not return entries")
	}
}

type stubGraph struct {
	isAICalls int
	events    []event.Event
}

func (s *stubGraph) GetRecentEvents(context.Context, string, int, time.Time, []string) ([]event.Event, error) {
	return s.events, nil
}
func (s *stubGraph) GetRecentEventsMultiPID(context.Context, string, []int, time.Time, []string) ([]event.Event, error) {
	return s.events, nil
}
func (s *stubGraph) GetRecentEventsBySession(context.Context, string, string, time.Time, []string) ([]event.Event, error) {
	return s.events, nil
}
func (s *stubGraph) GetProcessAncestors(context.Context, string, int, int) ([]event.Event, error) {
	return s.events, nil
}
func (s *stubGraph) IsAIProcess(_ context.Context, _ string, pid int) (bool, string, error) {
	s.isAICalls++
	return pid == 77, "graph-ai", nil
}

func TestAttributionQuerierResolution(t *testing.T) {
	ctx := context.Background()
	cache := NewAttributionCache(0, 0)

	// No inner graph: tagged current event resolves, untagged does not.
	q := NewAttributionQuerier(nil, cache)
	tagged := &event.Event{HostID: "h", Process: &event.ActorStruct{PID: 10}, Context: map[string]any{"is_ai": true, "ai_tool": "aider"}}
	q.SetCurrentEvent(tagged)
	if isAI, typ, err := q.IsAIProcess(ctx, "h", 10); err != nil || !isAI || typ != "aider" {
		t.Fatalf("tagged event: isAI=%v type=%q err=%v", isAI, typ, err)
	}
	if isAI, _, _ := q.IsAIProcess(ctx, "h", 11); isAI {
		t.Fatalf("different pid must not resolve from the current event")
	}
	if evs, err := q.GetRecentEvents(ctx, "h", 10, time.Now(), nil); err != nil || len(evs) != 0 {
		t.Fatalf("no graph: expected empty, got %v err=%v", evs, err)
	}
	if q.HasGraph() {
		t.Fatalf("HasGraph should be false without inner querier")
	}

	// Cache carries attribution to a later untagged event for the same pid.
	q.SetCurrentEvent(&event.Event{HostID: "h", Process: &event.ActorStruct{PID: 10}})
	if isAI, typ, _ := q.IsAIProcess(ctx, "h", 10); !isAI || typ != "aider" {
		t.Fatalf("cache should resolve pid 10 as aider, got isAI=%v type=%q", isAI, typ)
	}

	// With an inner graph, unresolved pids delegate; locally resolved ones do not.
	g := &stubGraph{events: []event.Event{{ID: "e1"}}}
	q2 := NewAttributionQuerier(g, cache)
	q2.SetCurrentEvent(&event.Event{HostID: "h", Process: &event.ActorStruct{PID: 77}})
	if isAI, typ, _ := q2.IsAIProcess(ctx, "h", 77); !isAI || typ != "graph-ai" {
		t.Fatalf("expected delegation to graph for pid 77, got isAI=%v type=%q", isAI, typ)
	}
	if isAI, typ, _ := q2.IsAIProcess(ctx, "h", 10); !isAI || typ != "aider" {
		t.Fatalf("expected cache hit for pid 10, got isAI=%v type=%q", isAI, typ)
	}
	if g.isAICalls != 1 {
		t.Fatalf("graph IsAIProcess calls = %d, want 1 (cache hit must not delegate)", g.isAICalls)
	}
	if evs, _ := q2.GetProcessAncestors(ctx, "h", 1, 5); len(evs) != 1 {
		t.Fatalf("expected delegation of GetProcessAncestors, got %v", evs)
	}
	if !q2.HasGraph() {
		t.Fatalf("HasGraph should be true with inner querier")
	}
}

func TestEventAIAttribution(t *testing.T) {
	cases := []struct {
		name string
		ctx  map[string]any
		isAI bool
		typ  string
	}{
		{"nil", nil, false, ""},
		{"session", map[string]any{"ai_session_id": "abc"}, true, "ai-agent"},
		{"blank session", map[string]any{"ai_session_id": "  "}, false, ""},
		{"is_ai bool", map[string]any{"is_ai": true}, true, "ai-agent"},
		{"is_ai false", map[string]any{"is_ai": false}, false, ""},
		{"is_ai string", map[string]any{"is_ai": "true"}, true, "ai-agent"},
		{"ai_type wins", map[string]any{"is_ai": true, "ai_type": "cursor", "ai_tool": "x"}, true, "cursor"},
		{"ai_tool fallback", map[string]any{"ai_session_id": "s", "ai_tool": "claude-code"}, true, "claude-code"},
	}
	for _, c := range cases {
		isAI, typ := EventAIAttribution(&event.Event{Context: c.ctx})
		if isAI != c.isAI || typ != c.typ {
			t.Errorf("%s: got (%v, %q), want (%v, %q)", c.name, isAI, typ, c.isAI, c.typ)
		}
	}
}

package ai_pack_test

import (
	"context"
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/detection/ai_pack"
	"github.com/correlic/correlic-backend/internal/event"
)

func sshKeyOpenEvent(id string, ctx map[string]any) *event.Event {
	return &event.Event{
		SchemaVersion: 1,
		ID:            id,
		HostID:        "host-a",
		Timestamp:     time.Now(),
		Source:        "ebpf",
		Type:          "file_open",
		Process: &event.ActorStruct{
			PID:     4242,
			PPID:    1,
			Comm:    "python3",
			ExePath: "/usr/bin/python3",
			Cmdline: []string{"python3", "agent.py"},
		},
		Target: &event.TargetStruct{
			FilePath: "/home/u/.ssh/id_rsa",
			FileSize: 2602,
		},
		Context: ctx,
	}
}

func evaluateNoGraph(t *testing.T, engine *detection.Engine, cache *detection.AttributionCache, evt *event.Event) []detection.Finding {
	t.Helper()
	q := detection.NewAttributionQuerier(nil, cache)
	q.SetCurrentEvent(evt)
	return engine.Evaluate(&detection.EvalContext{
		Ctx:        context.Background(),
		Event:      evt,
		HostID:     evt.HostID,
		OrgID:      "org-1",
		GraphQuery: q,
	})
}

// TestCredentialAccessFiresWithoutGraph verifies the headline first-run bug fix: an
// AI-attributed credential read must produce ai.credential_access through the real
// engine + AI pack with no Neo4j querier at all.
func TestCredentialAccessFiresWithoutGraph(t *testing.T) {
	engine := detection.NewEngine()
	engine.RegisterPack(ai_pack.NewAIPack())
	cache := detection.NewAttributionCache(0, 0)

	evt := sshKeyOpenEvent("evt-ai-1", map[string]any{"ai_session_id": "sess-x", "is_ai": true})
	findings := evaluateNoGraph(t, engine, cache, evt)

	var cred *detection.Finding
	for i := range findings {
		if findings[i].DetectionID == "ai.credential_access" {
			cred = &findings[i]
		}
	}
	if cred == nil {
		t.Fatalf("expected ai.credential_access finding, got %d findings: %+v", len(findings), findings)
	}
	if cred.OrgID != "org-1" {
		t.Errorf("finding org_id = %q, want org-1", cred.OrgID)
	}
	wantID := "org-1:ai.credential_access:host-a:/home/u/.ssh/**"
	if cred.ID != wantID {
		t.Errorf("finding id = %q, want %q", cred.ID, wantID)
	}
	if cred.HostID != "host-a" || cred.AnchorEventID != "evt-ai-1" || cred.Status != "pending" {
		t.Errorf("unexpected stamping: host=%q anchor=%q status=%q", cred.HostID, cred.AnchorEventID, cred.Status)
	}
	if got, _ := cred.Context["ai_type"].(string); got != "ai-agent" {
		t.Errorf("ai_type = %q, want ai-agent (default when no ai_type/ai_tool tag)", got)
	}
	if cred.Severity != "critical" {
		t.Errorf("severity = %q, want critical", cred.Severity)
	}
}

// TestNonAttributedEventProducesNothing: the same read by an untagged, unknown PID
// must stay silent — the rules are AI-scoped.
func TestNonAttributedEventProducesNothing(t *testing.T) {
	engine := detection.NewEngine()
	engine.RegisterPack(ai_pack.NewAIPack())
	cache := detection.NewAttributionCache(0, 0)

	evt := sshKeyOpenEvent("evt-plain-1", nil)
	if findings := evaluateNoGraph(t, engine, cache, evt); len(findings) != 0 {
		t.Fatalf("expected no findings for non-attributed event, got %d: %+v", len(findings), findings)
	}
}

// TestAttributionCacheCarriesPIDForward: once a PID was seen with attribution, a later
// untagged event for the same PID on the same host still resolves as AI.
func TestAttributionCacheCarriesPIDForward(t *testing.T) {
	engine := detection.NewEngine()
	engine.RegisterPack(ai_pack.NewAIPack())
	cache := detection.NewAttributionCache(0, 0)

	tagged := sshKeyOpenEvent("evt-tagged", map[string]any{"ai_session_id": "sess-y", "ai_type": "cursor"})
	tagged.Target.FilePath = "/home/u/project/README.md" // benign, only seeds the cache
	_ = evaluateNoGraph(t, engine, cache, tagged)

	later := sshKeyOpenEvent("evt-untagged", nil)
	findings := evaluateNoGraph(t, engine, cache, later)

	found := false
	for _, f := range findings {
		if f.DetectionID == "ai.credential_access" {
			found = true
			if got, _ := f.Context["ai_type"].(string); got != "cursor" {
				t.Errorf("ai_type = %q, want cursor (from cache)", got)
			}
		}
	}
	if !found {
		t.Fatalf("expected ai.credential_access via cached attribution, got %+v", findings)
	}

	// A different PID never seen with attribution stays silent.
	other := sshKeyOpenEvent("evt-other-pid", nil)
	other.Process.PID = 999
	if findings := evaluateNoGraph(t, engine, cache, other); len(findings) != 0 {
		t.Fatalf("expected no findings for unknown PID, got %+v", findings)
	}
}

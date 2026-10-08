package patterns

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/correlic/correlic-agent/internal/lineage"
)

type fakeFetcher struct {
	calls    atomic.Int32
	failures int32
	patterns []string
}

func (f *fakeFetcher) GetAIPatterns(ctx context.Context) ([]string, error) {
	n := f.calls.Add(1)
	if n <= f.failures {
		return nil, errors.New("backend down")
	}
	return f.patterns, nil
}

func TestManager_CacheRoundTripAndRetry(t *testing.T) {
	lineage.ResetForTesting()
	tracker := lineage.GetLineageTracker()
	cache := filepath.Join(t.TempDir(), "ai_patterns.json")

	// First run: backend fails once, then succeeds; the list is cached.
	f := &fakeFetcher{failures: 1, patterns: []string{"claude", "cursor"}}
	m := New(f, tracker, cache, nil)
	m.retryDelays = []time.Duration{time.Millisecond}
	m.interval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	go m.Run(ctx)
	select {
	case <-m.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("manager never became ready")
	}
	cancel()
	if got := tracker.PatternCount(); got != 2 {
		t.Fatalf("patterns = %d, want 2", got)
	}
	if f.calls.Load() != 2 {
		t.Errorf("calls = %d, want 2 (one failure, one success)", f.calls.Load())
	}

	// Second run: backend unreachable; the cache keeps detection working.
	lineage.ResetForTesting()
	tracker = lineage.GetLineageTracker()
	m2 := New(&fakeFetcher{failures: 100}, tracker, cache, nil)
	m2.retryDelays = nil
	m2.interval = time.Hour
	if n := m2.LoadCache(); n != 2 {
		t.Fatalf("LoadCache = %d, want 2", n)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	go m2.Run(ctx2)
	<-m2.Ready()
	cancel2()
	if !tracker.CheckPattern("claude") {
		t.Error("cached patterns should be active when the backend is down")
	}
}

func TestManager_ReadyClosesOnCancel(t *testing.T) {
	lineage.ResetForTesting()
	m := New(&fakeFetcher{failures: 100}, nil, "", nil)
	m.retryDelays = []time.Duration{time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel while waiting on a retry delay")
	}
	select {
	case <-m.Ready():
	default:
		t.Error("Ready must be closed even when the initial fetch is cancelled")
	}
}

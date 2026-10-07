package process

import (
	"os"
	"testing"
	"time"
)

func TestClassifyLifecycle_Nil(t *testing.T) {
	if ClassifyLifecycle(nil, DefaultLifecycleConfig()) != nil {
		t.Error("nil lifecycle should return nil annotations")
	}
}

func TestClassifyLifecycle_ExecOnlyRunning_Daemon(t *testing.T) {
	lc := &Lifecycle{PID: 100, Running: true, Children: nil}
	cfg := DefaultLifecycleConfig()
	a := ClassifyLifecycle(lc, cfg)
	if a == nil {
		t.Fatal("expected annotations")
	}
	if a.Class != "daemon" || !a.Daemonized {
		t.Errorf("running process: want class=daemon daemonized=true, got class=%s daemonized=%v", a.Class, a.Daemonized)
	}
	if !a.NoChildren {
		t.Error("no children: want NoChildren=true")
	}
	if a.ForkedChildren {
		t.Error("no children: want ForkedChildren=false")
	}
}

func TestClassifyLifecycle_ExecOnlyNoExitNoChildren_Daemon(t *testing.T) {
	lc := &Lifecycle{PID: 100, Running: true, Children: []*Lifecycle{}}
	cfg := DefaultLifecycleConfig()
	a := ClassifyLifecycle(lc, cfg)
	if a == nil {
		t.Fatal("expected annotations")
	}
	if a.Class != "daemon" || !a.Daemonized || !a.NoChildren {
		t.Errorf("exec only, no exit, no children: want class=daemon daemonized=true no_children=true, got class=%s daemonized=%v no_children=%v",
			a.Class, a.Daemonized, a.NoChildren)
	}
}

func TestClassifyLifecycle_ShortLived(t *testing.T) {
	ms := int64(100)
	lc := &Lifecycle{PID: 100, Running: false, DurationMs: &ms, Children: nil}
	cfg := DefaultLifecycleConfig()
	a := ClassifyLifecycle(lc, cfg)
	if a == nil {
		t.Fatal("expected annotations")
	}
	if !a.ShortLived || a.Class != "short_lived" {
		t.Errorf("exit < 500ms: want short_lived=true class=short_lived, got short_lived=%v class=%s", a.ShortLived, a.Class)
	}
}

func TestClassifyLifecycle_ChildrenLongRuntime_Daemon(t *testing.T) {
	ms := int64(60 * 1000) // 60s
	lc := &Lifecycle{PID: 100, Running: false, DurationMs: &ms, Children: []*Lifecycle{{PID: 101}}}
	cfg := DefaultLifecycleConfig()
	a := ClassifyLifecycle(lc, cfg)
	if a == nil {
		t.Fatal("expected annotations")
	}
	if !a.Daemonized || a.Class != "daemon" || !a.ForkedChildren {
		t.Errorf("long runtime + children: want daemonized=true class=daemon forked_children=true, got daemonized=%v class=%s forked_children=%v",
			a.Daemonized, a.Class, a.ForkedChildren)
	}
}

func TestClassifyLifecycle_NoChildrenLongRuntime_Batch(t *testing.T) {
	ms := int64(10 * 1000) // 10s
	lc := &Lifecycle{PID: 100, Running: false, DurationMs: &ms, Children: nil}
	cfg := DefaultLifecycleConfig()
	a := ClassifyLifecycle(lc, cfg)
	if a == nil {
		t.Fatal("expected annotations")
	}
	if a.Class != "batch" {
		t.Errorf("no children, > short_lived threshold: want class=batch, got %s", a.Class)
	}
	if a.Daemonized {
		t.Error("no children: should not be daemonized")
	}
}

func TestClassifyLifecycle_ShortLivedNoChildren(t *testing.T) {
	ms := int64(200)
	lc := &Lifecycle{PID: 100, Running: false, DurationMs: &ms, Children: nil}
	cfg := DefaultLifecycleConfig()
	a := ClassifyLifecycle(lc, cfg)
	if a == nil {
		t.Fatal("expected annotations")
	}
	if !a.ShortLived || !a.NoChildren || a.Class != "short_lived" {
		t.Errorf("short_lived + no_children: want short_lived=true no_children=true class=short_lived, got %+v", a)
	}
}

func TestClassifyLifecycle_Unknown(t *testing.T) {
	lc := &Lifecycle{PID: 100, Running: false, DurationMs: nil, Children: nil}
	cfg := DefaultLifecycleConfig()
	a := ClassifyLifecycle(lc, cfg)
	if a == nil {
		t.Fatal("expected annotations")
	}
	if a.Class != "unknown" {
		t.Errorf("no duration: want class=unknown, got %s", a.Class)
	}
}

func TestLifecycleConfigFromEnv_Overrides(t *testing.T) {
	os.Setenv("EXEC_SHORT_LIVED_MS", "1000")
	os.Setenv("EXEC_DAEMON_MIN_MS", "60000")
	defer func() {
		os.Unsetenv("EXEC_SHORT_LIVED_MS")
		os.Unsetenv("EXEC_DAEMON_MIN_MS")
	}()

	cfg := LifecycleConfigFromEnv()
	if cfg.ShortLivedThreshold != 1000*time.Millisecond {
		t.Errorf("ShortLivedThreshold: want 1s, got %v", cfg.ShortLivedThreshold)
	}
	if cfg.DaemonMinRuntime != 60000*time.Millisecond {
		t.Errorf("DaemonMinRuntime: want 60s, got %v", cfg.DaemonMinRuntime)
	}

	// 1500ms with 1000ms threshold → batch (above short_lived threshold)
	ms := int64(1500)
	lc := &Lifecycle{PID: 100, Running: false, DurationMs: &ms, Children: nil}
	a := ClassifyLifecycle(lc, cfg)
	if a.ShortLived || a.Class == "short_lived" {
		t.Errorf("1500ms with 1000ms threshold: should not be short_lived, got %+v", a)
	}
	if a.Class != "batch" {
		t.Errorf("expected batch, got %s", a.Class)
	}
}

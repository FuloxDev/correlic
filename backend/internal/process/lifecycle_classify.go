package process

import "time"

// ClassifyLifecycle derives LifecycleAnnotations from a lifecycle and config.
// Annotations are response-only; not persisted.
//
// Intentional semantics:
//   - "daemon" = long-running or currently running process (candidate daemon).
//   - If lc.Running is true we classify as daemon without requiring min runtime or children.
//   - This is conservative and avoids timing heuristics; AI can later say "currently running (candidate daemon)".
//   - Refinements (e.g. min_runtime_ms or has_children for running) can be added in a later tuning phase.
func ClassifyLifecycle(lc *Lifecycle, cfg LifecycleConfig) *LifecycleAnnotations {
	if lc == nil {
		return nil
	}
	a := &LifecycleAnnotations{}

	if len(lc.Children) > 0 {
		a.ForkedChildren = true
	} else {
		a.NoChildren = true
	}

	if lc.Running {
		a.Class = "daemon"
		a.Daemonized = true
		return a
	}

	if lc.DurationMs != nil {
		d := time.Duration(*lc.DurationMs) * time.Millisecond
		if d <= cfg.ShortLivedThreshold {
			a.ShortLived = true
			a.Class = "short_lived"
			return a
		}
		if d >= cfg.DaemonMinRuntime && a.ForkedChildren {
			a.Daemonized = true
			a.Class = "daemon"
			return a
		}
		a.Class = "batch"
		return a
	}

	a.Class = "unknown"
	return a
}

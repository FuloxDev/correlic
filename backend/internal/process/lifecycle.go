package process

import (
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

// LifecycleAnnotations are derived, response-only attributes. Not persisted.
type LifecycleAnnotations struct {
	ShortLived     bool   `json:"short_lived,omitempty"`
	Daemonized     bool   `json:"daemonized,omitempty"`
	ForkedChildren bool   `json:"forked_children,omitempty"`
	NoChildren     bool   `json:"no_children,omitempty"`
	Class          string `json:"class,omitempty"` // short_lived | daemon | batch | interactive | unknown
}

// Lifecycle is the derived process lifecycle: exec + optional exit, with child linkage.
// Domain model; not a query row. Used by API, timeline enrichment, and future detections.
type Lifecycle struct {
	PID       int          `json:"pid"`
	PPID      int          `json:"ppid"`
	ExecEvent *event.Event `json:"exec_event,omitempty"`
	ExitEvent *event.Event `json:"exit_event,omitempty"`

	ExePath   string     `json:"exe_path"`
	StartTime time.Time  `json:"start_time"`
	ExitTime  *time.Time `json:"exit_time,omitempty"`
	ExitCode  *int       `json:"exit_code,omitempty"`

	DurationMs  *int64                `json:"duration_ms,omitempty"`
	Running     bool                  `json:"running"`
	Children    []*Lifecycle          `json:"children,omitempty"`
	Annotations *LifecycleAnnotations `json:"annotations,omitempty"`
}

// LifecycleView is a flat view of lifecycle for timeline enrichment (response-only).
type LifecycleView struct {
	DurationMs *int64
	Exited     bool
}

// LifecycleViewByPID returns a map of PID to LifecycleView for all lifecycles in the tree.
func LifecycleViewByPID(roots []*Lifecycle) map[int]LifecycleView {
	out := make(map[int]LifecycleView)
	var walk func([]*Lifecycle)
	walk = func(lcs []*Lifecycle) {
		for _, lc := range lcs {
			out[lc.PID] = LifecycleView{DurationMs: lc.DurationMs, Exited: !lc.Running}
			walk(lc.Children)
		}
	}
	walk(roots)
	return out
}

// LifecycleAnnotationsByPID returns a map of PID to LifecycleAnnotations for all lifecycles in the tree.
func LifecycleAnnotationsByPID(roots []*Lifecycle) map[int]*LifecycleAnnotations {
	out := make(map[int]*LifecycleAnnotations)
	var walk func([]*Lifecycle)
	walk = func(lcs []*Lifecycle) {
		for _, lc := range lcs {
			if lc.Annotations != nil {
				out[lc.PID] = lc.Annotations
			}
			walk(lc.Children)
		}
	}
	walk(roots)
	return out
}

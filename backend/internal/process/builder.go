package process

import (
	"sort"

	"github.com/correlic/correlic-backend/internal/event"
)

// Builder builds lifecycles from exec and exit events. Order-independent; first exec per PID wins.
// Exit before exec is stored and attached when exec arrives. Duplicate execs ignored.
type Builder struct {
	byPID       map[int]*Lifecycle
	pendingExit map[int]*event.Event
}

// NewBuilder returns a new Builder.
func NewBuilder() *Builder {
	return &Builder{
		byPID:       make(map[int]*Lifecycle),
		pendingExit: make(map[int]*event.Event),
	}
}

// AddExec registers a process_exec event. First exec for PID wins; duplicates ignored.
func (b *Builder) AddExec(evt event.Event) {
	if evt.Type != "process_exec" || evt.Process == nil {
		return
	}
	pid := evt.Process.PID
	if pid == 0 {
		return
	}
	if _, exists := b.byPID[pid]; exists {
		return
	}
	lc := &Lifecycle{
		PID:       pid,
		PPID:      evt.Process.PPID,
		ExecEvent: &evt,
		ExePath:   evt.Process.ExePath,
		StartTime: evt.Timestamp,
		Running:   true,
	}
	b.byPID[pid] = lc
	if exitEvt, ok := b.pendingExit[pid]; ok {
		b.attachExit(lc, exitEvt)
		delete(b.pendingExit, pid)
	}
}

// AddExit registers a process_exit event. Attaches to existing lifecycle or stores for later.
func (b *Builder) AddExit(evt event.Event) {
	if evt.Type != "process_exit" || evt.Process == nil {
		return
	}
	pid := evt.Process.PID
	if pid == 0 {
		return
	}
	if lc, ok := b.byPID[pid]; ok {
		b.attachExit(lc, &evt)
		return
	}
	b.pendingExit[pid] = &evt
}

func (b *Builder) attachExit(lc *Lifecycle, evt *event.Event) {
	// Phase 18B: exit before exec is ignored for lifecycle modeling (reordered or bad clock).
	if evt.Timestamp.Before(lc.StartTime) {
		ExecExitBeforeExec.Add(1)
		return
	}
	// Identity comes from exec only; never trust exe_path on exit.
	lc.ExitEvent = evt
	lc.ExitTime = &evt.Timestamp
	lc.Running = false
	if evt.Context != nil {
		if c, ok := evt.Context["exit_code"]; ok {
			switch v := c.(type) {
			case int:
				lc.ExitCode = &v
			case float64:
				i := int(v)
				lc.ExitCode = &i
			case int64:
				i := int(v)
				lc.ExitCode = &i
			}
		}
	}
	if lc.ExitTime != nil {
		ms := lc.ExitTime.Sub(lc.StartTime).Milliseconds()
		lc.DurationMs = &ms
	}
}

// Build links children by PPID, returns top-level lifecycles sorted by StartTime asc.
func (b *Builder) Build() []*Lifecycle {
	for _, lc := range b.byPID {
		lc.Children = nil
	}
	for _, lc := range b.byPID {
		if lc.PPID == 0 {
			continue
		}
		parent, ok := b.byPID[lc.PPID]
		if !ok {
			continue
		}
		parent.Children = append(parent.Children, lc)
	}
	var roots []*Lifecycle
	for _, lc := range b.byPID {
		if lc.PPID == 0 {
			roots = append(roots, lc)
			continue
		}
		if _, parentInSet := b.byPID[lc.PPID]; !parentInSet {
			roots = append(roots, lc)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].StartTime.Before(roots[j].StartTime)
	})

	// Classify each lifecycle once per build; config loaded once (not per lifecycle).
	cfg := LifecycleConfigFromEnv()
	for _, lc := range b.byPID {
		lc.Annotations = ClassifyLifecycle(lc, cfg)
	}
	return roots
}

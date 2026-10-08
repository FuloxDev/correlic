// Package health keeps a small, process-wide picture of the agent's link to
// the backend so that persistent failures (most importantly a rejected API
// key) are surfaced in the logs at WARN once per minute rather than once per
// batch, and can be read back by the heartbeat.
package health

import (
	"log/slog"
	"sort"
	"sync"
	"time"
)

// WarnThrottle is the minimum interval between repeated WARN lines for the
// same component.
const WarnThrottle = time.Minute

// State is the per-component delivery state.
type State struct {
	// Status is the last HTTP status that caused the failure (0 for network errors).
	Status int
	// Err is the last error text.
	Err string
	// Since is when the component first started failing.
	Since time.Time
	// Dropped counts items (batches, events) dropped while failing.
	Dropped int64
}

type registry struct {
	mu       sync.Mutex
	failing  map[string]*State
	lastWarn map[string]time.Time
	now      func() time.Time
}

var global = &registry{
	failing:  make(map[string]*State),
	lastWarn: make(map[string]time.Time),
	now:      time.Now,
}

// ReportAuthRejected records that the backend rejected component's request
// with status (401/403). It logs an actionable WARN at most once per minute
// per component and returns true when it logged.
func ReportAuthRejected(component string, status int, err error) bool {
	return global.reportAuthRejected(component, status, err)
}

// ReportFailure records a non-auth delivery failure for component (5xx or
// network error). It logs at WARN at most once per minute per component.
func ReportFailure(component string, status int, err error, dropped int64) bool {
	return global.reportFailure(component, status, err, dropped)
}

// ReportOK clears the failing state for component. When the component was
// failing, an INFO "recovered" line is logged.
func ReportOK(component string) {
	global.reportOK(component)
}

// Snapshot returns a copy of the currently failing components.
func Snapshot() map[string]State {
	return global.snapshot()
}

// Failing reports whether any component is currently failing.
func Failing() bool {
	global.mu.Lock()
	defer global.mu.Unlock()
	return len(global.failing) > 0
}

func (r *registry) reportAuthRejected(component string, status int, err error) bool {
	r.mu.Lock()
	st := r.touch(component, status, err, 0)
	st.Dropped++
	logNow := r.shouldWarn(component)
	r.mu.Unlock()
	if !logNow {
		return false
	}
	slog.Warn("backend rejected the agent API key; telemetry from this component is being dropped",
		"component", component,
		"status", status,
		"failing_since", st.Since.Format(time.RFC3339),
		"dropped", st.Dropped,
		"action", "check api_key in agent.yaml: it must be an agent-type key for this org; rotate it with correlic-admin and restart the agent",
		"error", errText(err),
	)
	return true
}

func (r *registry) reportFailure(component string, status int, err error, dropped int64) bool {
	r.mu.Lock()
	st := r.touch(component, status, err, dropped)
	logNow := r.shouldWarn(component)
	r.mu.Unlock()
	if !logNow {
		return false
	}
	slog.Warn("backend delivery failing; retrying with backoff",
		"component", component,
		"status", status,
		"failing_since", st.Since.Format(time.RFC3339),
		"dropped", st.Dropped,
		"error", errText(err),
	)
	return true
}

func (r *registry) reportOK(component string) {
	r.mu.Lock()
	st, was := r.failing[component]
	delete(r.failing, component)
	delete(r.lastWarn, component)
	r.mu.Unlock()
	if was {
		slog.Info("backend delivery recovered",
			"component", component,
			"was_failing_for", r.now().Sub(st.Since).Round(time.Second).String(),
			"dropped_while_failing", st.Dropped,
		)
	}
}

// touch returns the state for component, creating it when needed. Caller holds the lock.
func (r *registry) touch(component string, status int, err error, dropped int64) *State {
	st, ok := r.failing[component]
	if !ok {
		st = &State{Since: r.now()}
		r.failing[component] = st
	}
	st.Status = status
	st.Err = errText(err)
	st.Dropped += dropped
	return st
}

// shouldWarn applies the once-per-minute throttle. Caller holds the lock.
func (r *registry) shouldWarn(component string) bool {
	now := r.now()
	if last, ok := r.lastWarn[component]; ok && now.Sub(last) < WarnThrottle {
		return false
	}
	r.lastWarn[component] = now
	return true
}

func (r *registry) snapshot() map[string]State {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]State, len(r.failing))
	for k, v := range r.failing {
		out[k] = *v
	}
	return out
}

// FailingComponents returns the sorted names of failing components.
func FailingComponents() []string {
	snap := Snapshot()
	names := make([]string, 0, len(snap))
	for k := range snap {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// resetForTesting clears all state. Tests only.
func resetForTesting(now func() time.Time) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.failing = make(map[string]*State)
	global.lastWarn = make(map[string]time.Time)
	if now != nil {
		global.now = now
	} else {
		global.now = time.Now
	}
}

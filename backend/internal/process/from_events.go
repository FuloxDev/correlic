package process

import (
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

// Exit cleanup (Phase 18B) — what to watch, no fix needed:
//   - Long-running daemons: exit after query window is not attached. Window-scoped model is correct; AI reasons within window. Feature, not bug.
//   - Exit storms after reboot/suspend: burst of exits with no execs are dropped; exec_exit_no_exec (and related) may spike once per boot. Normal.
//
// Optional future hardening (not v1):
//   - Asymmetric window: also require (exitTs - exec.StartTime) < MAX_PROCESS_LIFETIME to cap "process lived years" from clock skew.
//   - Unit tests: drop future exit, drop exit before exec, no graph node for unpaired exit — protects refactors when AI leans on lifecycle.
//

// ExitTimestampInBounds reports whether t is within the allowed year range for process_exit (lifecycle and graph).
// Bounds come from ExitYearBoundsFromEnv() (EXIT_YEAR_MIN, EXIT_YEAR_MAX; default 2000–2100).
func ExitTimestampInBounds(t time.Time) bool {
	minYear, maxYear := ExitYearBoundsFromEnv()
	yr := t.Year()
	return yr >= minYear && yr <= maxYear
}

// BuildLifecyclesFromEvents builds lifecycles from a slice of canonical events in one pass.
// Only process_exec and process_exit are used; other types ignored. No DB access.
// Phase 18B: process_exit with timestamp > (max event time)+ExitMaxFutureFromEnv() is ignored (insane future).
// Exits with timestamp year outside ExitYearBoundsFromEnv() (default 2000–2100) are dropped (exec_exit_year_out_of_bounds).
// Exit before exec start is ignored in Builder.attachExit. Never trust exe_path on exit.
func BuildLifecyclesFromEvents(events []event.Event) []*Lifecycle {
	if len(events) == 0 {
		return nil
	}
	exitMaxFuture := ExitMaxFutureFromEnv()
	// Reference time: latest timestamp in window. Exits after this + window are dropped.
	var maxTs time.Time
	for i := range events {
		if events[i].Timestamp.After(maxTs) {
			maxTs = events[i].Timestamp
		}
	}
	cutoff := maxTs.Add(exitMaxFuture)

	b := NewBuilder()
	for _, e := range events {
		switch e.Type {
		case "process_exec":
			b.AddExec(e)
		case "process_exit":
			if !ExitTimestampInBounds(e.Timestamp) {
				ExecExitYearOutOfBounds.Add(1)
				continue
			}
			if e.Timestamp.After(cutoff) {
				ExecExitFuture.Add(1)
				continue
			}
			b.AddExit(e)
		}
	}
	return b.Build()
}

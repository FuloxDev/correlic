// Package normalize (exec_cleanup.go)
//
// Exec cleanup is NOT:
//   - fork bomb prevention
//   - process lifecycle tracking
//   - security verdict
//
// It is:
//   - noise suppression
//   - storage protection
//   - correlation preservation

package normalize

// ExecCleanupDecision is the result of post-normalization exec cleanup policy.
type ExecCleanupDecision struct {
	Drop   bool
	Reason string
}

// ShouldDropExec decides whether to drop an exec event based only on normalized context.
// Uses exec_class and exec_role from Phase 12+ normalization. No PID history or timing logic.
func ShouldDropExec(ctx map[string]any) ExecCleanupDecision {
	class, _ := ctx["exec_class"].(string)
	role, _ := ctx["exec_role"].(string)
	normalized, _ := ctx["exec_normalized"].(bool)

	if !normalized {
		return ExecCleanupDecision{Drop: false}
	}

	// Drop ephemeral shell / runtime helpers
	if role == "ephemeral" {
		return ExecCleanupDecision{
			Drop:   true,
			Reason: "exec_ephemeral",
		}
	}

	// Drop helper forks (gen, fork helpers)
	if class == "helper" {
		return ExecCleanupDecision{
			Drop:   true,
			Reason: "exec_helper_burst",
		}
	}

	return ExecCleanupDecision{Drop: false}
}

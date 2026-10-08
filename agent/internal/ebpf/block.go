//go:build linux

package ebpf

import (
	"log/slog"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/enforcer"
)

// applyBlockRule runs the soft-block check for one signal. When a rule
// matches, the process is killed (the whole tree only if the rule says so),
// a block_event is emitted and true is returned. The event that triggered
// the check should still be dispatched so the UI shows what was blocked.
//
// candidate is the value matched against the rule: the exe path for
// process_exec, "ip:port" for net_connect, the file path for file_open.
func applyBlockRule(enf *enforcer.Enforcer, emit collect.EventSink, logger *slog.Logger,
	signalType string, pid uint32, candidate string, extra map[string]any) bool {
	if enf == nil || !enf.IsEnabled() || enf.IsProtected(pid) {
		return false
	}
	blocked, rule := enf.ShouldBlock(signalType, candidate)
	if !blocked {
		return false
	}
	start := time.Now()
	success, killErr := enf.Kill(pid, rule.KillTree)
	latency := time.Since(start)
	// Mark as blocked when the rule MATCHED, regardless of kill success:
	// fast processes may exit before the signal lands, the intent stands.
	logger.Warn("BLOCKED "+signalType,
		"pid", pid, "candidate", candidate, "rule_id", rule.ID,
		"kill_tree", rule.KillTree, "success", success, "latency", latency)
	if emit != nil {
		payload := map[string]any{
			"rule_id":     rule.ID,
			"signal_type": signalType,
			"pid":         int(pid),
			"success":     success,
			"error_msg":   errString(killErr),
			"latency_us":  latency.Microseconds(),
		}
		for k, v := range extra {
			payload[k] = v
		}
		emit("block_event", payload)
	}
	return true
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

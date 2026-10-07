//go:build linux

package ebpf

import (
	"context"
	"log/slog"

	"github.com/correlic/correlic-agent/internal/collect"
)

// SetuidRunner wraps the SetuidCollector to implement the collect.Collector interface.
type SetuidRunner struct {
	collector *SetuidCollector
	emit      collect.EventSink
	logger    *slog.Logger
}

// NewSetuidRunner creates a new privilege escalation monitoring runner.
func NewSetuidRunner(emit collect.EventSink, logger *slog.Logger) (*SetuidRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}

	collector, err := NewSetuidCollector(logger)
	if err != nil {
		return nil, err
	}

	return &SetuidRunner{
		collector: collector,
		emit:      emit,
		logger:    logger,
	}, nil
}

// Start implements the collect.Collector interface.
func (r *SetuidRunner) Start(ctx context.Context) {
	// Start the underlying collector
	go r.collector.Start(ctx)

	r.logger.Info("eBPF setuid runner started, forwarding privilege change events")

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("eBPF setuid runner stopping")
			r.collector.Close()
			return
		case event := <-r.collector.Events():
			// Categorize the event
			category, risk := categorizePrivilegeChange(event)

			// Skip expected privilege drops (e.g., sshd dropping to user)
			if category == "expected_drop" {
				continue
			}

			// Convert SetuidEvent to telemetry format
			payload := map[string]any{
				"pid":           event.PID,
				"ppid":          event.PPID,
				"old_uid":       event.OldUID,
				"old_euid":      event.OldEUID,
				"new_uid":       event.NewUID,
				"new_euid":      event.NewEUID,
				"new_suid":      event.NewSUID,
				"syscall":       event.SyscallName(),
				"comm":          event.Comm,
				"pcomm":         event.ParentComm,
				"category":      category,
				"risk":          risk,
				"is_escalation": event.IsEscalation(),
				"is_dropping":   event.IsDropping(),
				"source":        "ebpf",
			}

			ok := r.emit("privilege_change", payload)
			if !ok {
				r.logger.Debug("privilege change event dropped by sink")
			}
		}
	}
}

// Close releases eBPF resources.
func (r *SetuidRunner) Close() error {
	if r.collector != nil {
		return r.collector.Close()
	}
	return nil
}

// categorizePrivilegeChange returns a category and risk level.
func categorizePrivilegeChange(event SetuidEvent) (category, risk string) {
	// Privilege escalation to root - always critical
	if event.IsEscalation() {
		// Check if it's a known legitimate escalation
		legitimateEscalators := map[string]bool{
			"sudo": true, "su": true, "pkexec": true,
			"login": true, "sshd": true, "gdm": true,
			"lightdm": true, "docker": true, "containerd": true,
		}
		if legitimateEscalators[event.Comm] {
			return "legitimate_escalation", "info"
		}

		// Dev tools escalating - suspicious
		devTools := map[string]bool{
			"code": true, "node": true, "python": true, "python3": true,
			"cursor": true, "npm": true, "yarn": true,
		}
		if devTools[event.Comm] {
			return "dev_tool_escalation", "critical"
		}

		return "unexpected_escalation", "critical"
	}

	// Privilege drop - generally expected
	if event.IsDropping() {
		// sshd, nginx, etc. dropping privileges is expected
		expectedDroppers := map[string]bool{
			"sshd": true, "nginx": true, "apache": true, "httpd": true,
			"postgres": true, "mysql": true, "docker": true,
		}
		if expectedDroppers[event.Comm] {
			return "expected_drop", "none"
		}

		return "privilege_drop", "low"
	}

	// Same UID changes or identity switching
	if event.OldUID == event.NewUID {
		// Likely just identity confirmation
		return "identity_confirm", "low"
	}

	// User switching (non-root to non-root)
	return "user_switch", "medium"
}

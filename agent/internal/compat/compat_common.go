// Package compat provides platform-specific compatibility checking for the Correlic agent.
//
// On Linux, it probes the kernel for eBPF features (program types, map types, BTF).
// On macOS, it checks OS version, kqueue availability, and root privileges.
package compat

import (
	"fmt"
	"log/slog"
	"strings"
)

// Severity levels for check results.
const (
	SeverityOK       = "ok"
	SeverityWarn     = "warn"
	SeverityRequired = "required" // Agent cannot function without this
)

// Check represents a single compatibility check result.
type Check struct {
	Name        string // e.g. "ring_buffer", "btf", "kqueue"
	Severity    string // "ok", "warn", "required"
	Supported   bool
	Description string // Human-readable explanation
}

// Result holds the full compatibility report.
type Result struct {
	Compatible    bool    // True if all required checks pass
	KernelVersion string  // Linux kernel version or macOS version
	Arch          string  // e.g. "amd64", "arm64"
	Checks        []Check // Individual check results
	Remediation   string  // Platform-specific remediation text (shown when !Compatible)
}

// RequiredFailed returns only the checks that are required and failed.
func (r *Result) RequiredFailed() []Check {
	var failed []Check
	for _, c := range r.Checks {
		if c.Severity == SeverityRequired && !c.Supported {
			failed = append(failed, c)
		}
	}
	return failed
}

// Warnings returns checks that passed with warnings.
func (r *Result) Warnings() []Check {
	var warns []Check
	for _, c := range r.Checks {
		if c.Severity == SeverityWarn && !c.Supported {
			warns = append(warns, c)
		}
	}
	return warns
}

// LogReport logs the compatibility result at appropriate levels.
func (r *Result) LogReport(logger *slog.Logger) {
	logger.Info("compatibility check",
		"version", r.KernelVersion,
		"arch", r.Arch,
		"compatible", r.Compatible,
	)

	for _, c := range r.Checks {
		if c.Supported {
			logger.Debug("compat check passed", "check", c.Name)
		} else if c.Severity == SeverityRequired {
			logger.Error("compat check FAILED (required)", "check", c.Name, "detail", c.Description)
		} else {
			logger.Warn("compat check failed (optional)", "check", c.Name, "detail", c.Description)
		}
	}
}

// FormatReport returns a human-readable multi-line compatibility report.
func (r *Result) FormatReport() string {
	var b strings.Builder
	b.WriteString("Correlic Agent Compatibility Report\n")
	b.WriteString("====================================\n")
	b.WriteString(fmt.Sprintf("Version:    %s\n", r.KernelVersion))
	b.WriteString(fmt.Sprintf("Arch:       %s\n", r.Arch))
	b.WriteString(fmt.Sprintf("Compatible: %v\n\n", r.Compatible))

	b.WriteString("Checks:\n")
	for _, c := range r.Checks {
		status := "PASS"
		if !c.Supported {
			if c.Severity == SeverityRequired {
				status = "FAIL"
			} else {
				status = "WARN"
			}
		}
		b.WriteString(fmt.Sprintf("  [%s] %-28s %s\n", status, c.Name, c.Description))
	}

	if !r.Compatible && r.Remediation != "" {
		b.WriteString("\n")
		b.WriteString(r.Remediation)
	}

	return b.String()
}

func (r *Result) addCheck(c Check) {
	r.Checks = append(r.Checks, c)
	if c.Severity == SeverityRequired && !c.Supported {
		r.Compatible = false
	}
}

//go:build linux

package compat

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		input   string
		major   int
		minor   int
		wantErr bool
	}{
		{"6.18.9", 6, 18, false},
		{"5.8.0", 5, 8, false},
		{"5.8.0-kali-amd64", 5, 8, false},
		{"6.1.0-22-amd64", 6, 1, false},
		{"4.19.128", 4, 19, false},
		{"5.15.0-91-generic", 5, 15, false},
		{"6.8", 6, 8, false},
		{"invalid", 0, 0, true},
		{"", 0, 0, true},
		{"abc.def.ghi", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			major, minor, err := parseKernelVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseKernelVersion(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("parseKernelVersion(%q) unexpected error: %v", tt.input, err)
				return
			}
			if major != tt.major || minor != tt.minor {
				t.Errorf("parseKernelVersion(%q) = (%d, %d), want (%d, %d)",
					tt.input, major, minor, tt.major, tt.minor)
			}
		})
	}
}

func TestCheckKernelVersion(t *testing.T) {
	tests := []struct {
		version   string
		supported bool
	}{
		{"6.18.9", true},
		{"5.8.0", true},
		{"5.15.0", true},
		{"5.7.99", false},
		{"4.19.0", false},
		{"5.8.1-kali", true},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			c := checkKernelVersion(tt.version)
			if c.Supported != tt.supported {
				t.Errorf("checkKernelVersion(%q).Supported = %v, want %v",
					tt.version, c.Supported, tt.supported)
			}
			if c.Severity != SeverityRequired {
				t.Errorf("checkKernelVersion(%q).Severity = %q, want %q",
					tt.version, c.Severity, SeverityRequired)
			}
		})
	}
}

func TestCheckLinux(t *testing.T) {
	c := checkLinux()
	// We're running tests on Linux, so this should pass
	if !c.Supported {
		t.Skip("test only valid on Linux")
	}
	if c.Severity != SeverityRequired {
		t.Errorf("checkLinux().Severity = %q, want %q", c.Severity, SeverityRequired)
	}
}

func TestResultRequiredFailed(t *testing.T) {
	r := &Result{
		Compatible: false,
		Checks: []Check{
			{Name: "a", Severity: SeverityRequired, Supported: true},
			{Name: "b", Severity: SeverityRequired, Supported: false},
			{Name: "c", Severity: SeverityWarn, Supported: false},
			{Name: "d", Severity: SeverityRequired, Supported: false},
		},
	}

	failed := r.RequiredFailed()
	if len(failed) != 2 {
		t.Fatalf("RequiredFailed() returned %d checks, want 2", len(failed))
	}
	if failed[0].Name != "b" || failed[1].Name != "d" {
		t.Errorf("RequiredFailed() returned wrong checks: %v", failed)
	}
}

func TestResultWarnings(t *testing.T) {
	r := &Result{
		Checks: []Check{
			{Name: "a", Severity: SeverityRequired, Supported: false},
			{Name: "b", Severity: SeverityWarn, Supported: false},
			{Name: "c", Severity: SeverityWarn, Supported: true},
			{Name: "d", Severity: SeverityWarn, Supported: false},
		},
	}

	warns := r.Warnings()
	if len(warns) != 2 {
		t.Fatalf("Warnings() returned %d checks, want 2", len(warns))
	}
	if warns[0].Name != "b" || warns[1].Name != "d" {
		t.Errorf("Warnings() returned wrong checks: %v", warns)
	}
}

func TestFormatReport(t *testing.T) {
	r := &Result{
		Compatible:    true,
		KernelVersion: "6.18.9",
		Arch:          "amd64",
		Checks: []Check{
			{Name: "btf", Severity: SeverityRequired, Supported: true, Description: "BTF available"},
			{Name: "ring_buffer", Severity: SeverityWarn, Supported: false, Description: "Not available"},
		},
	}

	report := r.FormatReport()
	if !strings.Contains(report, "6.18.9") {
		t.Error("report should contain kernel version")
	}
	if !strings.Contains(report, "amd64") {
		t.Error("report should contain arch")
	}
	if !strings.Contains(report, "[PASS]") {
		t.Error("report should contain PASS for supported checks")
	}
	if !strings.Contains(report, "[WARN]") {
		t.Error("report should contain WARN for unsupported optional checks")
	}
}

func TestFormatReportIncompatible(t *testing.T) {
	r := &Result{
		Compatible:    false,
		KernelVersion: "4.19.0",
		Arch:          "amd64",
		Checks: []Check{
			{Name: "kernel_version", Severity: SeverityRequired, Supported: false, Description: "Too old"},
		},
		Remediation: fmt.Sprintf("Minimum supported kernel: Linux %d.%d+\n", MinKernelMajor, MinKernelMinor),
	}

	report := r.FormatReport()
	if !strings.Contains(report, "[FAIL]") {
		t.Error("report should contain FAIL for incompatible required checks")
	}
	if !strings.Contains(report, "Minimum supported kernel") {
		t.Error("report should contain remediation info when incompatible")
	}
}

func TestRunChecks(t *testing.T) {
	// Integration test — runs actual probes on the current system.
	// This will pass on any system that can run the agent.
	result := RunChecks()

	if result.KernelVersion == "" || result.KernelVersion == "unknown" {
		t.Error("RunChecks() should detect kernel version")
	}
	if result.Arch == "" {
		t.Error("RunChecks() should detect architecture")
	}
	if len(result.Checks) == 0 {
		t.Error("RunChecks() should return at least one check")
	}

	// Verify all expected check names are present
	expectedChecks := map[string]bool{
		"linux_os":        false,
		"kernel_version":  false,
		"btf":             false,
		"prog_tracepoint": false,
		"prog_kprobe":     false,
		"map_ring_buffer": false,
		"map_hash_map":    false,
		"privileges":      false,
	}

	for _, c := range result.Checks {
		if _, ok := expectedChecks[c.Name]; ok {
			expectedChecks[c.Name] = true
		}
	}

	for name, found := range expectedChecks {
		if !found {
			t.Errorf("RunChecks() missing expected check %q", name)
		}
	}
}

func TestAddCheckSetsCompatible(t *testing.T) {
	r := &Result{Compatible: true}

	// Adding a passing required check should keep Compatible true
	r.addCheck(Check{Name: "a", Severity: SeverityRequired, Supported: true})
	if !r.Compatible {
		t.Error("Compatible should remain true after passing required check")
	}

	// Adding a failing warn check should keep Compatible true
	r.addCheck(Check{Name: "b", Severity: SeverityWarn, Supported: false})
	if !r.Compatible {
		t.Error("Compatible should remain true after failing warn check")
	}

	// Adding a failing required check should set Compatible false
	r.addCheck(Check{Name: "c", Severity: SeverityRequired, Supported: false})
	if r.Compatible {
		t.Error("Compatible should be false after failing required check")
	}
}

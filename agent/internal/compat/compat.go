//go:build linux

package compat

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

// MinKernelMajor and MinKernelMinor define the minimum supported kernel version.
// Ring buffers and BTF/CO-RE both require Linux 5.8+.
const (
	MinKernelMajor = 5
	MinKernelMinor = 8
)

// RunChecks performs all kernel compatibility checks and returns a structured result.
func RunChecks() *Result {
	r := &Result{
		Compatible: true,
		Arch:       runtime.GOARCH,
	}

	// 1. OS check — must be Linux
	r.addCheck(checkLinux())

	// 2. Kernel version
	r.KernelVersion = detectKernelVersion()
	r.addCheck(checkKernelVersion(r.KernelVersion))

	// 3. BTF support (required for CO-RE)
	r.addCheck(checkBTF())

	// 4. Required BPF program types
	r.addCheck(checkProgramType("tracepoint", ebpf.TracePoint, true))
	r.addCheck(checkProgramType("kprobe", ebpf.Kprobe, true))
	r.addCheck(checkProgramType("raw_tracepoint", ebpf.RawTracepoint, true))

	// 5. Required BPF map types
	r.addCheck(checkMapType("ring_buffer", ebpf.RingBuf, true))
	r.addCheck(checkMapType("hash_map", ebpf.Hash, true))
	r.addCheck(checkMapType("lru_hash", ebpf.LRUHash, true))
	r.addCheck(checkMapType("percpu_array", ebpf.PerCPUArray, true))

	// 6. Optional capabilities (warn if missing)
	r.addCheck(checkMapType("perf_event_array", ebpf.PerfEventArray, false))

	// 7. Root / CAP_BPF check
	r.addCheck(checkPrivileges())

	r.Remediation = fmt.Sprintf("Minimum supported kernel: Linux %d.%d+\n"+
		"Supported distros: Ubuntu 20.10+, Debian 11+, RHEL 9+, Fedora 33+, Amazon Linux 2023+\n"+
		"Ensure CONFIG_DEBUG_INFO_BTF=y is enabled in your kernel config.\n",
		MinKernelMajor, MinKernelMinor)

	return r
}

// checkLinux verifies we're running on Linux.
func checkLinux() Check {
	if runtime.GOOS != "linux" {
		return Check{
			Name:        "linux_os",
			Severity:    SeverityRequired,
			Supported:   false,
			Description: fmt.Sprintf("eBPF requires Linux (running on %s)", runtime.GOOS),
		}
	}
	return Check{
		Name:        "linux_os",
		Severity:    SeverityRequired,
		Supported:   true,
		Description: "Linux detected",
	}
}

// detectKernelVersion reads the kernel version string.
func detectKernelVersion() string {
	// Try cilium/ebpf's version code first
	code, err := features.LinuxVersionCode()
	if err == nil {
		major := (code >> 16) & 0xFF
		minor := (code >> 8) & 0xFF
		patch := code & 0xFF
		return fmt.Sprintf("%d.%d.%d", major, minor, patch)
	}

	// Fallback: read /proc/version
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	// /proc/version format: "Linux version 6.18.9-kali-amd64 ..."
	parts := strings.Fields(string(data))
	if len(parts) >= 3 {
		return parts[2]
	}
	return "unknown"
}

// checkKernelVersion verifies the kernel is >= MinKernelMajor.MinKernelMinor.
func checkKernelVersion(version string) Check {
	major, minor, err := parseKernelVersion(version)
	if err != nil {
		return Check{
			Name:        "kernel_version",
			Severity:    SeverityRequired,
			Supported:   false,
			Description: fmt.Sprintf("Cannot parse kernel version %q", version),
		}
	}

	if major < MinKernelMajor || (major == MinKernelMajor && minor < MinKernelMinor) {
		return Check{
			Name:      "kernel_version",
			Severity:  SeverityRequired,
			Supported: false,
			Description: fmt.Sprintf("Kernel %d.%d is below minimum %d.%d (ring buffer + BTF require 5.8+)",
				major, minor, MinKernelMajor, MinKernelMinor),
		}
	}

	return Check{
		Name:        "kernel_version",
		Severity:    SeverityRequired,
		Supported:   true,
		Description: fmt.Sprintf("Kernel %d.%d meets minimum %d.%d", major, minor, MinKernelMajor, MinKernelMinor),
	}
}

// parseKernelVersion extracts major.minor from a version string like "6.18.9-kali-amd64".
func parseKernelVersion(version string) (major, minor int, err error) {
	// Strip any suffix after digits (e.g. "-kali-amd64")
	var patch int
	n, _ := fmt.Sscanf(version, "%d.%d.%d", &major, &minor, &patch)
	if n < 2 {
		return 0, 0, fmt.Errorf("cannot parse version: %s", version)
	}
	return major, minor, nil
}

// checkBTF verifies that BTF (BPF Type Format) is available.
// Required for CO-RE (Compile Once, Run Everywhere).
func checkBTF() Check {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	if err != nil {
		return Check{
			Name:      "btf",
			Severity:  SeverityRequired,
			Supported: false,
			Description: "BTF not available (/sys/kernel/btf/vmlinux missing). " +
				"Ensure CONFIG_DEBUG_INFO_BTF=y in kernel config",
		}
	}
	return Check{
		Name:        "btf",
		Severity:    SeverityRequired,
		Supported:   true,
		Description: "BTF available (CO-RE supported)",
	}
}

// checkProgramType probes whether a BPF program type is supported.
func checkProgramType(name string, pt ebpf.ProgramType, required bool) Check {
	severity := SeverityWarn
	if required {
		severity = SeverityRequired
	}

	err := features.HaveProgramType(pt)
	if err == nil {
		return Check{
			Name:        "prog_" + name,
			Severity:    severity,
			Supported:   true,
			Description: fmt.Sprintf("BPF program type %s supported", name),
		}
	}

	if errors.Is(err, ebpf.ErrNotSupported) {
		return Check{
			Name:        "prog_" + name,
			Severity:    severity,
			Supported:   false,
			Description: fmt.Sprintf("BPF program type %s not supported by kernel", name),
		}
	}

	// Probe error (permissions, etc.)
	return Check{
		Name:        "prog_" + name,
		Severity:    severity,
		Supported:   false,
		Description: fmt.Sprintf("BPF program type %s probe failed: %v", name, err),
	}
}

// checkMapType probes whether a BPF map type is supported.
func checkMapType(name string, mt ebpf.MapType, required bool) Check {
	severity := SeverityWarn
	if required {
		severity = SeverityRequired
	}

	err := features.HaveMapType(mt)
	if err == nil {
		return Check{
			Name:        "map_" + name,
			Severity:    severity,
			Supported:   true,
			Description: fmt.Sprintf("BPF map type %s supported", name),
		}
	}

	if errors.Is(err, ebpf.ErrNotSupported) {
		return Check{
			Name:        "map_" + name,
			Severity:    severity,
			Supported:   false,
			Description: fmt.Sprintf("BPF map type %s not supported by kernel", name),
		}
	}

	return Check{
		Name:        "map_" + name,
		Severity:    severity,
		Supported:   false,
		Description: fmt.Sprintf("BPF map type %s probe failed: %v", name, err),
	}
}

// checkPrivileges verifies the process has sufficient privileges for eBPF.
func checkPrivileges() Check {
	if os.Geteuid() == 0 {
		return Check{
			Name:        "privileges",
			Severity:    SeverityRequired,
			Supported:   true,
			Description: "Running as root",
		}
	}

	// Check for CAP_BPF (available since Linux 5.8)
	// We probe by attempting a simple BPF syscall — if we lack caps, we'll get EPERM.
	err := features.HaveMapType(ebpf.Hash)
	if err == nil {
		return Check{
			Name:        "privileges",
			Severity:    SeverityRequired,
			Supported:   true,
			Description: "CAP_BPF available (non-root with capabilities)",
		}
	}

	return Check{
		Name:        "privileges",
		Severity:    SeverityRequired,
		Supported:   false,
		Description: "Insufficient privileges. Run as root or grant CAP_BPF + CAP_PERFMON",
	}
}

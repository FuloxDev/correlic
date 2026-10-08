//go:build darwin

package compat

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/correlic/correlic-agent/internal/darwin/eslogger"
)

// MinMacOSMajor and MinMacOSMinor define the minimum supported macOS version.
// Go 1.26 binaries require macOS 11 (Big Sur) or later; Endpoint Security,
// kqueue and FSEvents are all available there.
const (
	MinMacOSMajor = 11
	MinMacOSMinor = 0
)

// RunChecks performs macOS compatibility checks and returns a structured result.
func RunChecks() *Result {
	r := &Result{
		Compatible: true,
		Arch:       runtime.GOARCH,
	}

	// 1. OS check
	r.addCheck(checkDarwin())

	// 2. macOS version
	r.KernelVersion = detectMacOSVersion()
	r.addCheck(checkMacOSVersion(r.KernelVersion))

	// 3. Root privileges (required for kqueue EVFILT_PROC on other users' processes)
	r.addCheck(checkPrivileges())

	// 4. kqueue availability (always available on macOS, just confirm)
	r.addCheck(checkKqueue())

	// 5. FSEvents availability (always available on macOS 10.5+)
	r.addCheck(checkFSEvents())

	// 6. lsof availability (needed for network monitoring)
	r.addCheck(checkLsof())

	// 7. Native Endpoint Security client (esf-tagged build + entitlement;
	//    warn if unavailable). Tried first at startup.
	r.addCheck(checkESF())

	// 8. eslogger: Apple's Endpoint Security CLI (macOS 13+). Tried second;
	//    the kqueue/FSEvents/lsof pollers are the last resort.
	r.addCheck(checkEslogger())

	r.Remediation = fmt.Sprintf("Minimum supported version: macOS %d.%d+ (Big Sur)\n"+
		"Run as root: sudo ./correlic-agent\n"+
		"Endpoint Security events (real PIDs, real-time): on macOS 13 or newer grant correlic-agent\n"+
		"Full Disk Access in System Settings > Privacy & Security so /usr/bin/eslogger can run.\n"+
		"The native ESF client needs an Apple entitlement the project does not hold.\n",
		MinMacOSMajor, MinMacOSMinor)

	return r
}

// checkEslogger reports whether the free Endpoint Security path is usable:
// /usr/bin/eslogger present (macOS 13+) and the agent running as root. Full
// Disk Access cannot be probed without starting eslogger; the agent logs a
// WARN with the remediation at startup when it is missing.
func checkEslogger() Check {
	if err := eslogger.Available(nil); err != nil {
		return Check{
			Name:      "eslogger",
			Severity:  SeverityWarn,
			Supported: false,
			Description: fmt.Sprintf("eslogger unavailable (%v); the agent will poll with kqueue/FSEvents/lsof. To fix: %s",
				err, eslogger.Remediation),
		}
	}
	return Check{
		Name:        "eslogger",
		Severity:    SeverityWarn,
		Supported:   true,
		Description: "eslogger available: Endpoint Security exec/exit/open events with real PIDs via /usr/bin/eslogger (needs Full Disk Access; network stays lsof)",
	}
}

func checkDarwin() Check {
	if runtime.GOOS != "darwin" {
		return Check{
			Name:        "macos",
			Severity:    SeverityRequired,
			Supported:   false,
			Description: fmt.Sprintf("macOS agent requires darwin (running on %s)", runtime.GOOS),
		}
	}
	return Check{
		Name:        "macos",
		Severity:    SeverityRequired,
		Supported:   true,
		Description: "macOS detected",
	}
}

// detectMacOSVersion reads the macOS product version via sw_vers.
func detectMacOSVersion() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func checkMacOSVersion(version string) Check {
	major, minor, err := parseMacOSVersion(version)
	if err != nil {
		return Check{
			Name:        "macos_version",
			Severity:    SeverityRequired,
			Supported:   false,
			Description: fmt.Sprintf("Cannot parse macOS version %q", version),
		}
	}

	if major < MinMacOSMajor || (major == MinMacOSMajor && minor < MinMacOSMinor) {
		return Check{
			Name:      "macos_version",
			Severity:  SeverityRequired,
			Supported: false,
			Description: fmt.Sprintf("macOS %d.%d is below minimum %d.%d (Big Sur)",
				major, minor, MinMacOSMajor, MinMacOSMinor),
		}
	}

	return Check{
		Name:        "macos_version",
		Severity:    SeverityRequired,
		Supported:   true,
		Description: fmt.Sprintf("macOS %d.%d meets minimum %d.%d", major, minor, MinMacOSMajor, MinMacOSMinor),
	}
}

// parseMacOSVersion handles both "10.15.7" and "14.3.1" (macOS 11+ uses single major).
func parseMacOSVersion(version string) (major, minor int, err error) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("cannot parse version: %s", version)
	}
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("cannot parse major: %s", version)
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("cannot parse minor: %s", version)
	}
	return major, minor, nil
}

func checkPrivileges() Check {
	if os.Geteuid() == 0 {
		return Check{
			Name:        "privileges",
			Severity:    SeverityRequired,
			Supported:   true,
			Description: "Running as root",
		}
	}
	return Check{
		Name:        "privileges",
		Severity:    SeverityRequired,
		Supported:   false,
		Description: "Root privileges required for process monitoring via kqueue",
	}
}

func checkKqueue() Check {
	// kqueue is always available on macOS/BSD — this is a sanity check
	return Check{
		Name:        "kqueue",
		Severity:    SeverityRequired,
		Supported:   true,
		Description: "kqueue available (process exec/exit monitoring)",
	}
}

func checkFSEvents() Check {
	// FSEvents has been available since macOS 10.5
	return Check{
		Name:        "fsevents",
		Severity:    SeverityRequired,
		Supported:   true,
		Description: "FSEvents available (file system monitoring)",
	}
}

func checkLsof() Check {
	path, err := exec.LookPath("lsof")
	if err != nil {
		return Check{
			Name:        "lsof",
			Severity:    SeverityRequired,
			Supported:   false,
			Description: "lsof not found in PATH (required for network monitoring)",
		}
	}
	return Check{
		Name:        "lsof",
		Severity:    SeverityRequired,
		Supported:   true,
		Description: fmt.Sprintf("lsof available at %s (network monitoring)", path),
	}
}

func checkESF() Check {
	// Probe ESF availability by inspecting the binary's code signature.
	// es_new_client() will fail with ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED if the
	// com.apple.developer.endpoint-security.client entitlement is absent.
	// We use codesign(1) here to check without actually opening an ESF client
	// (which would require root and would consume the one-client-per-process slot).
	self, err := os.Executable()
	if err != nil {
		return Check{
			Name:        "esf",
			Severity:    SeverityWarn,
			Supported:   false,
			Description: "ESF: cannot determine executable path",
		}
	}

	out, err := exec.Command("codesign", "-d", "--entitlements", "-", self).CombinedOutput()
	if err != nil {
		// Binary is not signed — ESF will be unavailable.
		return Check{
			Name:        "esf",
			Severity:    SeverityWarn,
			Supported:   false,
			Description: "native ESF client unavailable: binary is not code-signed with the Endpoint Security entitlement (expected without an Apple Developer account); eslogger or the kqueue/FSEvents pollers will be used instead",
		}
	}

	if strings.Contains(string(out), "com.apple.developer.endpoint-security.client") {
		return Check{
			Name:        "esf",
			Severity:    SeverityWarn,
			Supported:   true,
			Description: "Endpoint Security entitlement present; an esf-tagged build uses the native client before eslogger",
		}
	}

	return Check{
		Name:        "esf",
		Severity:    SeverityWarn,
		Supported:   false,
		Description: "native ESF client unavailable: entitlement missing (needs an Apple Developer Program Organization account); eslogger or the kqueue/FSEvents pollers will be used instead",
	}
}

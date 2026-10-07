//go:build windows

package compat

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// MinWindowsBuild is the minimum Windows build number supported.
// Windows 10 1809 (build 17763) ships the modern ETW kernel providers.
const MinWindowsBuild = 17763

// RunChecks performs Windows compatibility checks and returns a structured result.
func RunChecks() *Result {
	r := &Result{
		Compatible: true,
		Arch:       runtime.GOARCH,
	}

	r.addCheck(checkWindows())

	buildNum, buildStr := detectWindowsBuild()
	r.KernelVersion = buildStr
	r.addCheck(checkWindowsBuild(buildNum))

	r.addCheck(checkAdminPrivileges())
	r.addCheck(checkETWAccess())

	r.Remediation = fmt.Sprintf(
		"Minimum supported: Windows 10 1809 (build %d) / Windows Server 2019+\n"+
			"Run as Administrator (ETW kernel providers require elevation).\n",
		MinWindowsBuild,
	)

	return r
}

func checkWindows() Check {
	if runtime.GOOS != "windows" {
		return Check{
			Name:        "windows_os",
			Severity:    SeverityRequired,
			Supported:   false,
			Description: fmt.Sprintf("Windows agent requires windows (running on %s)", runtime.GOOS),
		}
	}
	return Check{
		Name:        "windows_os",
		Severity:    SeverityRequired,
		Supported:   true,
		Description: "Windows detected",
	}
}

// detectWindowsBuild reads the Windows build number from the registry.
func detectWindowsBuild() (int, string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE)
	if err != nil {
		// Fallback: try ver command
		return detectWindowsBuildViaVer()
	}
	defer k.Close()

	val, _, err := k.GetStringValue("CurrentBuildNumber")
	if err != nil {
		return detectWindowsBuildViaVer()
	}

	var build int
	fmt.Sscanf(strings.TrimSpace(val), "%d", &build)
	return build, fmt.Sprintf("Windows Build %s", val)
}

func detectWindowsBuildViaVer() (int, string) {
	out, err := exec.Command("cmd", "/c", "ver").Output()
	if err != nil {
		return 0, "unknown"
	}
	line := strings.TrimSpace(string(out))
	// Format: "Microsoft Windows [Version 10.0.19045.4412]"
	idx := strings.Index(line, "Version ")
	if idx < 0 {
		return 0, line
	}
	ver := line[idx+8:]
	ver = strings.TrimRight(ver, "]")
	parts := strings.Split(ver, ".")
	if len(parts) >= 3 {
		var build int
		fmt.Sscanf(parts[2], "%d", &build)
		return build, fmt.Sprintf("Windows Build %d", build)
	}
	return 0, line
}

func checkWindowsBuild(build int) Check {
	if build == 0 {
		return Check{
			Name:        "windows_build",
			Severity:    SeverityRequired,
			Supported:   false,
			Description: "Cannot determine Windows build number",
		}
	}
	if build < MinWindowsBuild {
		return Check{
			Name:      "windows_build",
			Severity:  SeverityRequired,
			Supported: false,
			Description: fmt.Sprintf("Windows build %d is below minimum %d (Windows 10 1809 / Server 2019 required)",
				build, MinWindowsBuild),
		}
	}
	return Check{
		Name:        "windows_build",
		Severity:    SeverityRequired,
		Supported:   true,
		Description: fmt.Sprintf("Windows build %d meets minimum %d", build, MinWindowsBuild),
	}
}

// checkAdminPrivileges checks whether the current process is elevated (Administrator).
func checkAdminPrivileges() Check {

	// OpenProcessToken on the current process, then check UAC elevation flag.
	// IsMember/CheckTokenMembership requires an impersonation token and fails
	// when the process was launched via Start-Process -Verb RunAs; IsElevated
	// reads TOKEN_ELEVATION directly and works with primary tokens.
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return Check{
			Name:        "admin_privileges",
			Severity:    SeverityRequired,
			Supported:   false,
			Description: fmt.Sprintf("Cannot open process token: %v", err),
		}
	}
	defer tok.Close()

	if !tok.IsElevated() {
		return Check{
			Name:        "admin_privileges",
			Severity:    SeverityRequired,
			Supported:   false,
			Description: "Not running as Administrator (required for ETW kernel providers)",
		}
	}
	return Check{
		Name:        "admin_privileges",
		Severity:    SeverityRequired,
		Supported:   true,
		Description: "Running as Administrator",
	}
}

// checkETWAccess verifies that the ETW StartTraceW API is accessible.
func checkETWAccess() Check {
	dll := windows.NewLazySystemDLL("advapi32.dll")
	proc := dll.NewProc("StartTraceW")
	if err := proc.Find(); err != nil {
		return Check{
			Name:        "etw_access",
			Severity:    SeverityRequired,
			Supported:   false,
			Description: fmt.Sprintf("ETW not available (StartTraceW missing): %v", err),
		}
	}
	return Check{
		Name:        "etw_access",
		Severity:    SeverityRequired,
		Supported:   true,
		Description: "ETW available (advapi32.StartTraceW found)",
	}
}

package ai_pack

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/correlic/correlic-backend/internal/detection"
)

// escalationCriticalBinaries are binaries that directly grant elevated privileges.
var escalationCriticalBinaries = map[string]bool{
	"sudo":    true,
	"su":      true,
	"pkexec":  true,
	"doas":    true,
	"nsenter": true,
	"setpriv": true, // Direct capability/privilege manipulation (util-linux)
	"runuser": true, // Run command as another user (RHEL/systemd)
	"debugfs": true, // ext filesystem debugger — read/write any file bypassing permissions
	// Kernel module loading
	"modprobe": true,
	"insmod":   true,
	"rmmod":    true,
	// Windows privilege escalation
	"runas.exe":    true, // Windows "sudo" equivalent — run as another user
	"psexec.exe":   true, // Sysinternals — remote/elevated execution
	"psexec64.exe": true,
}

// escalationHighBinaries are capability/permission manipulation tools.
var escalationHighBinaries = map[string]bool{
	"setcap":    true,
	"capsh":     true,
	"newgrp":    true, // Switch primary group
	"sg":        true, // Run command as different group
	"newuidmap": true, // User namespace UID mapping — container escape vector
	"newgidmap": true, // User namespace GID mapping — container escape vector
	"chroot":    true, // Filesystem isolation break/escape
	// Windows LOLBins — legitimate binaries abused for privilege escalation / execution
	"powershell.exe": true, // PowerShell — especially with -ExecutionPolicy Bypass
	"pwsh.exe":       true, // PowerShell Core
	"wmic.exe":       true, // WMI command-line (deprecated but still abused)
	"mshta.exe":      true, // HTML Application host — runs arbitrary HTA/JS
	"certutil.exe":   true, // Can download files, decode base64 (LOLBin)
	"regsvr32.exe":   true, // DLL registration — Squiblydoo attack vector
	"rundll32.exe":   true, // DLL execution — sideloading vector
	"cscript.exe":    true, // Windows Script Host (VBS/JS)
	"wscript.exe":    true, // Windows Script Host (VBS/JS)
}

// escalationMediumBinaries are filesystem/namespace manipulation tools.
var escalationMediumBinaries = map[string]bool{
	"mount":    true,
	"umount":   true,
	"unshare":  true,
	"losetup":  true, // Loop device manipulation — mount arbitrary images
	"firejail": true, // Sandbox escape if misconfigured
}

// chmodSetuidRegex matches chmod invocations that set setuid or setgid bits.
// Matches: u+s, g+s, 4755, 2755, 4xxx, 2xxx patterns.
var chmodSetuidRegex = regexp.MustCompile(`(?i)(u\+s|g\+s|[24]7[0-7]{2}|[24][0-7]{3})`)

// straceAttachRegex matches strace/ltrace attaching to a running process.
var straceAttachRegex = regexp.MustCompile(`-p\s*\d+`)

// gdbAttachRegex matches gdb attaching to a running process.
var gdbAttachRegex = regexp.MustCompile(`(--pid\s*\d+|-p\s*\d+|\battach\s+\d+)`)

// ddRawDiskRegex matches dd reading from raw block devices.
var ddRawDiskRegex = regexp.MustCompile(`if=/dev/(sd[a-z]|nvme\d|vd[a-z]|xvd[a-z]|loop\d|dm-\d)`)

// chownRootRegex matches chown invocations targeting root ownership.
var chownRootRegex = regexp.MustCompile(`\broot\b`)

// AIPrivilegeEscalation detects AI agent privilege escalation attempts.
type AIPrivilegeEscalation struct{}

func (d *AIPrivilegeEscalation) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.privilege_escalation",
		Pack:            "ai",
		Name:            "AI Privilege Escalation",
		Severity:        "critical",
		Description:     "AI agent executed privilege escalation commands",
		Tags:            []string{"ai", "privilege-escalation", "container-escape"},
		MITRETechniques: []string{"T1548", "T1548.003", "T1068", "T1611", "T1055.008"},
	}
}

func (d *AIPrivilegeEscalation) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"process_exec", "privilege_use"},
		WindowSecs: 0,
	}
}

func (d *AIPrivilegeEscalation) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt.Process == nil {
		return nil
	}

	// Handle privilege_use events (from Windows Security Audit Event 4672)
	if evt.Type == "privilege_use" {
		return d.evaluatePrivilegeUse(ctx)
	}

	isAI, aiType, err := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if err != nil || !isAI {
		return nil
	}

	binaryName := ""
	if evt.Process.ExePath != "" {
		binaryName = filepath.Base(evt.Process.ExePath)
	}
	if binaryName == "" || binaryName == "." {
		binaryName = evt.Process.Comm
	}
	if binaryName == "" {
		return nil
	}

	cmdline := ""
	if len(evt.Process.Cmdline) > 0 {
		cmdline = strings.Join(evt.Process.Cmdline, " ")
	}

	var severity string
	var confidence float64
	var mitreTechniques []string

	switch {
	case escalationCriticalBinaries[binaryName]:
		severity = "critical"
		confidence = 0.95
		switch {
		case binaryName == "sudo" || binaryName == "doas":
			mitreTechniques = []string{"T1548.003"}
		case binaryName == "su" || binaryName == "pkexec" || binaryName == "setpriv" || binaryName == "runuser":
			mitreTechniques = []string{"T1548"}
		case binaryName == "nsenter":
			mitreTechniques = []string{"T1611"}
		case binaryName == "modprobe" || binaryName == "insmod" || binaryName == "rmmod":
			mitreTechniques = []string{"T1068"}
		case binaryName == "debugfs":
			mitreTechniques = []string{"T1068"}
		default:
			mitreTechniques = []string{"T1548"}
		}

	case escalationHighBinaries[binaryName]:
		severity = "high"
		confidence = 0.85
		switch {
		case binaryName == "setcap" || binaryName == "capsh":
			mitreTechniques = []string{"T1548"}
		case binaryName == "newuidmap" || binaryName == "newgidmap":
			mitreTechniques = []string{"T1611"}
		case binaryName == "chroot":
			mitreTechniques = []string{"T1611"}
		case binaryName == "powershell.exe" || binaryName == "pwsh.exe":
			mitreTechniques = []string{"T1059.001"}
			// Upgrade severity for PowerShell bypass patterns
			lowerCmd := strings.ToLower(cmdline)
			if strings.Contains(lowerCmd, "-executionpolicy bypass") ||
				strings.Contains(lowerCmd, "-ep bypass") ||
				strings.Contains(lowerCmd, "-enc ") ||
				strings.Contains(lowerCmd, "-encodedcommand") {
				severity = "critical"
				confidence = 0.95
			}
		case binaryName == "mshta.exe" || binaryName == "regsvr32.exe" || binaryName == "rundll32.exe":
			mitreTechniques = []string{"T1218"} // System Binary Proxy Execution
		case binaryName == "cscript.exe" || binaryName == "wscript.exe":
			mitreTechniques = []string{"T1059.005"} // Visual Basic
		case binaryName == "certutil.exe":
			mitreTechniques = []string{"T1140"} // Deobfuscate/Decode Files
		case binaryName == "wmic.exe":
			mitreTechniques = []string{"T1047"} // WMI
		default:
			mitreTechniques = []string{"T1548"}
		}

	// chmod with setuid/setgid flags
	case binaryName == "chmod" && cmdline != "" && chmodSetuidRegex.MatchString(cmdline):
		severity = "high"
		confidence = 0.85
		mitreTechniques = []string{"T1548"}

	// chown targeting root
	case binaryName == "chown" && cmdline != "" && chownRootRegex.MatchString(cmdline):
		severity = "high"
		confidence = 0.85
		mitreTechniques = []string{"T1548"}

	// Process injection via debugger/tracer attach (T1055.008)
	case (binaryName == "strace" || binaryName == "ltrace") && cmdline != "" && straceAttachRegex.MatchString(cmdline):
		severity = "high"
		confidence = 0.85
		mitreTechniques = []string{"T1055.008"}

	case binaryName == "gdb" && cmdline != "" && gdbAttachRegex.MatchString(cmdline):
		severity = "high"
		confidence = 0.85
		mitreTechniques = []string{"T1055.008"}

	// Raw disk read — bypasses file permissions entirely
	case binaryName == "dd" && cmdline != "" && ddRawDiskRegex.MatchString(cmdline):
		severity = "high"
		confidence = 0.85
		mitreTechniques = []string{"T1068"}

	// machinectl shell — systemd-nspawn privilege escalation
	case binaryName == "machinectl" && cmdline != "" && strings.Contains(cmdline, "shell"):
		severity = "critical"
		confidence = 0.90
		mitreTechniques = []string{"T1611"}

	// ip netns exec — network namespace manipulation
	case binaryName == "ip" && cmdline != "" && strings.Contains(cmdline, "netns") && strings.Contains(cmdline, "exec"):
		severity = "medium"
		confidence = 0.70
		mitreTechniques = []string{"T1611"}

	case escalationMediumBinaries[binaryName]:
		severity = "medium"
		confidence = 0.70
		mitreTechniques = []string{"T1548"}
		// Upgrade: unshare --user is a namespace escalation technique
		if binaryName == "unshare" && strings.Contains(cmdline, "--user") {
			severity = "critical"
			confidence = 0.90
			mitreTechniques = []string{"T1611"}
		}

	default:
		return nil
	}

	baselinePattern := binaryName
	if cmdline != "" && cmdline != binaryName {
		baselinePattern = truncate(cmdline, 200)
	}

	title := fmt.Sprintf("AI agent attempted privilege escalation: %s", binaryName)
	summary := fmt.Sprintf("%s ran %s", aiType, binaryName)
	if cmdline != "" && cmdline != binaryName {
		summary = fmt.Sprintf("%s ran: %s", aiType, truncate(cmdline, 200))
	}

	fctx := map[string]any{
		"ai_type":     aiType,
		"binary":      binaryName,
		"cmdline":     cmdline,
		"pid":         evt.Process.PID,
		"ppid":        evt.Process.PPID,
		"signal_type": "escalation_cmd",
		"pattern":     baselinePattern,
	}
	if evt.Process.SessionID != "" {
		fctx["session_id"] = evt.Process.SessionID
	}
	if len(mitreTechniques) > 0 {
		fctx["mitre_techniques"] = mitreTechniques
	}
	if cmdline == "" {
		fctx["low_context"] = true
	}

	return []detection.Finding{
		{
			Title:      title,
			Summary:    summary,
			Severity:   severity,
			Confidence: confidence,
			Context:    fctx,
		},
	}
}

// evaluatePrivilegeUse detects actual sensitive privilege usage from Windows
// Security Audit Event 4672. This fires on REAL privilege use, not binary names.
func (d *AIPrivilegeEscalation) evaluatePrivilegeUse(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event

	isAI, aiType, _ := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if !isAI {
		return nil
	}

	privs := detection.StringSlice(evt.Context["privileges"])
	if len(privs) == 0 {
		return nil
	}

	// Map privileges to severity
	var criticalPrivs, highPrivs []string
	for _, p := range privs {
		switch p {
		case "SeDebugPrivilege", "SeTcbPrivilege", "SeCreateTokenPrivilege":
			criticalPrivs = append(criticalPrivs, p)
		case "SeLoadDriverPrivilege", "SeImpersonatePrivilege",
			"SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege",
			"SeRestorePrivilege", "SeTakeOwnershipPrivilege":
			highPrivs = append(highPrivs, p)
		}
	}

	if len(criticalPrivs) == 0 && len(highPrivs) == 0 {
		return nil
	}

	severity := "high"
	confidence := 0.90
	allPrivs := append(criticalPrivs, highPrivs...)
	if len(criticalPrivs) > 0 {
		severity = "critical"
		confidence = 0.95
	}

	title := fmt.Sprintf("AI agent used sensitive privileges: %s", strings.Join(allPrivs, ", "))
	summary := fmt.Sprintf("%s process (PID %d) activated %d sensitive privilege(s): %s",
		aiType, evt.Process.PID, len(allPrivs), strings.Join(allPrivs, ", "))

	return []detection.Finding{
		{
			Title:      title,
			Summary:    summary,
			Severity:   severity,
			Confidence: confidence,
			Context: map[string]any{
				"ai_type":          aiType,
				"privileges":       allPrivs,
				"pid":              evt.Process.PID,
				"user":             evt.Process.User,
				"signal_type":      "privilege",
				"pattern":          strings.Join(allPrivs, ","),
				"mitre_techniques": []string{"T1134", "T1548"},
			},
		},
	}
}

package ai_pack

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/correlic/correlic-backend/internal/detection"
)

// persistenceCriticalPaths are exact file paths that represent critical persistence mechanisms.
var persistenceCriticalPaths = map[string]bool{
	"/etc/crontab":       true,
	"/etc/sudoers":       true,
	"/etc/rc.local":      true,
	"/etc/ld.so.preload": true, // LD_PRELOAD hijacking — loads .so into every process (T1574.006)
	"/etc/ld.so.conf":    true, // Shared library search path manipulation
	"/etc/environment":   true, // System-wide env vars, persists across reboots
	"/etc/ssh/sshrc":     true, // System-wide SSH login hook
	"/etc/modules":       true, // Auto-loaded kernel modules at boot
}

// persistenceCriticalDirs are directory prefixes — any file under these is critical persistence.
var persistenceCriticalDirs = []string{
	"/var/spool/cron/",
	"/etc/cron.d/",
	"/etc/cron.daily/",
	"/etc/cron.hourly/",
	"/etc/cron.weekly/",
	"/etc/cron.monthly/",
	"/etc/sudoers.d/",
	"/etc/pam.d/",          // PAM backdoors — inject auth modules (T1556.003)
	"/etc/ld.so.conf.d/",   // Shared library search path directories
	"/etc/modules-load.d/", // Kernel module autoload at boot
	// Windows persistence directories (paths normalized to forward slashes by agent)
	"C:/Windows/System32/Tasks/",       // Scheduled Tasks XML definitions
	"C:/Windows/System32/GroupPolicy/", // Group Policy scripts
}

// persistenceHighDirs are directory segments that indicate high-severity persistence.
var persistenceHighDirs = []string{
	"/etc/init.d/",
	"/.git/hooks/",
	"/etc/systemd/system/",
	"/.config/systemd/user/",
	"/etc/security/",       // PAM limits/access.conf
	"/etc/modprobe.d/",     // Kernel module autoload rules
	"/etc/apt/apt.conf.d/", // APT hooks — run code on package operations
	"/etc/xdg/autostart/",  // Desktop autostart (T1547.001)
	"/.config/autostart/",  // User-level desktop autostart
	// Windows startup folders (paths normalized to forward slashes by agent)
	"/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/", // User startup
	"C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/",   // All-users startup
}

// persistenceHighBasenames are shell startup files (high severity).
var persistenceHighBasenames = map[string]bool{
	".bashrc":       true,
	".bash_profile": true,
	".zshrc":        true,
	".zprofile":     true,
	".zshenv":       true,
	".zlogin":       true,
	".profile":      true,
	"config.fish":   true, // Fish shell startup (~/.config/fish/config.fish)
}

// persistenceMediumDirs are directory prefixes for medium-severity persistence paths.
var persistenceMediumDirs = []string{
	"/etc/profile.d/",
	"/etc/udev/rules.d/",
	"/etc/NetworkManager/dispatcher.d/", // Runs scripts on network events
	"/etc/update-motd.d/",               // Runs as root on every login
	"/etc/dpkg/dpkg.cfg.d/",             // Debian package manager hooks
}

// persistenceMediumPaths are exact paths for medium-severity persistence.
var persistenceMediumPaths = map[string]bool{
	"/etc/profile":     true,
	"/etc/bash.bashrc": true,
}

// persistenceMediumBasenames are file basenames for medium-severity persistence.
var persistenceMediumBasenames = map[string]bool{
	".bash_logout": true, // Can exfiltrate data on session close
}

// persistenceCriticalCmds are binaries that directly manipulate persistence (critical severity).
var persistenceCriticalCmds = map[string]bool{
	"crontab":     true,
	"update-rc.d": true,
	"chkconfig":   true, // RHEL/CentOS service persistence
	// Windows persistence commands
	"schtasks.exe": true, // Windows Task Scheduler CLI
	"sc.exe":       true, // Service Control manager — create/modify services
	"reg.exe":      true, // Registry manipulation — Run keys, services
}

// persistenceHighCmds are binaries for scheduling (high severity).
var persistenceHighCmds = map[string]bool{
	"at":     true,
	"batch":  true,
	"at.exe": true, // Legacy Windows task scheduler
}

// AIPersistence detects AI agent access to persistence-sensitive locations
// or execution of persistence-related commands.
type AIPersistence struct{}

func (d *AIPersistence) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.persistence",
		Pack:            "ai",
		Name:            "AI Persistence Mechanism",
		Severity:        "critical",
		Description:     "AI agent accessed persistence-sensitive locations or executed persistence-related commands",
		Tags:            []string{"ai", "persistence", "scheduled-task"},
		MITRETechniques: []string{"T1546", "T1053", "T1098.004", "T1543", "T1574.006", "T1556.003", "T1547.001"},
	}
}

func (d *AIPersistence) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"file_open", "process_exec", "registry_write"},
		WindowSecs: 0,
	}
}

func (d *AIPersistence) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt.Process == nil {
		return nil
	}

	isAI, aiType, err := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if err != nil || !isAI {
		return nil
	}

	switch evt.Type {
	case "file_open":
		return d.evaluateFileOpen(ctx, aiType)
	case "process_exec":
		return d.evaluateExec(ctx, aiType)
	case "registry_write":
		return d.evaluateRegistryWrite(ctx, aiType)
	default:
		return nil
	}
}

// evaluateRegistryWrite detects persistence via registry modifications.
// Uses Windows Security Audit Event 4657 data — exact key path + old/new values.
func (d *AIPersistence) evaluateRegistryWrite(ctx *detection.EvalContext, aiType string) []detection.Finding {
	evt := ctx.Event
	if evt.Context == nil {
		return nil
	}

	regKey, _ := evt.Context["reg_key"].(string)
	regValue, _ := evt.Context["reg_value"].(string)
	newVal, _ := evt.Context["new_value"].(string)
	if regKey == "" {
		return nil
	}

	lowerKey := strings.ToLower(regKey)

	var severity string
	var confidence float64
	var title string
	var mitre []string

	switch {
	// Run keys — auto-start programs (T1547.001)
	case strings.Contains(lowerKey, `\currentversion\run`):
		severity = "critical"
		confidence = 0.95
		title = fmt.Sprintf("AI agent added Run key persistence: %s = %s", regValue, newVal)
		mitre = []string{"T1547.001"}

	// Services — create/modify Windows service (T1543.003)
	case strings.Contains(lowerKey, `\services\`) && (regValue == "ImagePath" || regValue == "Start"):
		severity = "critical"
		confidence = 0.95
		title = fmt.Sprintf("AI agent modified service: %s\\%s = %s", regKey, regValue, newVal)
		mitre = []string{"T1543.003"}

	// Winlogon — logon script persistence (T1547.004)
	case strings.Contains(lowerKey, `\winlogon`) && (regValue == "Shell" || regValue == "Userinit"):
		severity = "critical"
		confidence = 0.95
		title = fmt.Sprintf("AI agent modified Winlogon: %s = %s", regValue, newVal)
		mitre = []string{"T1547.004"}

	// AppInit_DLLs — DLL injection persistence (T1546.010)
	case strings.Contains(lowerKey, `\windows nt\currentversion\windows`) && regValue == "AppInit_DLLs":
		severity = "critical"
		confidence = 0.95
		title = fmt.Sprintf("AI agent set AppInit_DLLs: %s", newVal)
		mitre = []string{"T1546.010"}

	// Image File Execution Options — debugger hijack (T1546.012)
	case strings.Contains(lowerKey, `\image file execution options\`) && regValue == "Debugger":
		severity = "critical"
		confidence = 0.95
		title = fmt.Sprintf("AI agent set IFEO debugger: %s = %s", regKey, newVal)
		mitre = []string{"T1546.012"}

	// Windows Defender exclusions — defense evasion (T1562.001)
	case strings.Contains(lowerKey, `\windows defender\exclusions`):
		severity = "high"
		confidence = 0.90
		title = fmt.Sprintf("AI agent added Defender exclusion: %s", newVal)
		mitre = []string{"T1562.001"}

	default:
		return nil // Not a persistence-relevant key
	}

	return []detection.Finding{
		{
			Title:      title,
			Summary:    fmt.Sprintf("%s process modified registry key %s\\%s", aiType, regKey, regValue),
			Severity:   severity,
			Confidence: confidence,
			Context: map[string]any{
				"ai_type":          aiType,
				"reg_key":          regKey,
				"reg_value":        regValue,
				"new_value":        newVal,
				"pid":              evt.Process.PID,
				"comm":             evt.Process.Comm,
				"signal_type":      "registry_key",
				"pattern":          regKey,
				"mitre_techniques": mitre,
			},
		},
	}
}

func (d *AIPersistence) evaluateFileOpen(ctx *detection.EvalContext, aiType string) []detection.Finding {
	evt := ctx.Event
	if evt.Target == nil || evt.Target.FilePath == "" {
		return nil
	}

	// Non-existent files cannot be persistence targets (PATHEXT probes).
	if evt.Context != nil {
		if fe, ok := evt.Context["file_exists"]; ok {
			if fe == false || fe == "false" {
				return nil
			}
		}
	}

	filePath := evt.Target.FilePath
	basename := filepath.Base(filePath)
	isWrite := isWriteOpen(evt.Context)

	var severity string
	var confidence float64
	var mitreTechniques []string

	switch {
	// Critical: exact paths
	case persistenceCriticalPaths[filePath]:
		severity = "critical"
		confidence = 0.95
		mitreTechniques = mitreTechniquesForPath(filePath)

	// Critical: cron/sudoers directory prefixes
	case matchesAnyPrefix(filePath, persistenceCriticalDirs):
		severity = "critical"
		confidence = 0.95
		mitreTechniques = mitreTechniquesForPath(filePath)

	// Critical: SSH authorized_keys or rc (login hook)
	case strings.Contains(filePath, "/.ssh/") && (basename == "authorized_keys" || basename == "rc"):
		severity = "critical"
		confidence = 0.95
		mitreTechniques = []string{"T1098.004"}

	// High: init.d, git hooks, systemd, shell startup
	case matchesAnyContains(filePath, persistenceHighDirs):
		severity = "high"
		confidence = 0.85
		mitreTechniques = mitreTechniquesForPath(filePath)

	// High: shell startup basenames
	case persistenceHighBasenames[basename]:
		severity = "high"
		confidence = 0.85
		mitreTechniques = []string{"T1546"}

	// High: SSH config
	case strings.Contains(filePath, "/.ssh/") && basename == "config":
		severity = "high"
		confidence = 0.85
		mitreTechniques = []string{"T1098.004"}

	// Medium: profile.d, udev rules
	case matchesAnyPrefix(filePath, persistenceMediumDirs):
		severity = "medium"
		confidence = 0.70
		mitreTechniques = mitreTechniquesForPath(filePath)

	// Medium: exact paths
	case persistenceMediumPaths[filePath]:
		severity = "medium"
		confidence = 0.70
		mitreTechniques = []string{"T1546"}

	// Medium: basenames (e.g. .bash_logout)
	case persistenceMediumBasenames[basename]:
		severity = "medium"
		confidence = 0.70
		mitreTechniques = []string{"T1546"}

	default:
		return nil
	}

	// Read-only opens are less suspicious — reduce confidence and demote severity.
	// Writing to persistence paths is the real threat; reading may be benign inspection.
	if !isWrite {
		confidence -= 0.15
		if confidence < 0.40 {
			confidence = 0.40
		}
		if severity == "critical" {
			severity = "high"
		} else if severity == "high" {
			severity = "medium"
		}
	}

	accessVerb := "accessed"
	if isWrite {
		accessVerb = "wrote to"
	}

	title := fmt.Sprintf("AI agent %s persistence path: %s", accessVerb, basename)
	summary := fmt.Sprintf("%s %s %s", aiType, accessVerb, filePath)

	fctx := map[string]any{
		"ai_type":     aiType,
		"pid":         evt.Process.PID,
		"comm":        evt.Process.Comm,
		"file_path":   filePath,
		"is_write":    isWrite,
		"signal_type": "persistence_path",
		"pattern":     filePath,
	}
	if evt.Process.SessionID != "" {
		fctx["session_id"] = evt.Process.SessionID
	}
	if len(mitreTechniques) > 0 {
		fctx["mitre_techniques"] = mitreTechniques
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

func (d *AIPersistence) evaluateExec(ctx *detection.EvalContext, aiType string) []detection.Finding {
	evt := ctx.Event

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

	// Normalize cmdline to lowercase for subcommand checks.
	lowerCmdline := strings.ToLower(cmdline)

	switch {
	// reg.exe: only write operations are persistence — query/export are read-only.
	// Also skip when cmdline is empty (can't determine intent; ai.unauthorized_exec handles it).
	case binaryName == "reg.exe" && (cmdline == "" || isRegReadOnly(lowerCmdline)):
		return nil

	// schtasks.exe: only /create, /change, /delete are persistence — /query is read-only.
	// Skip on empty cmdline (can't determine subcommand).
	case binaryName == "schtasks.exe" && (cmdline == "" || isSchedTaskReadOnly(lowerCmdline)):
		return nil

	// sc.exe: only create/config are persistence — query/queryex are read-only.
	// Skip on empty cmdline (can't determine subcommand).
	case binaryName == "sc.exe" && (cmdline == "" || isScReadOnly(lowerCmdline)):
		return nil

	case persistenceCriticalCmds[binaryName]:
		severity = "critical"
		confidence = 0.95
		mitreTechniques = []string{"T1053"} // crontab, update-rc.d, chkconfig = scheduled task/service
		if binaryName == "crontab" {
			mitreTechniques = []string{"T1053"}
		}

	// systemctl enable/start/link is persistence; other subcommands (status, stop) are not
	case binaryName == "systemctl" && (strings.Contains(cmdline, " enable") || strings.Contains(cmdline, " start") || strings.Contains(cmdline, " link")):
		severity = "critical"
		confidence = 0.95
		mitreTechniques = []string{"T1543"}

	// loginctl enable-linger allows user systemd services to persist without login
	case binaryName == "loginctl" && strings.Contains(cmdline, "enable-linger"):
		severity = "high"
		confidence = 0.85
		mitreTechniques = []string{"T1543"}

	case persistenceHighCmds[binaryName]:
		severity = "high"
		confidence = 0.85
		mitreTechniques = []string{"T1053"} // at, batch = scheduled task/job

	default:
		return nil
	}

	baselinePattern := binaryName
	if cmdline != "" && cmdline != binaryName {
		baselinePattern = truncate(cmdline, 200)
	}

	title := fmt.Sprintf("AI agent executed persistence command: %s", binaryName)
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
		"signal_type": "persistence_cmd",
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

// mitreTechniquesForPath returns the specific MITRE ATT&CK technique IDs
// relevant to a given persistence file path.
func mitreTechniquesForPath(path string) []string {
	switch {
	// Cron = Scheduled Task/Job
	case strings.Contains(path, "cron"):
		return []string{"T1053"}
	// Sudoers = Event-Triggered Exec (abuse elevation)
	case strings.Contains(path, "sudoers"):
		return []string{"T1546"}
	// SSH = SSH Authorized Keys
	case strings.Contains(path, "/.ssh/"):
		return []string{"T1098.004"}
	// Systemd = Create System Process
	case strings.Contains(path, "systemd"):
		return []string{"T1543"}
	// PAM = Modify Authentication Process (T1556.003)
	case strings.Contains(path, "/pam.d/"):
		return []string{"T1556.003"}
	// LD_PRELOAD/ld.so = Hijack Execution Flow (T1574.006)
	case strings.Contains(path, "ld.so"):
		return []string{"T1574.006"}
	// Kernel modules
	case strings.Contains(path, "modules-load.d/") || path == "/etc/modules":
		return []string{"T1547.001"}
	// Git hooks = Event-Triggered Exec
	case strings.Contains(path, "/.git/hooks/"):
		return []string{"T1546"}
	// init.d = Create System Process
	case strings.Contains(path, "/init.d/"):
		return []string{"T1543"}
	// Autostart = Boot/Logon Autostart
	case strings.Contains(path, "autostart"):
		return []string{"T1547.001"}
	// Windows Scheduled Tasks
	case strings.Contains(path, "Tasks/") && strings.Contains(path, "System32"):
		return []string{"T1053.005"}
	// Windows Startup Folder
	case strings.Contains(path, "Startup/") || strings.Contains(path, "Start Menu"):
		return []string{"T1547.001"}
	// Windows Group Policy
	case strings.Contains(path, "GroupPolicy"):
		return []string{"T1484.001"}
	// udev rules = Event-Triggered Exec
	case strings.Contains(path, "udev/rules.d"):
		return []string{"T1546"}
	// APT hooks = Event-Triggered Exec
	case strings.Contains(path, "apt.conf.d"):
		return []string{"T1546"}
	// Shell startup files, profile.d, rc.local = Event-Triggered Exec
	default:
		return []string{"T1546"}
	}
}

// matchesAnyPrefix returns true if path starts with any of the given prefixes.
func matchesAnyPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// matchesAnyContains returns true if path contains any of the given substrings.
func matchesAnyContains(path string, subs []string) bool {
	for _, s := range subs {
		if strings.Contains(path, s) {
			return true
		}
	}
	return false
}

// isRegReadOnly returns true if the reg.exe cmdline is a read-only operation
// (query or export), not a persistence write (add, delete, copy, import, restore).
func isRegReadOnly(lowerCmdline string) bool {
	// Look for read-only subcommands: "reg query" or "reg export"
	// Check both "reg query" and "reg.exe query" since Windows cmdline includes extension.
	return strings.Contains(lowerCmdline, "reg query") ||
		strings.Contains(lowerCmdline, "reg.exe query") ||
		strings.Contains(lowerCmdline, "reg export") ||
		strings.Contains(lowerCmdline, "reg.exe export")
}

// isSchedTaskReadOnly returns true if the schtasks.exe cmdline is a read-only
// operation (/query, /showsid), not a persistence write (/create, /change, /delete).
func isSchedTaskReadOnly(lowerCmdline string) bool {
	return strings.Contains(lowerCmdline, "/query") ||
		strings.Contains(lowerCmdline, "/showsid")
}

// isScReadOnly returns true if the sc.exe cmdline is a read-only operation
// (query, queryex, sdshow), not a persistence write (create, config, delete).
func isScReadOnly(lowerCmdline string) bool {
	return strings.Contains(lowerCmdline, " query") ||
		strings.Contains(lowerCmdline, " queryex") ||
		strings.Contains(lowerCmdline, " sdshow")
}

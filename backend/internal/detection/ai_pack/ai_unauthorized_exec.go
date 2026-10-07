package ai_pack

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/correlic/correlic-backend/internal/detection"
)

// mitreTechForBinary maps suspicious binaries to their primary MITRE ATT&CK technique.
var mitreTechForBinary = map[string][]string{
	// Download tools — T1105 Ingress Tool Transfer
	"curl": {"T1105"}, "wget": {"T1105"}, "fetch": {"T1105"},
	// Reverse shell / tunnel — T1095 Non-Application Layer Protocol
	"nc": {"T1095"}, "ncat": {"T1095"}, "socat": {"T1095"},
	// SSH — T1021.004 Remote Services: SSH
	"ssh": {"T1021.004"}, "scp": {"T1021.004"}, "sftp": {"T1021.004"}, "sshpass": {"T1021.004"},
	// Network scanning — T1046 Network Service Scanning
	"nmap": {"T1046"},
	// Permission changes — T1222 File and Directory Permissions Modification
	"chmod": {"T1222"}, "chown": {"T1222"}, "chgrp": {"T1222"},
	// User manipulation — T1136 Create Account
	"useradd": {"T1136"}, "usermod": {"T1136"}, "passwd": {"T1136"},
	"visudo": {"T1136"}, "chpasswd": {"T1136"}, "adduser": {"T1136"},
	// Persistence — T1053 Scheduled Task/Job
	"crontab": {"T1053"}, "at": {"T1053"},
	// System services — T1543 Create or Modify System Process
	"systemctl": {"T1543"},
	// Encoding / staging — T1027 Obfuscated Files or Information
	"base64": {"T1027"}, "xxd": {"T1027"},
	// Archiving — T1560 Archive Collected Data
	"tar": {"T1560"}, "zip": {"T1560"},
	// Container escape — T1611 Escape to Host
	"nsenter": {"T1611"}, "unshare": {"T1611"}, "mount": {"T1611"},
	// Packet capture — T1040 Network Sniffing
	"tcpdump": {"T1040"}, "tshark": {"T1040"},
	// Firewall manipulation — T1562.004 Disable or Modify System Firewall
	"iptables": {"T1562.004"}, "ip6tables": {"T1562.004"}, "nftables": {"T1562.004"}, "nft": {"T1562.004"},
	// Crypto — T1573 Encrypted Channel
	"openssl": {"T1573"},
	// Data transfer / exfil — T1048 Exfiltration Over Alternative Protocol
	"rclone": {"T1048"}, "rsync": {"T1048"},
	// Windows LOLBins
	"certutil.exe":  {"T1140"},     // Deobfuscate/Decode Files
	"bitsadmin.exe": {"T1197"},     // BITS Jobs
	"mshta.exe":     {"T1218"},     // System Binary Proxy Execution
	"regsvr32.exe":  {"T1218"},     // System Binary Proxy Execution
	"rundll32.exe":  {"T1218"},     // System Binary Proxy Execution
	"net.exe":       {"T1136"},     // Create Account
	"net1.exe":      {"T1136"},     // Create Account
	"schtasks.exe":  {"T1053.005"}, // Scheduled Task
	"sc.exe":        {"T1543.003"}, // Windows Service
	"reg.exe":       {"T1112"},     // Modify Registry
	"wevtutil.exe":  {"T1070.001"}, // Clear Windows Event Logs
}

// suspiciousBinaries are binaries that AI agents should not typically run.
var suspiciousBinaries = map[string]bool{
	// Download tools
	"curl":  true,
	"wget":  true,
	"fetch": true,

	// Reverse shell / tunnel
	"nc":    true,
	"ncat":  true,
	"socat": true,
	"ssh":   true,
	"nmap":  true,

	// Permission changes
	"chmod": true,
	"chown": true,
	"chgrp": true,

	// User manipulation
	"useradd":  true,
	"usermod":  true,
	"passwd":   true,
	"visudo":   true,
	"chpasswd": true,
	"adduser":  true,

	// Persistence
	"crontab":   true,
	"at":        true,
	"systemctl": true,

	// Encoding / staging
	"base64": true,
	"xxd":    true,
	"tar":    true,
	"zip":    true,

	// Container escape
	"nsenter": true,
	"unshare": true,
	"mount":   true,

	// Packet capture / sniffing
	"tcpdump": true,
	"tshark":  true,

	// Firewall manipulation
	"iptables":  true,
	"ip6tables": true,
	"nftables":  true,
	"nft":       true,

	// Crypto operations
	"openssl": true,

	// Non-interactive SSH / data transfer
	"sshpass": true,
	"scp":     true,
	"sftp":    true,
	"rclone":  true, // Cloud sync — can exfiltrate to S3/GCS/etc.
	"rsync":   true,

	// Windows LOLBins — legitimate binaries used as attack tools
	"certutil.exe":  true, // Download tool / base64 decode (replaces curl/wget on old Windows)
	"bitsadmin.exe": true, // Background download tool — file transfer
	"mshta.exe":     true, // HTML Application execution — remote code execution
	"regsvr32.exe":  true, // DLL registration — Squiblydoo attack vector
	"rundll32.exe":  true, // DLL execution — sideloading
	"net.exe":       true, // User manipulation: net user add, net localgroup
	"net1.exe":      true, // Alternate net.exe (spawned by net.exe internally)
	"schtasks.exe":  true, // Persistence via Scheduled Tasks
	"sc.exe":        true, // Service manipulation
	"reg.exe":       true, // Registry manipulation
	"wevtutil.exe":  true, // Event log clearing — anti-forensics
}

// pipeToShellRe detects download-tool output piped into a shell interpreter.
// This is always suspicious regardless of source domain.
var pipeToShellRe = regexp.MustCompile(`(?i)\|\s*(bash|sh|zsh|dash|powershell|pwsh)`)

var suspiciousCmdlinePatterns = []*regexp.Regexp{
	// Shells launching inline commands with network primitives/IP literals.
	regexp.MustCompile(`(?i)(bash|sh|zsh|dash)\s+(-c|-i).*(/dev/tcp|/dev/udp|\d+\.\d+\.\d+\.\d+|nc\s|ncat\s|curl\s|wget\s)`),
	// Interpreters running inline code with network operations.
	regexp.MustCompile(`(?i)(python3?|node|ruby|perl)\s+(-c|-e)\s+.*(socket|http\.request|net\.connect|urllib|requests\.(get|post)|fetch\()`),
	// Classic interactive shell indicators.
	regexp.MustCompile(`(?i)(bash|sh)\s+-i`),
	// Pipe-to-shell: curl/wget output piped to bash/sh — classic remote code execution.
	regexp.MustCompile(`(?i)(curl|wget)\s+.*\|\s*(bash|sh|zsh|dash)`),
	// Windows: PowerShell downloading patterns.
	regexp.MustCompile(`(?i)powershell.*(?:Invoke-WebRequest|IWR|Invoke-RestMethod|IRM|DownloadString|DownloadFile|Start-BitsTransfer)`),
	// Windows: PowerShell encoded commands — often used to obfuscate malicious payloads.
	regexp.MustCompile(`(?i)powershell.*-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}`),
	// Windows: certutil used for downloading or decoding.
	regexp.MustCompile(`(?i)certutil.*(?:-urlcache|-decode|-decodehex)`),
}

// AIUnauthorizedExec detects when an AI agent runs suspicious binaries.
type AIUnauthorizedExec struct{}

func (d *AIUnauthorizedExec) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.unauthorized_exec",
		Pack:            "ai",
		Name:            "AI Unauthorized Execution",
		Severity:        "high",
		Description:     "AI agent process executed a suspicious or potentially dangerous binary",
		Tags:            []string{"ai", "exec", "unauthorized"},
		MITRETechniques: []string{"T1059", "T1059.004"},
	}
}

func (d *AIUnauthorizedExec) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"process_exec"},
		WindowSecs: 0,
	}
}

func (d *AIUnauthorizedExec) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt.Process == nil {
		return nil
	}

	// Check if the process belongs to an AI agent tree
	isAI, aiType, err := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if err != nil || !isAI {
		return nil
	}

	// Get the binary name
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

	isSuspiciousBinary := suspiciousBinaries[binaryName]
	matchType := "binary"
	matchedPattern := ""
	if !isSuspiciousBinary {
		pat := matchSuspiciousCmdlinePattern(cmdline)
		if pat == "" {
			return nil
		}
		matchType = "cmdline_pattern"
		matchedPattern = pat
	}

	// For download tools (curl, wget, fetch), suppress if the target is a known safe domain.
	// AI agents legitimately call APIs at openai.com, anthropic.com, etc.
	// But NEVER suppress pipe-to-shell patterns — those are always suspicious.
	if isSuspiciousBinary && isDownloadTool(binaryName) {
		if pipeToShellRe.MatchString(cmdline) {
			// Always suspicious — fall through to generate finding
		} else if ctx.SafeDomainChecker != nil {
			domain := extractURLDomain(cmdline)
			if domain != "" && ctx.SafeDomainChecker.IsSafe(domain) {
				return nil
			}
		}
	}

	// For SSH, suppress git-over-SSH to well-known hosting providers.
	// AI agents (Claude Code, Cursor, etc.) legitimately run git push/fetch/clone
	// which spawns ssh with e.g. "git@github.com". Without this suppression the
	// ssh binary hit + the port-22 connection triggers chain.reverse_shell_setup.
	if isSuspiciousBinary && binaryName == "ssh" && isGitSSH(cmdline) {
		return nil
	}

	// For reg.exe, distinguish read-only queries from actual modifications.
	// "reg query" is T1012 (Query Registry — discovery), not T1112 (Modify Registry).
	// Only "reg add", "reg delete", "reg import" are actual modifications.
	if isSuspiciousBinary && (binaryName == "reg.exe" || binaryName == "reg") {
		lowerCmd := strings.ToLower(cmdline)
		if strings.Contains(lowerCmd, " query ") || strings.HasSuffix(lowerCmd, " query") {
			// Read-only registry query — downgrade to low severity, correct MITRE to T1012
			return []detection.Finding{
				{
					Title:      fmt.Sprintf("AI agent queried registry: %s", binaryName),
					Summary:    fmt.Sprintf("%s ran: %s", aiType, truncate(cmdline, 200)),
					Severity:   "low",
					Confidence: 0.30,
					Context: map[string]any{
						"ai_type":          aiType,
						"binary":           binaryName,
						"cmdline":          cmdline,
						"match_type":       "registry_query",
						"signal_type":      "command",
						"pattern":          truncate(cmdline, 200),
						"mitre_techniques": []string{"T1012"},
					},
				},
			}
		}
		// reg add/delete/import — keep HIGH severity with T1112
	}

	confidence := 0.85 // binary blocklist match
	if matchType == "cmdline_pattern" {
		confidence = 0.70
	}

	title := fmt.Sprintf("AI agent executed suspicious binary: %s", binaryName)
	summary := fmt.Sprintf("%s ran %s", aiType, binaryName)
	if cmdline != "" && cmdline != binaryName {
		summary = fmt.Sprintf("%s ran: %s", aiType, truncate(cmdline, 200))
	}
	if matchType == "cmdline_pattern" {
		title = "AI agent executed suspicious inline command"
		summary = fmt.Sprintf("%s ran %s with suspicious inline execution", aiType, binaryName)
		if cmdline != "" {
			summary = fmt.Sprintf("%s ran: %s", aiType, truncate(cmdline, 200))
		}
	}

	// Use full cmdline as pattern so baselines are specific to the exact command,
	// not a blanket allow for the binary. "Allow Always" on `ssh user@host` should
	// not suppress `ssh attacker@evil.com`.
	baselinePattern := binaryName
	if cmdline != "" && cmdline != binaryName {
		baselinePattern = truncate(cmdline, 200)
	}

	fctx := map[string]any{
		"ai_type":         aiType,
		"binary":          binaryName,
		"cmdline":         cmdline,
		"pid":             evt.Process.PID,
		"ppid":            evt.Process.PPID,
		"signal_type":     "binary",
		"pattern":         baselinePattern,
		"match_type":      matchType,
		"matched_pattern": matchedPattern,
	}
	if evt.Process.SessionID != "" {
		fctx["session_id"] = evt.Process.SessionID
	}
	if cmdline == "" {
		fctx["low_context"] = true
	}

	// Per-finding MITRE technique based on what was actually detected.
	if mitre, ok := mitreTechForBinary[binaryName]; ok {
		// Pipe-to-shell with download tool is T1059.004 (Unix Shell), not just T1105
		if isDownloadTool(binaryName) && pipeToShellRe.MatchString(cmdline) {
			fctx["mitre_techniques"] = []string{"T1059.004", "T1105"}
		} else {
			fctx["mitre_techniques"] = mitre
		}
	} else if matchType == "cmdline_pattern" {
		// Cmdline pattern matches — determine technique from the pattern
		if strings.Contains(matchedPattern, "powershell") || strings.Contains(matchedPattern, "Invoke-") {
			fctx["mitre_techniques"] = []string{"T1059.001"}
		} else if strings.Contains(matchedPattern, "certutil") {
			fctx["mitre_techniques"] = []string{"T1140"}
		} else {
			fctx["mitre_techniques"] = []string{"T1059.004"}
		}
	}

	return []detection.Finding{
		{
			Title:      title,
			Summary:    summary,
			Confidence: confidence,
			Context:    fctx,
		},
	}
}

func isDownloadTool(binary string) bool {
	switch binary {
	case "curl", "wget", "fetch":
		return true
	}
	return false
}

// knownGitSSHHosts are well-known git hosting providers whose SSH endpoints
// are legitimately reached by AI agents running git operations.
var knownGitSSHHosts = []string{
	"github.com",
	"gitlab.com",
	"bitbucket.org",
	"codeberg.org",
	"sr.ht",
}

// isGitSSH returns true if the SSH command line looks like an automated
// git-over-SSH invocation to a known hosting provider. It matches two
// complementary signals:
//
//  1. The destination is "git@<known-host>" — the standard git SSH user.
//  2. BatchMode=yes combined with any "git@" destination — indicates a
//     non-interactive, program-driven SSH call (git sets this flag).
//
// Either signal alone is sufficient; together they cover both named and
// self-hosted forges behind a git@ user with BatchMode.
func isGitSSH(cmdline string) bool {
	if cmdline == "" {
		return false
	}

	// Signal 1: git@<known-host> anywhere in the cmdline.
	for _, host := range knownGitSSHHosts {
		if strings.Contains(cmdline, "git@"+host) {
			return true
		}
	}

	// Signal 2: BatchMode=yes + git@ — automated git SSH to any host.
	if strings.Contains(cmdline, "BatchMode=yes") && strings.Contains(cmdline, "git@") {
		return true
	}

	return false
}

func extractURLDomain(cmdline string) string {
	// First try explicit URL schemes.
	for _, prefix := range []string{"https://", "http://"} {
		idx := strings.Index(cmdline, prefix)
		if idx < 0 {
			continue
		}
		rest := cmdline[idx+len(prefix):]
		end := len(rest)
		for i, c := range rest {
			if c == '/' || c == ' ' || c == '\'' || c == '"' || c == ':' || c == '?' || c == '#' {
				end = i
				break
			}
		}
		if end > 0 {
			return rest[:end]
		}
	}

	// Fallback: look for bare domain tokens (e.g. "curl api.github.com/repos/foo").
	// Split on whitespace, skip flags (starting with -), find first domain-like token.
	for _, token := range strings.Fields(cmdline) {
		if strings.HasPrefix(token, "-") {
			continue
		}
		// Strip quotes
		token = strings.Trim(token, "'\"")
		// Strip path suffix: "api.openai.com/v1/chat" → "api.openai.com"
		host := token
		if slashIdx := strings.Index(host, "/"); slashIdx > 0 {
			host = host[:slashIdx]
		}
		// Must look like a domain: contains a dot, no special chars
		if strings.Contains(host, ".") && !strings.ContainsAny(host, "=@#$%&|\\") {
			return host
		}
	}
	return ""
}

func matchSuspiciousCmdlinePattern(cmdline string) string {
	if cmdline == "" {
		return ""
	}
	for _, re := range suspiciousCmdlinePatterns {
		if re.MatchString(cmdline) {
			return re.String()
		}
	}
	return ""
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}

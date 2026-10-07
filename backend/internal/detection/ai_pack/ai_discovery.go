package ai_pack

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/event"
)

const discoveryWindow = 60 * time.Second
const discoveryThreshold = 3 // need at least 3 recon commands in the window

// discoveryBinaries are commands used for system/network reconnaissance.
// Individually low-severity, but a burst indicates pre-attack enumeration.
var discoveryBinaries = map[string]bool{
	// System info
	"whoami":      true,
	"id":          true,
	"hostname":    true,
	"uname":       true,
	"hostnamectl": true,

	// Environment enumeration
	"env":      true,
	"printenv": true,

	// Network reconnaissance
	"ifconfig":   true,
	"ip":         true,
	"ss":         true,
	"netstat":    true,
	"arp":        true,
	"route":      true,
	"traceroute": true,
	"dig":        true,
	"nslookup":   true,
	"host":       true,

	// Process enumeration
	"ps":     true,
	"pstree": true,
	"top":    true,
	"lsof":   true,

	// File/disk enumeration
	"df":    true,
	"lsblk": true,
	"fdisk": true,
	"blkid": true,

	// User enumeration
	"w":      true,
	"who":    true,
	"last":   true,
	"finger": true,
	"getent": true,

	// System capability enumeration
	"getcap": true,
	"find":   true, // only counted, not standalone trigger
	"cat":    true, // only counted, not standalone trigger
	"ls":     true, // only counted, not standalone trigger

	// Windows system enumeration equivalents
	"ipconfig.exe":   true,
	"systeminfo.exe": true,
	"tasklist.exe":   true,
	"net.exe":        true, // net user, net localgroup, net share
	"wmic.exe":       true,
	"query.exe":      true, // query user, query session
	"quser.exe":      true,
	"qwinsta.exe":    true,
	"nltest.exe":     true, // Domain trust enumeration
	"dsquery.exe":    true, // Active Directory query
	"cmdkey.exe":     true, // Credential enumeration
	"netstat.exe":    true,
	"whoami.exe":     true,
	"hostname.exe":   true,
}

// discoveryHighValueBinaries always fire when run by AI, even standalone.
var discoveryHighValueBinaries = map[string]bool{
	"nmap":       true, // Network scanner — always suspicious for AI
	"masscan":    true, // Fast port scanner
	"zmap":       true, // Internet-wide scanner
	"nikto":      true, // Web vulnerability scanner
	"gobuster":   true, // Directory brute-forcer
	"dirb":       true, // Directory scanner
	"enum4linux": true, // SMB enumeration
	"linpeas":    true, // Linux privilege escalation scanner
	"pspy":       true, // Process spy without root
}

// discoveryTargetFiles are files commonly read during reconnaissance.
// Only fire within a burst of other discovery activity (not standalone).
var discoveryTargetFiles = map[string]bool{
	"/etc/hosts":       true,
	"/etc/resolv.conf": true,
	"/etc/os-release":  true,
	"/etc/issue":       true,
	"/etc/hostname":    true,
	"/etc/fstab":       true,
	"/etc/mtab":        true,
	"/etc/group":       true,
	// Windows hosts file (path normalized to forward slashes)
	"C:/Windows/System32/drivers/etc/hosts": true,
}

// AIDiscovery detects AI agent reconnaissance — system enumeration and
// pre-attack information gathering.
type AIDiscovery struct{}

func (d *AIDiscovery) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.discovery",
		Pack:            "ai",
		Name:            "AI Reconnaissance",
		Severity:        "low",
		Description:     "AI agent performed system/network reconnaissance commands — possible pre-attack enumeration",
		Tags:            []string{"ai", "discovery", "reconnaissance", "enumeration"},
		MITRETechniques: []string{"T1082", "T1083", "T1057", "T1016", "T1049", "T1033"},
	}
}

func (d *AIDiscovery) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"process_exec"},
		WindowSecs: int(discoveryWindow.Seconds()),
	}
}

func (d *AIDiscovery) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt.Process == nil {
		return nil
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

	// High-value recon tools fire immediately — always suspicious from AI
	if discoveryHighValueBinaries[binaryName] {
		cmdline := ""
		if len(evt.Process.Cmdline) > 0 {
			cmdline = strings.Join(evt.Process.Cmdline, " ")
		}

		baselinePattern := binaryName
		if cmdline != "" && cmdline != binaryName {
			baselinePattern = truncate(cmdline, 200)
		}

		fctx := map[string]any{
			"ai_type":     aiType,
			"binary":      binaryName,
			"cmdline":     cmdline,
			"pid":         evt.Process.PID,
			"ppid":        evt.Process.PPID,
			"recon_type":  "active_scanner",
			"signal_type": "discovery_cmd",
			"pattern":     baselinePattern,
		}
		if evt.Process.SessionID != "" {
			fctx["session_id"] = evt.Process.SessionID
		}
		if cmdline == "" {
			fctx["low_context"] = true
		}

		// Per-finding MITRE based on scanner type.
		switch binaryName {
		case "nmap", "masscan", "zmap":
			fctx["mitre_techniques"] = []string{"T1046"} // Network Service Scanning
		case "nikto", "gobuster", "dirb":
			fctx["mitre_techniques"] = []string{"T1595.002"} // Vulnerability Scanning
		case "enum4linux":
			fctx["mitre_techniques"] = []string{"T1087"} // Account Discovery
		case "linpeas":
			fctx["mitre_techniques"] = []string{"T1082"} // System Information Discovery
		case "pspy":
			fctx["mitre_techniques"] = []string{"T1057"} // Process Discovery
		}

		return []detection.Finding{
			{
				Title:      fmt.Sprintf("AI agent ran active scanner: %s", binaryName),
				Summary:    fmt.Sprintf("%s executed %s — active reconnaissance tool", aiType, binaryName),
				Severity:   "high",
				Confidence: 0.85,
				Context:    fctx,
			},
		}
	}

	// For common discovery commands, only fire if there's a burst
	if !discoveryBinaries[binaryName] {
		return nil
	}

	// Look back for other discovery commands in the window.
	// Use session-based lookback when available — on Windows each command spawns
	// a new PID, so PID-scoped lookback only ever sees 1 command.
	// Check ai_session_id from context first (set by agent for AI processes),
	// then fall back to Process.SessionID, then PID-scoped.
	since := evt.Timestamp.Add(-discoveryWindow)
	var recentExecs []event.Event

	sessionID := evt.Process.SessionID
	if evt.Context != nil {
		if aiSID, ok := evt.Context["ai_session_id"].(string); ok && aiSID != "" {
			sessionID = aiSID
		}
	}

	if sessionID != "" && sessionID != "0" {
		recentExecs, err = ctx.GraphQuery.GetRecentEventsBySession(
			ctx.Ctx, ctx.HostID, sessionID, since, []string{"process_exec"},
		)
	} else {
		recentExecs, err = ctx.GraphQuery.GetRecentEvents(
			ctx.Ctx, ctx.HostID, evt.Process.PID, since, []string{"process_exec"},
		)
	}
	if err != nil {
		return nil
	}

	// Count distinct discovery binaries in the window
	discoveryCommands := make(map[string]bool)
	discoveryCommands[binaryName] = true // Include current event

	for _, re := range recentExecs {
		if re.Process == nil {
			continue
		}
		reComm := re.Process.Comm
		if re.Process.ExePath != "" {
			reComm = filepath.Base(re.Process.ExePath)
		}
		if discoveryBinaries[reComm] {
			discoveryCommands[reComm] = true
		}
	}

	if len(discoveryCommands) < discoveryThreshold {
		return nil
	}

	// Collect which commands were run
	cmds := make([]string, 0, len(discoveryCommands))
	for cmd := range discoveryCommands {
		cmds = append(cmds, cmd)
	}

	severity := "low"
	confidence := 0.55
	if len(discoveryCommands) >= 5 {
		severity = "medium"
		confidence = 0.70
	}
	if len(discoveryCommands) >= 8 {
		severity = "high"
		confidence = 0.80
	}

	var relatedIDs []string
	for _, re := range recentExecs {
		relatedIDs = append(relatedIDs, re.ID)
	}

	fctx := map[string]any{
		"ai_type":            aiType,
		"pid":                evt.Process.PID,
		"discovery_commands": cmds,
		"command_count":      len(discoveryCommands),
		"window_secs":        int(discoveryWindow.Seconds()),
		"signal_type":        "discovery_burst",
		"pattern":            fmt.Sprintf("pid:%d:discovery:%d", evt.Process.PID, len(discoveryCommands)),
	}
	if evt.Process.SessionID != "" {
		fctx["session_id"] = evt.Process.SessionID
	}

	return []detection.Finding{
		{
			Title:         fmt.Sprintf("AI agent ran %d reconnaissance commands in %v", len(discoveryCommands), discoveryWindow),
			Summary:       fmt.Sprintf("%s executed %d distinct discovery commands within %v: %s", aiType, len(discoveryCommands), discoveryWindow, strings.Join(cmds, ", ")),
			Severity:      severity,
			Confidence:    confidence,
			RelatedEvents: relatedIDs,
			Context:       fctx,
		},
	}
}

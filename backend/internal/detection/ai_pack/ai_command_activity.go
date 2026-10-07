package ai_pack

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/correlic/correlic-backend/internal/detection"
)

// AlwaysNoise, BareNoise, etc. are processes that are internal runtime artifacts regardless
// of arguments — they fire constantly and add no investigative value.
// aiRootBinaries are the AI agent binaries themselves — their startup is not
// a "command" worth tracking. We track their CHILDREN, not the agent itself.
var aiRootBinaries = map[string]bool{
	"cursor":     true,
	"cursor.exe": true,
	"claude":     true,
	"claude.exe": true,
	"code":       true, // VSCode
	"code.exe":   true,
}

// SystemStartupNoise are Windows system processes spawned automatically by
// Windows when console apps run. They provide no security insight.
// Exported so the noise-filters API can return them.
var SystemStartupNoise = map[string]bool{
	"conhost":       true, // Console Host — spawned for every console app
	"conhost.exe":   true,
	"wsl":           true, // WSL launcher
	"wsl.exe":       true,
	"wslhost":       true, // WSL host process
	"wslhost.exe":   true,
	"csrss":         true, // Client/Server Runtime Subsystem
	"csrss.exe":     true,
	"sihost":        true, // Shell Infrastructure Host
	"sihost.exe":    true,
	"fontdrvhost":   true, // Font Driver Host
	"fontdrvhost.exe": true,
	"dllhost":       true, // COM Surrogate
	"dllhost.exe":   true,
	"WerFault":      true, // Windows Error Reporting
	"WerFault.exe":  true,
	"consent":       true, // UAC consent prompt
	"consent.exe":   true,
	"RuntimeBroker": true, // Runtime Broker
	"RuntimeBroker.exe": true,
	"backgroundTaskHost":     true, // Background Task Host
	"backgroundTaskHost.exe": true,
	"SearchProtocolHost":     true, // Windows Search
	"SearchProtocolHost.exe": true,
	"SecurityHealthSystray":     true, // Windows Security tray
	"SecurityHealthSystray.exe": true,
}

// BuildToolNoise are compiler/linker internals spawned during builds.
// Exported so the noise-filters API can return them.
var BuildToolNoise = map[string]bool{
	"link":    true, // Go linker
	"asm":     true, // Go assembler
	"compile": true, // Go compiler
	"cc1":     true, // GCC compiler
	"as":      true, // GNU assembler
	"ld":      true, // GNU linker
	"cc":      true, // C compiler
}

// AlwaysNoise are runtime artifacts that are always noise regardless of arguments.
// Exported so the noise-filters API can return them.
var AlwaysNoise = map[string]bool{
	"libuv-worker": true,
	"ldconfig":     true,
	"locale":       true,
	"dircolors":    true,
	"lesspipe":     true,
	"basename":     true,
	"dirname":      true,
	"tput":         true,
	"stty":         true,
}

// BareNoise are runtime binaries that are noise ONLY when invoked without arguments.
// "node" alone = internal worker (noise), "node /app/scripts/foo.js" = real command (track it).
// "reg" alone = noise, "reg query HKLM\..." = LOLBin, ALWAYS tracked.
// Exported so the noise-filters API can return them.
var BareNoise = map[string]bool{
	"node":       true,
	"python":     true,
	"python3":    true,
	"sh":         true,
	"bash":       true,
	"zsh":        true,
	"cmd":        true,
	"powershell": true,
	"pwsh":       true,
	"psql":       true,
	"ruby":       true,
	"perl":       true,
	"reg":        true, // registry query — noise without args, interesting with args
	"git":        true, // git without args = internal check, git clone/push = real command
}

// electronSubprocessArgs are Electron/Chromium internal subprocess arguments.
// AI agents built on Electron (Cursor, VSCode) spawn many internal processes
// (renderer, gpu, crashpad, utility) that are not user commands.
var electronSubprocessArgs = []string{
	"--type=renderer",
	"--type=gpu-process",
	"--type=crashpad-handler",
	"--type=utility",
	"--type=zygote",
	"--type=broker",
}

// AICommandActivity is a catch-all rule that tracks every command/binary executed
// by an AI agent. It fires at low severity for visibility — users suppress noise
// via "Allow Always" baselines while keeping full audit trail of AI behavior.
//
// Dual-baseline support: findings carry both a command pattern and file_path.
// Users can "Allow File", "Allow Command", or "Allow Both" from the UI.
// Suppression: MatchesBaseline checks signal_type=command (for the cmdline) AND
// signal_type=command_file (for the file path). If either matches, finding is suppressed.
type AICommandActivity struct{}

func (d *AICommandActivity) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:          "ai.command_activity",
		Pack:        "ai",
		Name:        "AI Command Activity",
		Severity:    "low",
		Description: "AI agent executed a command — tracked for audit visibility until baselined",
		Tags:            []string{"ai", "audit", "command", "activity"},
		MITRETechniques: []string{"T1059"},
	}
}

func (d *AICommandActivity) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"process_exec"},
		WindowSecs: 0,
	}
}

func (d *AICommandActivity) Evaluate(ctx *detection.EvalContext) []detection.Finding {
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
	// Normalize: strip .exe suffix for consistent matching against noise maps.
	// Windows binaries come as "bash.exe" but noise maps use "bash".
	binaryNameNoExt := strings.TrimSuffix(strings.ToLower(binaryName), ".exe")

	cmdline := ""
	if len(evt.Process.Cmdline) > 0 {
		cmdline = strings.Join(evt.Process.Cmdline, " ")
	}

	// Extract the actual user command from shell wrappers.
	// AI agents (Claude Code, Cursor) wrap commands in bash:
	//   bash -c "source .claude/shell-snapshots/... && eval 'curl -sk https://...'"
	// The useful part is inside eval '...' — extract it for display.
	displayCmd := extractInnerCommand(cmdline)
	if displayCmd == "" {
		displayCmd = cmdline
	}

	// Skip Electron/Chromium internal subprocesses (renderer, gpu, crashpad, etc.)
	// These are spawned by AI agents like Cursor/VSCode but are not user commands.
	for _, arg := range electronSubprocessArgs {
		if strings.Contains(cmdline, arg) {
			return nil
		}
	}

	// Skip AI agent root binaries — we track their children, not the agent itself.
	if aiRootBinaries[binaryNameNoExt] {
		return nil
	}
	// Skip system startup noise (conhost, wsl, wslhost) — no security value
	// without arguments, and cmdline is usually empty (process exited too fast).
	if SystemStartupNoise[binaryNameNoExt] {
		return nil
	}

	// Skip build tool internals (link.exe, asm.exe, compile.exe, etc.)
	if BuildToolNoise[binaryNameNoExt] {
		return nil
	}

	// Skip runtime noise — internal process artifacts with no investigative value.
	if AlwaysNoise[binaryNameNoExt] {
		return nil
	}
	// Bare runtimes without arguments are internal workers (e.g. "node" fork).
	// But "node /app/scripts/foo.js" or "python -m openclaw" are real commands — track them.
	// Bare runtimes: suppress if cmdline is empty, just the binary name, or just
	// the full exe path (e.g. "C:/Program Files/Git/bin/bash.exe" with no args).
	if BareNoise[binaryNameNoExt] {
		if cmdline == "" || cmdline == binaryName || cmdline == binaryNameNoExt {
			return nil
		}
		// cmdline is just the full exe path with no additional arguments
		cmdParts := strings.Fields(cmdline)
		if len(cmdParts) <= 1 {
			return nil
		}
	}

	// Build the command baseline pattern from the display command (not the full bash wrapper).
	// "bash -c source ... && eval 'curl -sk https://example.com'" → "curl -sk https://example.com"
	commandPattern := binaryName
	if displayCmd != "" && displayCmd != binaryName {
		commandPattern = truncate(displayCmd, 200)
	} else if cmdline != "" && cmdline != binaryName {
		commandPattern = truncate(cmdline, 200)
	}

	// Extract file path from cmdline args for dual-baseline support.
	// "node /app/scripts/foo.js" → "/app/scripts/foo.js"
	filePath := extractFilePath(evt.Process.Cmdline)

	// Use extracted inner command for title/summary (clean display).
	// Store full cmdline in context for forensic detail.
	displayBinary := binaryName
	if displayCmd != cmdline && displayCmd != "" {
		// Inner command extracted — use its binary name for the title.
		// Skip leading env var assignments (KEY=VALUE) to find the actual binary.
		// e.g. "PGPASSWORD=correlic psql -h localhost" → binary is "psql", not "PGPASSWORD=correlic"
		parts := strings.Fields(displayCmd)
		for _, p := range parts {
			if !strings.Contains(p, "=") || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "C:") {
				displayBinary = filepath.Base(p)
				break
			}
		}
	}

	title := fmt.Sprintf("AI agent ran: %s", displayBinary)
	summary := fmt.Sprintf("%s executed %s", aiType, displayBinary)
	if displayCmd != "" && displayCmd != binaryName {
		summary = fmt.Sprintf("%s ran: %s", aiType, truncate(displayCmd, 120))
	}

	fctx := map[string]any{
		"ai_type":     aiType,
		"binary":      displayBinary,
		"cmdline":     cmdline,
		"display_cmd": displayCmd,
		"pid":         evt.Process.PID,
		"ppid":        evt.Process.PPID,
		"signal_type": "command",
		"pattern":     commandPattern,
	}
	if filePath != "" {
		fctx["file_path"] = filePath
	}
	if evt.Process.SessionID != "" {
		fctx["session_id"] = evt.Process.SessionID
	}
	// Flag findings where cmdline capture failed (process exited too fast).
	// LOLBins (reg.exe, schtasks.exe, etc.) without args need manual investigation.
	if cmdline == "" {
		fctx["low_context"] = true
	}

	findings := []detection.Finding{
		{
			Title:      title,
			Summary:    summary,
			Severity:   "low",
			Confidence: 0.30,
			Context:    fctx,
		},
	}

	// When an interpreter runs a script file (e.g. "node /app/foo.js"), also emit
	// a file_activity finding for the script. process_exec events don't generate
	// file_open events for interpreted scripts, so ai.file_activity would miss them.
	// Only emit for actual script interpreters — not for tools that read files
	// (cat, grep, sed, head, etc.) which are already covered by ai.file_activity
	// via file_open events.
	if filePath != "" && isScriptInterpreter(binaryName) {
		fileName := filepath.Base(filePath)
		dirPath := filepath.ToSlash(filepath.Dir(filePath))
		fileFctx := map[string]any{
			"ai_type":     aiType,
			"file_path":   filePath,
			"file_name":   fileName,
			"dir_path":    dirPath,
			"pid":         evt.Process.PID,
			"ppid":        evt.Process.PPID,
			"comm":        binaryName,
			"signal_type": "file_activity",
			"pattern":     filePath,
		}
		if evt.Process.SessionID != "" {
			fileFctx["session_id"] = evt.Process.SessionID
		}
		findings = append(findings, detection.Finding{
			Title:      fmt.Sprintf("AI agent accessed: %s", fileName),
			Summary:    fmt.Sprintf("%s accessed %s via %s", aiType, filePath, binaryName),
			Severity:   "low",
			Confidence: 0.25,
			Context:    fileFctx,
		})
	}

	return findings
}

// isScriptInterpreter returns true if the binary is a script interpreter/runtime
// that actually executes the file argument. Tools that just read files (cat, grep,
// sed, etc.) are NOT interpreters — their file access is tracked via file_open events.
var scriptInterpreters = map[string]bool{
	"node": true, "nodejs": true, "npx": true, "tsx": true, "ts-node": true,
	"python": true, "python3": true, "python2": true,
	"ruby": true, "perl": true, "php": true,
	"bash": true, "sh": true, "zsh": true, "dash": true, "fish": true,
	"lua": true, "luajit": true,
	"java": true, "javac": true, "kotlin": true, "kotlinc": true,
	"go": true, "deno": true, "bun": true,
	"Rscript": true, "julia": true,
	// Windows shells/interpreters
	"powershell": true, "pwsh": true, "cmd": true,
	"cscript": true, "wscript": true, "mshta": true,
}

func isScriptInterpreter(binary string) bool {
	return scriptInterpreters[binary]
}

// extractInnerCommand strips shell wrapper boilerplate from AI agent commands.
// AI agents (Claude Code, Cursor, Aider) wrap commands in bash:
//
//	bash -c "source .claude/shell-snapshots/... && shopt -u extglob ... && eval 'curl -sk https://...'"
//
// This extracts the inner command from eval '...' for clean display.
// Returns empty string if no wrapper pattern is found.
func extractInnerCommand(cmdline string) string {
	// Pattern 1: eval 'actual_command' or eval "actual_command"
	// The eval content may itself contain "cd /path && real_command",
	// so we extract the eval content first, then strip cd prefixes.
	for _, prefix := range []string{"eval '", `eval "`} {
		idx := strings.Index(cmdline, prefix)
		if idx < 0 {
			continue
		}
		rest := cmdline[idx+len(prefix):]
		closeChar := byte('\'')
		if prefix == `eval "` {
			closeChar = '"'
		}
		endIdx := strings.IndexByte(rest, closeChar)
		var evalContent string
		if endIdx > 0 {
			evalContent = rest[:endIdx]
		} else {
			evalContent = strings.TrimRight(rest, "' \"\n\r")
		}
		// Strip "cd /path && " prefix from eval content
		return stripCdPrefix(evalContent)
	}

	// Pattern 2: bash -c "source ... && shopt ... && actual_command"
	// Take everything after the last && that isn't shell setup.
	if strings.Contains(cmdline, " -c ") && strings.Contains(cmdline, "&&") {
		parts := strings.Split(cmdline, "&&")
		// Walk backwards to find the first non-boilerplate part
		for i := len(parts) - 1; i >= 0; i-- {
			part := strings.TrimSpace(parts[i])
			part = strings.TrimRight(part, "' \"\n\r")
			if len(part) > 3 && !isShellBoilerplate(part) {
				return stripCdPrefix(part)
			}
		}
	}

	return ""
}

// stripCdPrefix removes "cd /some/path && " from the beginning of a command.
func stripCdPrefix(cmd string) string {
	if !strings.HasPrefix(cmd, "cd ") {
		return cmd
	}
	// "cd /path && actual_command" → "actual_command"
	idx := strings.Index(cmd, "&&")
	if idx < 0 {
		return cmd // just "cd /path" with no follow-up
	}
	return strings.TrimSpace(cmd[idx+2:])
}

// isShellBoilerplate returns true for shell setup commands that should be skipped.
func isShellBoilerplate(part string) bool {
	boilerplate := []string{"source ", "shopt ", "true", "export ", "eval "}
	for _, b := range boilerplate {
		if strings.HasPrefix(part, b) {
			return true
		}
	}
	return false
}

// extractFilePath finds the first file-path-like argument from cmdline args.
// Rejects arguments that are clearly command lines (contain shell operators).
func extractFilePath(cmdlineArgs []string) string {
	if len(cmdlineArgs) < 2 {
		return ""
	}
	for _, arg := range cmdlineArgs[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// Reject command-line strings that were passed as a single argument
		// (e.g. bash -c "source /path && shopt && eval '...'").
		if strings.Contains(arg, " && ") || strings.Contains(arg, " || ") ||
			strings.Contains(arg, " | ") || strings.Contains(arg, "eval '") ||
			strings.Contains(arg, "shopt ") {
			continue
		}
		// Reject unreasonably long args — file paths are under 4096 chars.
		if len(arg) > 4096 {
			continue
		}
		if (strings.HasPrefix(arg, "/") || strings.Contains(arg, "/")) &&
			strings.Contains(filepath.Base(arg), ".") {
			return arg
		}
	}
	return ""
}

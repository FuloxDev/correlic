// Package classify provides platform-agnostic process classification.
package classify

// CheckRole classifies the process as "agent", "shell", "tool", or "unknown".
// The comm value is expected to be lowercase with .exe stripped (e.g. "powershell" not "powershell.exe").
func CheckRole(comm string) string {
	// Known shells (Unix + Windows)
	shells := []string{
		"bash", "zsh", "sh", "dash", "fish", "csh", "tcsh", "ash",
		"powershell", "pwsh", "cmd",
	}
	for _, s := range shells {
		if comm == s {
			return "shell"
		}
	}

	// Known tools (Unix + Windows)
	tools := []string{
		// Unix
		"ls", "cat", "grep", "find", "git", "curl", "wget", "rm", "cp", "mv",
		"mkdir", "touch", "chmod", "chown", "ps", "top", "sed", "awk", "cut",
		"head", "tail", "wc", "sort", "uniq", "tar", "gzip", "zip", "unzip",
		"python", "python3", "node", "go", "cargo", "docker", "kubectl",
		// Windows
		"tasklist", "taskkill", "net", "ipconfig", "wmic", "systeminfo",
		"type", "findstr", "xcopy", "robocopy", "certutil",
		"reg", "sc", "netsh", "schtasks", "icacls", "attrib",
		"where", "whoami", "nslookup", "ping", "tracert", "netstat",
	}
	for _, t := range tools {
		if comm == t {
			return "tool"
		}
	}

	// Default to agent if it's not a shell or obvious tool, assuming it was caught by AI lineage
	return "agent"
}

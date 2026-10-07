//go:build linux

package procmon

import (
	"path/filepath"
	"strings"
)

func approvalKindFromProc(info ProcInfo) (string, map[string]any, bool) {
	if kind, subject, ok := gitApprovalFromProc(info); ok {
		return kind, subject, true
	}
	if kind, subject, ok := execApprovalFromProc(info); ok {
		return kind, subject, true
	}
	return "", nil, false
}

func gitApprovalFromProc(info ProcInfo) (string, map[string]any, bool) {
	argv := info.Argv
	if len(argv) == 0 {
		return "", nil, false
	}
	argv0 := strings.ToLower(argv[0])
	comm := strings.ToLower(info.Comm)
	joined := strings.ToLower(strings.Join(argv, " "))
	base0 := strings.ToLower(filepath.Base(argv0))

	isGit := base0 == "git" || comm == "git" || strings.HasPrefix(joined, "git ")
	if !isGit {
		return "", nil, false
	}

	sub := ""
	if base0 == "git" && len(argv) >= 2 {
		sub = strings.ToLower(argv[1])
	} else {
		for i := 0; i < len(argv)-1; i++ {
			if strings.ToLower(filepath.Base(argv[i])) == "git" {
				sub = strings.ToLower(argv[i+1])
				break
			}
		}
	}
	if sub == "" {
		return "", nil, false
	}

	switch sub {
	case "clone":
		remoteURL, repoPath, branch := parseGitCloneArgs(argv)
		if remoteURL == "" {
			return "", nil, false
		}
		return "git_clone", map[string]any{
			"remote_url": remoteURL,
			"repo_path":  repoPath,
			"branch":     branch,
		}, true
	case "pull":
		return "git_pull", map[string]any{
			"argv": argv,
		}, true
	case "remote":
		op, remoteURL := parseGitRemoteArgs(argv)
		if op == "" {
			return "", nil, false
		}
		kind := ""
		switch op {
		case "remote_add":
			kind = "git_remote_add"
		case "remote_set_url":
			kind = "git_remote_set_url"
		}
		if kind == "" {
			return "", nil, false
		}
		return kind, map[string]any{
			"remote_url": remoteURL,
		}, true
	default:
		return "", nil, false
	}
}

func execApprovalFromProc(info ProcInfo) (string, map[string]any, bool) {
	joined := strings.ToLower(strings.Join(info.Argv, " "))
	argv0 := strings.ToLower(info.Argv0)
	comm := strings.ToLower(info.Comm)

	isShell := argv0 == "sh" || strings.HasSuffix(argv0, "/sh") || comm == "sh" ||
		argv0 == "bash" || strings.HasSuffix(argv0, "/bash") || strings.Contains(comm, "bash") || strings.Contains(comm, "dash")

	if isShell && strings.Contains(joined, " -c ") {
		if strings.Contains(joined, "base64") && strings.Contains(joined, "|") && (strings.Contains(joined, "| sh") || strings.Contains(joined, "| bash") || strings.Contains(joined, "|bash")) {
			return "base64_pipe_to_shell", map[string]any{"argv": info.Argv, "comm": info.Comm}, true
		}
		if (strings.Contains(joined, "curl ") || strings.Contains(joined, "wget ")) && strings.Contains(joined, "|") &&
			(strings.Contains(joined, "| sh") || strings.Contains(joined, "| bash") || strings.Contains(joined, "|bash")) {
			return "curl_pipe_to_shell", map[string]any{"argv": info.Argv, "comm": info.Comm}, true
		}
	}

	if strings.Contains(joined, "curl ") || strings.Contains(joined, "wget ") {
		return "repo_download", map[string]any{"argv": info.Argv, "comm": info.Comm}, true
	}

	return "", nil, false
}

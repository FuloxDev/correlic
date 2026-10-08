//go:build linux

package procmon

import (
	"path/filepath"
	"strings"
)

// gitEventPayloadFromProc attempts to derive a higher-level git_event payload from a process_exec event.
//
// Output schema matches backend git_event detector expectations:
//
//	op, repo_path, remote_url, branch, result
//
// This is best-effort and intentionally conservative.
func gitEventPayloadFromProc(info ProcInfo) (map[string]any, bool) {
	argv := info.Argv
	if len(argv) == 0 {
		return nil, false
	}

	argv0 := strings.ToLower(argv[0])
	comm := strings.ToLower(info.Comm)
	joined := strings.ToLower(strings.Join(argv, " "))

	base0 := strings.ToLower(filepath.Base(argv0))

	// We treat both `git` and git transport helpers (git-remote-https, git-remote-ssh, etc) as git-related.
	// Important: `git pull/fetch` may not include the remote URL in argv, but helpers do.
	isGit := base0 == "git" || comm == "git" || strings.HasPrefix(joined, "git ")
	isGitRemoteHelper := strings.HasPrefix(base0, "git-remote-") || strings.HasPrefix(comm, "git-remote-")
	if !(isGit || isGitRemoteHelper) {
		return nil, false
	}

	// Determine subcommand.
	var sub string
	if base0 == "git" && len(argv) >= 2 {
		sub = strings.ToLower(argv[1])
	} else {
		// fallback: try to find "git" token in argv
		for i := 0; i < len(argv)-1; i++ {
			if strings.ToLower(filepath.Base(argv[i])) == "git" {
				sub = strings.ToLower(argv[i+1])
				break
			}
		}
	}
	// If we're a git-remote-* helper, subcommand may not be present; handle below.

	// Transport helper processes carry the authoritative remote URL (very useful for backend identity graph).
	if isGitRemoteHelper || strings.HasPrefix(sub, "remote-") {
		if remoteURL := parseGitRemoteHelperURL(argv); remoteURL != "" {
			out := map[string]any{
				"op":         "remote_transport",
				"remote_url": remoteURL,
				"result":     "ok",
			}
			return out, true
		}
		// If we couldn't extract a URL, don't emit.
		return nil, false
	}

	if sub == "" {
		return nil, false
	}

	switch sub {
	case "clone":
		remoteURL, repoPath, branch := parseGitCloneArgs(argv)
		if remoteURL == "" {
			return nil, false
		}
		out := map[string]any{
			"op":         "clone",
			"remote_url": remoteURL,
			"repo_path":  repoPath,
			"branch":     branch,
			"result":     "ok",
		}
		return out, true

	case "remote":
		op, remoteURL := parseGitRemoteArgs(argv)
		if op == "" || remoteURL == "" {
			return nil, false
		}
		out := map[string]any{
			"op":         op,
			"remote_url": remoteURL,
			"result":     "ok",
		}
		return out, true

	default:
		// For v0 we only derive clone + remote add/set-url because those include URLs we can normalize in backend.
		return nil, false
	}
}

func parseGitCloneArgs(argv []string) (remoteURL string, repoPath string, branch string) {
	// git clone [opts] <repo> [<dir>]
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch a {
		case "-b", "--branch":
			if i+1 < len(argv) {
				branch = argv[i+1]
				i++
			}
		}
	}

	// Find the first non-flag-ish arg after "clone" that looks like a URL-ish remote.
	afterClone := false
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !afterClone {
			if strings.ToLower(a) == "clone" {
				afterClone = true
			}
			continue
		}
		if strings.HasPrefix(a, "-") {
			// skip options and their values (best-effort)
			// handle common forms: -b <branch>, --branch <branch>, --depth <n>
			if a == "-b" || a == "--branch" || a == "--depth" || a == "-c" || a == "--config" {
				if i+1 < len(argv) {
					i++
				}
			}
			continue
		}
		if looksLikeGitRemote(a) {
			remoteURL = a
			// optional destination dir
			if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
				repoPath = argv[i+1]
			}
			return remoteURL, repoPath, branch
		}
	}
	return "", "", branch
}

func parseGitRemoteArgs(argv []string) (op string, remoteURL string) {
	// git remote add <name> <url>
	// git remote set-url <name> <newurl>
	lower := make([]string, 0, len(argv))
	for _, a := range argv {
		lower = append(lower, strings.ToLower(a))
	}

	// find "remote"
	ri := -1
	for i, a := range lower {
		if a == "remote" {
			ri = i
			break
		}
	}
	if ri < 0 || ri+1 >= len(argv) {
		return "", ""
	}
	sub := lower[ri+1]
	switch sub {
	case "add":
		// expect: remote add <name> <url>
		if ri+3 < len(argv) && looksLikeGitRemote(argv[ri+3]) {
			return "remote_add", argv[ri+3]
		}
	case "set-url":
		if ri+3 < len(argv) && looksLikeGitRemote(argv[ri+3]) {
			return "remote_set_url", argv[ri+3]
		}
	}
	return "", ""
}

func looksLikeGitRemote(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// https://host/org/repo(.git)
	if strings.Contains(s, "://") {
		return true
	}
	// scp-like: git@host:org/repo(.git)
	if strings.Contains(s, "@") && strings.Contains(s, ":") && !strings.Contains(s, "://") {
		return true
	}
	return false
}

// parseGitRemoteHelperURL extracts a remote URL from git transport helper argv.
//
// Examples:
// - ["git", "remote-https", "origin", "https://github.com/org/repo.git"] => url at idx 3
// - ["git-remote-https", "origin", "https://github.com/org/repo.git"]   => url at idx 2
func parseGitRemoteHelperURL(argv []string) string {
	// Prefer last arg that looks like a remote URL.
	for i := len(argv) - 1; i >= 0; i-- {
		if looksLikeGitRemote(argv[i]) {
			return strings.TrimSpace(argv[i])
		}
	}
	return ""
}

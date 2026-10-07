//go:build linux

package procmon

import "testing"

func TestGitEventPayloadFromProc_Clone(t *testing.T) {
	t.Parallel()

	info := ProcInfo{
		Comm: "git",
		Argv: []string{"git", "clone", "git@github.com:org/repo.git", "/tmp/repo"},
	}
	p, ok := gitEventPayloadFromProc(info)
	if !ok {
		t.Fatalf("expected ok")
	}
	if p["op"] != "clone" {
		t.Fatalf("op=%v", p["op"])
	}
	if p["remote_url"] != "git@github.com:org/repo.git" {
		t.Fatalf("remote_url=%v", p["remote_url"])
	}
	if p["repo_path"] != "/tmp/repo" {
		t.Fatalf("repo_path=%v", p["repo_path"])
	}
}

func TestGitEventPayloadFromProc_RemoteAdd(t *testing.T) {
	t.Parallel()

	info := ProcInfo{
		Comm: "git",
		Argv: []string{"git", "remote", "add", "origin", "https://github.com/org/repo.git"},
	}
	p, ok := gitEventPayloadFromProc(info)
	if !ok {
		t.Fatalf("expected ok")
	}
	if p["op"] != "remote_add" {
		t.Fatalf("op=%v", p["op"])
	}
	if p["remote_url"] != "https://github.com/org/repo.git" {
		t.Fatalf("remote_url=%v", p["remote_url"])
	}
}

func TestGitEventPayloadFromProc_RemoteHelper(t *testing.T) {
	t.Parallel()

	// Matches backend-observed: ["/usr/lib/git-core/git", "remote-https", "origin", "https://github.com/X/Y.git"]
	info := ProcInfo{
		Comm: "git",
		Argv: []string{"/usr/lib/git-core/git", "remote-https", "origin", "https://github.com/org/repo.git"},
	}
	p, ok := gitEventPayloadFromProc(info)
	if !ok {
		t.Fatalf("expected ok")
	}
	if p["op"] != "remote_transport" {
		t.Fatalf("op=%v", p["op"])
	}
	if p["remote_url"] != "https://github.com/org/repo.git" {
		t.Fatalf("remote_url=%v", p["remote_url"])
	}
}

func TestGitEventPayloadFromProc_NonGit(t *testing.T) {
	t.Parallel()

	info := ProcInfo{
		Comm: "bash",
		Argv: []string{"bash", "-c", "echo hi"},
	}
	if _, ok := gitEventPayloadFromProc(info); ok {
		t.Fatalf("expected not ok")
	}
}

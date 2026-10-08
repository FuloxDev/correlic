package ingest

import (
	"testing"

	"github.com/correlic/correlic-backend/internal/event"
)

func fileOpen(path string) *event.Event {
	return &event.Event{
		Type:    "file_open",
		Process: &event.ActorStruct{PID: 100, Comm: "cat", ExePath: "/usr/bin/cat"},
		Target:  &event.TargetStruct{FilePath: path},
	}
}

func TestIsSuspiciousPaths(t *testing.T) {
	rules := DefaultSamplingRules()

	suspicious := []string{
		"/home/alice/.ssh/id_rsa",
		"/home/alice/.aws/credentials",
		"/etc/shadow",
		"/etc/shadow-",                             // absolute prefix semantics
		"/home/bob/work/.kube/config",              // substring in the middle of the path
		"/var/lib/app/secrets/token.json",          // keyword substring
		"C:/Users/bob/.ssh/id_ed25519",             // Windows path normalized to slashes
		"/home/alice/project/.env",                 // .env anywhere
		"/home/alice/.mozilla/firefox/logins.json", // browser data
	}
	for _, p := range suspicious {
		if !rules.IsSuspicious(fileOpen(p)) {
			t.Errorf("expected %q to be suspicious", p)
		}
	}

	benign := []string{
		"/home/alice/project/main.go",
		"/home/alice/project/README.md",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/tmp/build-cache/object.o",
	}
	for _, p := range benign {
		if rules.IsSuspicious(fileOpen(p)) {
			t.Errorf("expected %q to be benign", p)
		}
	}
}

func TestMatchesPattern(t *testing.T) {
	cases := []struct {
		path, pattern string
		want          bool
	}{
		// substring (no "*", not absolute)
		{"/home/alice/.ssh/id_rsa", ".ssh/", true},
		{"/home/alice/.ssh/id_rsa", "id_rsa", true},
		{"/home/alice/project/main.go", ".ssh/", false},
		// absolute prefix
		{"/etc/shadow", "/etc/shadow", true},
		{"/etc/shadow-", "/etc/shadow", true},
		{"/home/alice/etc/shadow", "/etc/shadow", false},
		// single-star glob
		{"/home/alice/server.key", "*.key", true},
		{"/home/alice/.ssh/config", "/home/*/.ssh/", false}, // suffix must match
		{"/home/alice/.ssh/", "/home/*/.ssh/", true},
		// multi-star glob
		{"/home/alice/.aws/credentials", "/home/*/.aws/*", true},
		{"/opt/alice/.aws/credentials", "/home/*/.aws/*", false},
		// empty pattern never matches
		{"/anything", "", false},
	}
	for _, c := range cases {
		if got := matchesPattern(c.path, c.pattern); got != c.want {
			t.Errorf("matchesPattern(%q, %q) = %v, want %v", c.path, c.pattern, got, c.want)
		}
	}
}

// TestSamplerSecurityFirstOrder guards the documented invariant: a suspicious file
// read by an otherwise "benign" process is kept, and AI events are always kept.
func TestSamplerSecurityFirstOrder(t *testing.T) {
	s := NewSampler(DefaultSamplingRules())

	shadowByLs := fileOpen("/etc/shadow")
	shadowByLs.Process.ExePath = "/bin/ls"
	if !s.ShouldKeep(shadowByLs) {
		t.Fatalf("suspicious read by benign process must be kept")
	}

	benignByLs := fileOpen("/home/alice/project/main.go")
	benignByLs.Process.ExePath = "/bin/ls"
	if s.ShouldKeep(benignByLs) {
		t.Fatalf("benign read by benign process must be dropped")
	}

	aiEvt := fileOpen("/home/alice/project/main.go")
	aiEvt.Process.ExePath = "/bin/ls"
	aiEvt.Context = map[string]any{"ai_session_id": "s1"}
	if !s.ShouldKeep(aiEvt) {
		t.Fatalf("AI-attributed events must always be kept")
	}
}

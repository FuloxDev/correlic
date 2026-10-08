package ingest

import "testing"

func TestMatchSuspiciousPath(t *testing.T) {
	cases := map[string]string{
		"/home/u/.ssh/id_rsa":            ".ssh/",
		"/etc/shadow":                    "/etc/shadow",
		"/etc/shadow-":                   "/etc/shadow",
		"/srv/app/.env.production":       ".env",
		"/home/u/.aws/credentials":       ".aws/",
		"C:/Windows/System32/config/SAM": "config", // first match in list order wins
		"/proc/1/environ":                "/proc/",
	}
	for path, want := range cases {
		got, ok := MatchSuspiciousPath(path)
		if !ok || got != want {
			t.Errorf("MatchSuspiciousPath(%q) = %q,%v; want %q", path, got, ok, want)
		}
	}
	for _, path := range []string{"", "/home/u/proj/main.go", "/usr/share/doc/readme", "/tmp/build/out.o"} {
		if got, ok := MatchSuspiciousPath(path); ok {
			t.Errorf("MatchSuspiciousPath(%q) = %q, want no match", path, got)
		}
	}
}

func TestSampler_AlwaysKeepsAIToolCalls(t *testing.T) {
	rules := DefaultSamplingRules()
	if !rules.IsAlwaysKeep("ai_tool_call") {
		t.Fatal("ai_tool_call must be in the always-keep list")
	}
	// The security-first order is unchanged: process_exec still kept, benign still dropped.
	if !rules.IsAlwaysKeep("process_exec") || rules.IsAlwaysKeep("process_exit") {
		t.Error("always-keep list changed unexpectedly")
	}
}

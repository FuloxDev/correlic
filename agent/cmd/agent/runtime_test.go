package main

import (
	"testing"
	"time"
)

func TestExtractConfigFlag(t *testing.T) {
	tests := []struct {
		args     []string
		wantPath string
		wantRest []string
		wantErr  bool
	}{
		{nil, "", []string{}, false},
		{[]string{"check-compat"}, "", []string{"check-compat"}, false},
		{[]string{"--config", "/etc/correlic/agent.yaml"}, "/etc/correlic/agent.yaml", []string{}, false},
		{[]string{"-config", "/a.yaml", "service", "install"}, "/a.yaml", []string{"service", "install"}, false},
		{[]string{"--config=/b.yaml"}, "/b.yaml", []string{}, false},
		{[]string{"-config=/c.yaml"}, "/c.yaml", []string{}, false},
		{[]string{"--config"}, "", nil, true},
		{[]string{"--config="}, "", nil, true},
	}
	for _, tt := range tests {
		path, rest, err := extractConfigFlag(tt.args)
		if (err != nil) != tt.wantErr {
			t.Errorf("%v: err = %v, wantErr %v", tt.args, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if path != tt.wantPath {
			t.Errorf("%v: path = %q, want %q", tt.args, path, tt.wantPath)
		}
		if len(rest) != len(tt.wantRest) {
			t.Errorf("%v: rest = %v, want %v", tt.args, rest, tt.wantRest)
			continue
		}
		for i := range rest {
			if rest[i] != tt.wantRest[i] {
				t.Errorf("%v: rest = %v, want %v", tt.args, rest, tt.wantRest)
			}
		}
	}
}

func TestAgentRuntimeWait(t *testing.T) {
	rt := newAgentRuntime(nil)
	block := make(chan struct{})
	rt.spawn("quick", func() {})
	rt.spawn("slow", func() { <-block })
	if rt.wait(20 * time.Millisecond) {
		t.Fatal("wait should time out while a goroutine is blocked")
	}
	close(block)
	if !rt.wait(time.Second) {
		t.Fatal("wait should return once all goroutines finished")
	}
}

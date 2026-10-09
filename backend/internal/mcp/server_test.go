package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// errorsAs is errors.As for tests in this package.
func errorsAs(err error, target any) bool { return errors.As(err, target) }

func TestServeStdio(t *testing.T) {
	tools := []Tool{{Name: "echo", Description: "echo", InputSchema: map[string]any{"type": "object"}}}
	call := func(name string, args map[string]any) (ToolResult, error) {
		if name != "echo" {
			return ToolResult{}, errors.New("unknown tool: " + name)
		}
		return ToolResult{Content: []ToolContent{{Type: "text", Text: `{"got":"` + args["v"].(string) + `"}`}}}, nil
	}
	srv := NewServer(ServerInfo{Name: "correlic-mcp", Version: "test"}, tools, call)
	srv.SetInstructions("hello")

	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"v":"x"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":6,"method":"ping"}`,
		`not json`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := srv.Serve(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 6 responses (notification and garbage produce none), got %d:\n%s", len(lines), out.String())
	}
	var init struct {
		Result struct {
			ProtocolVersion string         `json:"protocolVersion"`
			Instructions    string         `json:"instructions"`
			ServerInfo      ServerInfo     `json:"serverInfo"`
			Capabilities    map[string]any `json:"capabilities"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &init); err != nil || init.Error != nil {
		t.Fatalf("initialize response: %s (%v)", lines[0], err)
	}
	// A newer client revision is answered with ours, never refused.
	if init.Result.ProtocolVersion != ProtocolVersion || init.Result.Instructions != "hello" || init.Result.ServerInfo.Name != "correlic-mcp" {
		t.Errorf("initialize result = %+v", init.Result)
	}
	if _, ok := init.Result.Capabilities["tools"]; !ok {
		t.Error("tools capability missing")
	}
	if !strings.Contains(lines[1], `"name":"echo"`) {
		t.Errorf("tools/list = %s", lines[1])
	}
	if !strings.Contains(lines[2], `"isError":false`) || !strings.Contains(lines[2], `\"got\":\"x\"`) {
		t.Errorf("tools/call = %s", lines[2])
	}
	if !strings.Contains(lines[3], `"isError":true`) || !strings.Contains(lines[3], "unknown tool: nope") {
		t.Errorf("tools/call error = %s", lines[3])
	}
	if !strings.Contains(lines[4], `"code":-32601`) {
		t.Errorf("unknown method = %s", lines[4])
	}
	if !strings.Contains(lines[5], `"id":6`) || strings.Contains(lines[5], "error") {
		t.Errorf("ping = %s", lines[5])
	}
}

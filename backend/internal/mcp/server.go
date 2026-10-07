package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

const ProtocolVersion = "2024-11-05"

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Server struct {
	info        ServerInfo
	tools       []Tool
	callTool    func(name string, args map[string]any) (ToolResult, error)
	mu          sync.Mutex
	initialized bool
}

func NewServer(info ServerInfo, tools []Tool, callTool func(name string, args map[string]any) (ToolResult, error)) *Server {
	return &Server{info: info, tools: tools, callTool: callTool}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcNotification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (s *Server) Serve(in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	// Messages can be large (e.g. tool results). Increase buffer.
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 10*1024*1024)

	enc := json.NewEncoder(out)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}

		// Determine if this is a request (has id) or notification (no id).
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(line, &probe); err != nil {
			// Can't respond without an id; log and continue.
			log.Printf("mcp: invalid json: %v", err)
			continue
		}

		if _, hasID := probe["id"]; hasID {
			var req rpcRequest
			if err := json.Unmarshal(line, &req); err != nil {
				// Best effort: echo id if present.
				id := probe["id"]
				_ = s.write(enc, rpcResponse{
					JSONRPC: "2.0",
					ID:      id,
					Error:   &rpcError{Code: -32700, Message: "Parse error"},
				})
				continue
			}
			resp := s.handleRequest(&req)
			_ = s.write(enc, resp)
		} else {
			var n rpcNotification
			if err := json.Unmarshal(line, &n); err != nil {
				log.Printf("mcp: invalid notification: %v", err)
				continue
			}
			s.handleNotification(&n)
		}
	}

	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}

func (s *Server) write(enc *json.Encoder, v any) error {
	// Ensure one writer at a time; json.Encoder is not safe for concurrent use.
	s.mu.Lock()
	defer s.mu.Unlock()
	return enc.Encode(v) // Encode adds a trailing newline delimiter.
}

func (s *Server) handleNotification(n *rpcNotification) {
	if n.Method == "notifications/initialized" {
		s.mu.Lock()
		s.initialized = true
		s.mu.Unlock()
	}
}

func (s *Server) handleRequest(req *rpcRequest) rpcResponse {
	if req.JSONRPC != "2.0" {
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32600, Message: "Invalid Request"}}
	}

	switch req.Method {
	case "ping":
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(req)
	default:
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "Method not found"}}
	}
}

func (s *Server) handleInitialize(req *rpcRequest) rpcResponse {
	var params struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ClientInfo      map[string]any `json:"clientInfo"`
	}
	_ = json.Unmarshal(req.Params, &params)

	// Only support the documented protocol version for now.
	if params.ProtocolVersion != "" && params.ProtocolVersion != ProtocolVersion {
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &rpcError{
				Code:    -32602,
				Message: "Unsupported protocol version",
				Data: map[string]any{
					"supported": []string{ProtocolVersion},
					"requested": params.ProtocolVersion,
				},
			},
		}
	}

	res := map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": s.info,
	}
	return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: res}
}

func (s *Server) handleToolsList(req *rpcRequest) rpcResponse {
	res := map[string]any{
		"tools": s.tools,
	}
	return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: res}
}

func (s *Server) handleToolsCall(req *rpcRequest) rpcResponse {
	// Servers should not do more than pings before initialized, but some clients call tools early.
	// We allow it as a convenience.

	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "Invalid params"}}
	}
	if params.Name == "" {
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "Invalid params: missing tool name"}}
	}

	start := time.Now()
	result, err := s.callTool(params.Name, params.Arguments)
	if err != nil {
		// Treat as tool error (not protocol error) so model can see message.
		result = ToolResult{
			Content: []ToolContent{{Type: "text", Text: err.Error()}},
			IsError: true,
		}
	}
	_ = start // keep for future logging/metrics

	// Validate tool result basic shape.
	if len(result.Content) == 0 {
		result.Content = []ToolContent{{Type: "text", Text: "ok"}}
	}
	return rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}

// Helpers

func RequireString(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("missing required argument: %s", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("invalid argument %s: expected non-empty string", key)
	}
	return s, nil
}

func OptionalString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func OptionalBool(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func OptionalInt(m map[string]any, key string) (int, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return int(t), true
	case int:
		return t, true
	default:
		return 0, false
	}
}

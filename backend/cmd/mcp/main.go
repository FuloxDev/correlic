package main

import (
	"context"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/mcp"
)

const (
	serverName    = "correlic-mcp"
	serverVersion = "0.1.0"
)

func main() {
	baseURL := strings.TrimSpace(os.Getenv("CORRELIC_API_URL"))
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	auth := strings.TrimSpace(os.Getenv("CORRELIC_API_KEY"))
	// Auth middleware accepts raw key or "Bearer <key>".
	if auth != "" && !strings.Contains(auth, " ") {
		// Keep raw key (backend accepts single token).
	}
	allowFree := strings.EqualFold(strings.TrimSpace(os.Getenv("CORRELIC_MCP_ALLOW_FREE")), "true") ||
		strings.TrimSpace(os.Getenv("CORRELIC_MCP_ALLOW_FREE")) == "1"

	client := &mcp.CorrelicClient{
		BaseURL:       baseURL,
		Authorization: auth,
	}

	tools := []mcp.Tool{
		{
			Name:        "correlic.ai.proof",
			Description: "Generate an AI Proof report (evidence-backed) over a time window.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"since":          map[string]any{"type": "string", "description": "RFC3339 timestamp"},
					"until":          map[string]any{"type": "string", "description": "RFC3339 timestamp"},
					"agent_id":       map[string]any{"type": "string"},
					"include_non_ai": map[string]any{"type": "boolean"},
				},
				"required": []string{"since", "until"},
			},
		},
		{
			Name:        "correlic.network.summary",
			Description: "Get network summary for a time window (DNS + net_connect aggregates).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"since":    map[string]any{"type": "string"},
					"until":    map[string]any{"type": "string"},
					"agent_id": map[string]any{"type": "string"},
				},
			},
		},
		{
			Name:        "correlic.ports.summary",
			Description: "Get ports summary for a time window (open services + exposure).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"since":    map[string]any{"type": "string"},
					"until":    map[string]any{"type": "string"},
					"agent_id": map[string]any{"type": "string"},
				},
			},
		},
		{
			Name:        "correlic.telemetry.search",
			Description: "Search recent telemetry with filters (event type, time window, pid, ai_only).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"event_type": map[string]any{"type": "string"},
					"agent_id":   map[string]any{"type": "string"},
					"since":      map[string]any{"type": "string"},
					"until":      map[string]any{"type": "string"},
					"pid":        map[string]any{"type": "integer"},
					"limit":      map[string]any{"type": "integer"},
					"offset":     map[string]any{"type": "integer"},
					"ai_only":    map[string]any{"type": "boolean"},
				},
			},
		},
		{
			Name:        "correlic.tier",
			Description: "Return current Correlic tier and limits (for gating decisions).",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
	}

	callTool := func(name string, args map[string]any) (mcp.ToolResult, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		// Enforce Pro/Trial by default.
		if !allowFree {
			t, _, err := client.Tier(ctx)
			if err == nil {
				tt := strings.ToLower(strings.TrimSpace(t))
				if tt != "pro" && tt != "trial" {
					return mcp.ToolResult{}, mcp.ErrUnauthorizedTier
				}
			}
		}

		switch name {
		case "correlic.tier":
			body, err := client.DoTier(ctx)
			return toTextResult(body, err)

		case "correlic.ai.proof":
			since, err := mcp.RequireString(args, "since")
			if err != nil {
				return mcp.ToolResult{}, err
			}
			until, err := mcp.RequireString(args, "until")
			if err != nil {
				return mcp.ToolResult{}, err
			}
			q := url.Values{}
			q.Set("since", since)
			q.Set("until", until)
			if v := mcp.OptionalString(args, "agent_id"); v != "" {
				q.Set("agent_id", v)
			}
			if mcp.OptionalBool(args, "include_non_ai") {
				q.Set("include_non_ai", "true")
			}
			body, err := client.DoGET(ctx, "/ai/proof", q)
			return toTextResult(body, err)

		case "correlic.network.summary":
			q := url.Values{}
			if v := mcp.OptionalString(args, "since"); v != "" {
				q.Set("since", v)
			}
			if v := mcp.OptionalString(args, "until"); v != "" {
				q.Set("until", v)
			}
			if v := mcp.OptionalString(args, "agent_id"); v != "" {
				q.Set("agent_id", v)
			}
			body, err := client.DoGET(ctx, "/network/summary", q)
			return toTextResult(body, err)

		case "correlic.ports.summary":
			q := url.Values{}
			if v := mcp.OptionalString(args, "since"); v != "" {
				q.Set("since", v)
			}
			if v := mcp.OptionalString(args, "until"); v != "" {
				q.Set("until", v)
			}
			if v := mcp.OptionalString(args, "agent_id"); v != "" {
				q.Set("agent_id", v)
			}
			body, err := client.DoGET(ctx, "/ports/summary", q)
			return toTextResult(body, err)

		case "correlic.telemetry.search":
			q := url.Values{}
			if v := mcp.OptionalString(args, "event_type"); v != "" {
				q.Set("event_type", v)
			}
			if v := mcp.OptionalString(args, "agent_id"); v != "" {
				q.Set("agent_id", v)
			}
			if v := mcp.OptionalString(args, "since"); v != "" {
				q.Set("since", v)
			}
			if v := mcp.OptionalString(args, "until"); v != "" {
				q.Set("until", v)
			}
			if v, ok := mcp.OptionalInt(args, "pid"); ok && v > 0 {
				q.Set("pid", intToString(v))
			}
			if v, ok := mcp.OptionalInt(args, "limit"); ok && v > 0 {
				q.Set("limit", intToString(v))
			}
			if v, ok := mcp.OptionalInt(args, "offset"); ok && v >= 0 {
				q.Set("offset", intToString(v))
			}
			if mcp.OptionalBool(args, "ai_only") {
				q.Set("ai_only", "true")
			}
			body, err := client.DoGET(ctx, "/telemetry", q)
			return toTextResult(body, err)

		default:
			return mcp.ToolResult{}, errUnknownTool(name)
		}
	}

	srv := mcp.NewServer(mcp.ServerInfo{Name: serverName, Version: serverVersion}, tools, callTool)
	if err := srv.Serve(os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func toTextResult(body []byte, err error) (mcp.ToolResult, error) {
	if err != nil {
		return mcp.ToolResult{}, err
	}
	// Ensure the returned text contains no literal newlines (stdio transport constraint).
	compact := strings.ReplaceAll(string(body), "\n", "")
	compact = strings.ReplaceAll(compact, "\r", "")
	return mcp.ToolResult{
		Content: []mcp.ToolContent{{Type: "text", Text: compact}},
		IsError: false,
	}, nil
}

func errUnknownTool(name string) error {
	return &toolError{msg: "unknown tool: " + name}
}

type toolError struct{ msg string }

func (e *toolError) Error() string { return e.msg }

func intToString(v int) string {
	return strconv.Itoa(v)
}

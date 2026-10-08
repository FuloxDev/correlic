// Package provider provides an abstraction layer for LLM providers.
// Supports OpenAI, Google Gemini, and other providers via a common interface.
package provider

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// Provider is the interface all LLM providers must implement.
type Provider interface {
	// Name returns the provider name (e.g., "openai", "gemini").
	Name() string

	// Chat sends messages to the LLM and returns the response.
	Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error)

	// AnalyzeEvents analyzes security events and returns structured analysis.
	AnalyzeEvents(ctx context.Context, events []map[string]any) (*SecurityAnalysis, error)

	// ExplainEvent explains a single event in human-readable terms.
	ExplainEvent(ctx context.Context, event map[string]any) (*EventExplanation, error)
}

// ToolDefinition defines a tool the LLM can call.
type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"` // JSON Schema object
}

// ToolCall represents a tool invocation requested by the LLM.
type ToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON string
}

// ChatRequest represents a chat request to the LLM.
type ChatRequest struct {
	Messages    []Message        `json:"messages"`
	MaxTokens   int              `json:"max_tokens,omitempty"`
	Temperature float64          `json:"temperature,omitempty"`
	Model       string           `json:"model,omitempty"`       // Override default model
	Tools       []ToolDefinition `json:"tools,omitempty"`       // Tool definitions for function calling
	ToolChoice  string           `json:"tool_choice,omitempty"` // "auto", "required", or "none"
}

// Message represents a chat message.
type Message struct {
	Role       string     `json:"role"` // "system", "user", "assistant", "tool"
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`   // Tool calls made by the assistant
	ToolCallID string     `json:"tool_call_id,omitempty"` // ID of the tool call this message responds to
}

// ChatResponse represents a response from the LLM.
type ChatResponse struct {
	Content      string        `json:"content"`
	Model        string        `json:"model"`
	InputTokens  int           `json:"input_tokens"`
	OutputTokens int           `json:"output_tokens"`
	FinishReason string        `json:"finish_reason"`
	Latency      time.Duration `json:"latency"`
	ToolCalls    []ToolCall    `json:"tool_calls,omitempty"`
}

// SecurityAnalysis represents structured analysis of security events.
type SecurityAnalysis struct {
	Severity         string            `json:"severity"` // "low", "medium", "high", "critical"
	Summary          string            `json:"summary"`
	ThreatType       string            `json:"threat_type,omitempty"`
	AttackTechniques []AttackTechnique `json:"attack_techniques,omitempty"`
	Recommendations  []string          `json:"recommendations"`
	RelatedEvents    []string          `json:"related_events,omitempty"`
	Confidence       float64           `json:"confidence"` // 0.0 to 1.0
	RawResponse      string            `json:"raw_response,omitempty"`
}

// AttackTechnique represents a MITRE ATT&CK technique.
type AttackTechnique struct {
	ID          string `json:"id"`     // e.g., "T1059.001"
	Name        string `json:"name"`   // e.g., "PowerShell"
	Tactic      string `json:"tactic"` // e.g., "Execution"
	Description string `json:"description,omitempty"`
}

// EventExplanation represents the explanation of a single event.
type EventExplanation struct {
	Summary         string   `json:"summary"`
	TechnicalDetail string   `json:"technical_detail"`
	RiskLevel       string   `json:"risk_level"`
	IsNormal        bool     `json:"is_normal"`
	Concerns        []string `json:"concerns,omitempty"`
	Context         string   `json:"context,omitempty"`
}

// StreamingProvider extends Provider with streaming support.
// Providers that implement this can stream chat responses token-by-token.
type StreamingProvider interface {
	Provider
	// StreamChat streams the LLM response, calling onDelta for each text chunk.
	// Returns the final ChatResponse with token usage after the stream completes.
	StreamChat(ctx context.Context, req *ChatRequest, onDelta func(delta string)) (*ChatResponse, error)
}

// Config holds common configuration for LLM providers.
type Config struct {
	APIKey      string
	Model       string
	MaxTokens   int
	Temperature float64
	BaseURL     string // For custom endpoints
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxTokens:   4096,
		Temperature: 0.7,
	}
}

// ExtractJSON extracts JSON from a string, handling markdown code blocks.
// LLMs often return JSON wrapped in ```json ... ``` blocks.
func ExtractJSON(content string) string {
	content = strings.TrimSpace(content)

	// Pattern to match ```json ... ``` or ``` ... ```
	codeBlockRegex := regexp.MustCompile("(?s)```(?:json)?\\s*\\n?(.*?)\\n?```")
	if matches := codeBlockRegex.FindStringSubmatch(content); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	// If no code block, try to find JSON object directly
	if strings.HasPrefix(content, "{") {
		// Find the matching closing brace
		depth := 0
		for i, c := range content {
			if c == '{' {
				depth++
			} else if c == '}' {
				depth--
				if depth == 0 {
					return content[:i+1]
				}
			}
		}
	}

	return content
}

// ParseSecurityAnalysis parses LLM response into SecurityAnalysis struct.
func ParseSecurityAnalysis(content string) *SecurityAnalysis {
	analysis := &SecurityAnalysis{RawResponse: content}

	// Extract JSON from markdown code blocks
	jsonStr := ExtractJSON(content)

	// Try to parse as JSON
	if err := json.Unmarshal([]byte(jsonStr), analysis); err != nil {
		// If parsing fails, use the raw content as summary
		analysis.Summary = content
		analysis.Severity = "unknown"
		analysis.Confidence = 0.5
	}

	// Ensure raw_response is not duplicated in output if parsing succeeded
	if analysis.Summary != "" && analysis.Summary != content {
		analysis.RawResponse = "" // Clear raw response if we got good structured data
	}

	return analysis
}

// ParseEventExplanation parses LLM response into EventExplanation struct.
func ParseEventExplanation(content string) *EventExplanation {
	explanation := &EventExplanation{}

	// Extract JSON from markdown code blocks
	jsonStr := ExtractJSON(content)

	// Try to parse as JSON
	if err := json.Unmarshal([]byte(jsonStr), explanation); err != nil {
		// If parsing fails, use raw content as summary
		explanation.Summary = content
		explanation.RiskLevel = "unknown"
	}

	return explanation
}

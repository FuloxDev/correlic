package provider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAIProvider implements the Provider interface for OpenAI.
type OpenAIProvider struct {
	config     Config
	httpClient *http.Client
}

// NewOpenAIProvider creates a new OpenAI provider.
func NewOpenAIProvider(cfg Config) *OpenAIProvider {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.openai.com/v1"
	}
	if cfg.Model == "" {
		cfg.Model = "gpt-4o-mini" // Default to cheaper model
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 4096
	}
	if cfg.Temperature == 0 {
		cfg.Temperature = 0.7
	}

	return &OpenAIProvider{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (p *OpenAIProvider) Name() string {
	return "openai"
}

// Chat implements Provider.Chat for OpenAI.
func (p *OpenAIProvider) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	start := time.Now()

	model := p.config.Model
	if req.Model != "" {
		model = req.Model
	}

	maxTokens := p.config.MaxTokens
	if req.MaxTokens > 0 {
		maxTokens = req.MaxTokens
	}

	temperature := p.config.Temperature
	if req.Temperature > 0 {
		temperature = req.Temperature
	}

	// Build messages array with proper tool message handling.
	openaiMessages := make([]map[string]any, 0, len(req.Messages))
	for _, msg := range req.Messages {
		m := map[string]any{
			"role":    msg.Role,
			"content": msg.Content,
		}
		if msg.Role == "tool" && msg.ToolCallID != "" {
			m["tool_call_id"] = msg.ToolCallID
		}
		if len(msg.ToolCalls) > 0 {
			// Assistant message with tool calls — serialize in OpenAI format.
			tcs := make([]map[string]any, len(msg.ToolCalls))
			for i, tc := range msg.ToolCalls {
				tcs[i] = map[string]any{
					"id":   tc.ID,
					"type": "function",
					"function": map[string]any{
						"name":      tc.Name,
						"arguments": tc.Arguments,
					},
				}
			}
			m["tool_calls"] = tcs
		}
		openaiMessages = append(openaiMessages, m)
	}

	// Build OpenAI request
	openaiReq := map[string]any{
		"model":       model,
		"messages":    openaiMessages,
		"max_tokens":  maxTokens,
		"temperature": temperature,
	}

	// Add tools if provided.
	if len(req.Tools) > 0 {
		tools := make([]map[string]any, len(req.Tools))
		for i, t := range req.Tools {
			tools[i] = map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        t.Name,
					"description": t.Description,
					"parameters":  t.Parameters,
				},
			}
		}
		openaiReq["tools"] = tools
	}
	if req.ToolChoice != "" {
		openaiReq["tool_choice"] = req.ToolChoice
	}

	body, err := json.Marshal(openaiReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.config.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var openaiResp struct {
		Choices []struct {
			Message struct {
				Content   *string `json:"content"` // nullable when tool_calls present
				ToolCalls []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
		Model string `json:"model"`
	}

	if err := json.Unmarshal(respBody, &openaiResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if len(openaiResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	choice := openaiResp.Choices[0]

	content := ""
	if choice.Message.Content != nil {
		content = *choice.Message.Content
	}

	var toolCalls []ToolCall
	for _, tc := range choice.Message.ToolCalls {
		toolCalls = append(toolCalls, ToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: tc.Function.Arguments,
		})
	}

	return &ChatResponse{
		Content:      content,
		Model:        openaiResp.Model,
		InputTokens:  openaiResp.Usage.PromptTokens,
		OutputTokens: openaiResp.Usage.CompletionTokens,
		FinishReason: choice.FinishReason,
		Latency:      time.Since(start),
		ToolCalls:    toolCalls,
	}, nil
}

// StreamChat implements StreamingProvider.StreamChat for OpenAI.
func (p *OpenAIProvider) StreamChat(ctx context.Context, req *ChatRequest, onDelta func(delta string)) (*ChatResponse, error) {
	start := time.Now()

	model := p.config.Model
	if req.Model != "" {
		model = req.Model
	}
	maxTokens := p.config.MaxTokens
	if req.MaxTokens > 0 {
		maxTokens = req.MaxTokens
	}
	temperature := p.config.Temperature
	if req.Temperature > 0 {
		temperature = req.Temperature
	}

	openaiReq := map[string]any{
		"model":       model,
		"messages":    req.Messages,
		"max_tokens":  maxTokens,
		"temperature": temperature,
		"stream":      true,
	}

	body, err := json.Marshal(openaiReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// Use a client without timeout for streaming (context handles cancellation).
	httpClient := &http.Client{}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.config.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("openai error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var fullContent strings.Builder
	var finalModel string
	var finishReason string

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			Model string `json:"model"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		if chunk.Model != "" {
			finalModel = chunk.Model
		}
		if len(chunk.Choices) > 0 {
			delta := chunk.Choices[0].Delta.Content
			if delta != "" {
				fullContent.WriteString(delta)
				onDelta(delta)
			}
			if chunk.Choices[0].FinishReason != nil {
				finishReason = *chunk.Choices[0].FinishReason
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan openai stream: %w", err)
	}

	return &ChatResponse{
		Content:      fullContent.String(),
		Model:        finalModel,
		FinishReason: finishReason,
		Latency:      time.Since(start),
		// OpenAI streaming doesn't provide token counts in chunks; they arrive in the final chunk
		// or via the usage endpoint. We leave these as 0 for streaming.
	}, nil
}

// AnalyzeEvents implements Provider.AnalyzeEvents for OpenAI.
func (p *OpenAIProvider) AnalyzeEvents(ctx context.Context, events []map[string]any) (*SecurityAnalysis, error) {
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		return nil, fmt.Errorf("marshal events: %w", err)
	}

	resp, err := p.Chat(ctx, &ChatRequest{
		Messages: []Message{
			{
				Role:    "system",
				Content: SecurityAnalysisSystemPrompt,
			},
			{
				Role:    "user",
				Content: fmt.Sprintf("Analyze these security events and provide a structured threat assessment:\n\n%s", string(eventsJSON)),
			},
		},
	})
	if err != nil {
		return nil, err
	}

	return ParseSecurityAnalysis(resp.Content), nil
}

// ExplainEvent implements Provider.ExplainEvent for OpenAI.
func (p *OpenAIProvider) ExplainEvent(ctx context.Context, event map[string]any) (*EventExplanation, error) {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("marshal event: %w", err)
	}

	resp, err := p.Chat(ctx, &ChatRequest{
		Messages: []Message{
			{
				Role:    "system",
				Content: EventExplanationSystemPrompt,
			},
			{
				Role:    "user",
				Content: fmt.Sprintf("Explain this security event in simple terms:\n\n%s", string(eventJSON)),
			},
		},
		MaxTokens: 1024, // Shorter response for single event
	})
	if err != nil {
		return nil, err
	}

	return ParseEventExplanation(resp.Content), nil
}

// Security analysis system prompt
const SecurityAnalysisSystemPrompt = `You are a security analyst AI assistant specializing in endpoint detection and response (EDR).
Analyze the provided security events and return a JSON response with this structure:
{
  "severity": "low|medium|high|critical",
  "summary": "Brief description of what happened",
  "threat_type": "Type of threat if any (e.g., 'malware', 'lateral_movement', 'privilege_escalation')",
  "attack_techniques": [
    {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}
  ],
  "recommendations": ["List of recommended actions"],
  "related_events": ["IDs of related events"],
  "confidence": 0.0-1.0
}

Focus on:
- Process execution chains (parent-child relationships)
- Network connections from suspicious processes
- File access to sensitive paths
- Privilege escalation patterns
- Container escape attempts
- Credential access

Be concise but thorough. If the events appear benign, say so with low severity.`

// Event explanation system prompt
const EventExplanationSystemPrompt = `You are a security analyst AI assistant.
Explain the provided security event in simple terms for a developer or security analyst.
Return a JSON response with this structure:
{
  "summary": "One-sentence explanation",
  "technical_detail": "More detailed technical explanation",
  "risk_level": "low|medium|high|critical",
  "is_normal": true|false,
  "concerns": ["List of security concerns if any"],
  "context": "Additional context about what this event means"
}

Be concise and helpful. If this is normal system behavior, explain why.`

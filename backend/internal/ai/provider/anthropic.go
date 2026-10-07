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

// AnthropicProvider implements the Provider interface for Anthropic Claude.
type AnthropicProvider struct {
	config     Config
	httpClient *http.Client
}

// NewAnthropicProvider creates a new Anthropic provider.
func NewAnthropicProvider(cfg Config) *AnthropicProvider {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.anthropic.com/v1"
	}
	if cfg.Model == "" {
		cfg.Model = "claude-sonnet-4-20250514"
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 4096
	}
	if cfg.Temperature == 0 {
		cfg.Temperature = 0.7
	}

	return &AnthropicProvider{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

func (p *AnthropicProvider) Name() string {
	return "anthropic"
}

// Chat implements Provider.Chat for Anthropic Claude.
func (p *AnthropicProvider) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
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

	// Anthropic uses a top-level "system" field, not a system message.
	// Extract system messages and pass the rest as messages.
	var systemPrompt string
	var messages []map[string]any
	for _, msg := range req.Messages {
		if msg.Role == "system" {
			if systemPrompt != "" {
				systemPrompt += "\n\n"
			}
			systemPrompt += msg.Content
			continue
		}
		if msg.Role == "tool" {
			// Anthropic represents tool results as user messages with tool_result content blocks.
			messages = append(messages, map[string]any{
				"role": "user",
				"content": []map[string]any{
					{
						"type":        "tool_result",
						"tool_use_id": msg.ToolCallID,
						"content":     msg.Content,
					},
				},
			})
			continue
		}
		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			// Assistant message with tool calls — include tool_use content blocks.
			content := []map[string]any{}
			if msg.Content != "" {
				content = append(content, map[string]any{
					"type": "text",
					"text": msg.Content,
				})
			}
			for _, tc := range msg.ToolCalls {
				// Parse arguments JSON string back to an object for Anthropic's input field.
				var input any
				if err := json.Unmarshal([]byte(tc.Arguments), &input); err != nil {
					input = map[string]any{}
				}
				content = append(content, map[string]any{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Name,
					"input": input,
				})
			}
			messages = append(messages, map[string]any{
				"role":    "assistant",
				"content": content,
			})
			continue
		}
		messages = append(messages, map[string]any{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}

	// Build Anthropic request
	anthropicReq := map[string]any{
		"model":       model,
		"max_tokens":  maxTokens,
		"temperature": temperature,
		"messages":    messages,
	}
	if systemPrompt != "" {
		anthropicReq["system"] = systemPrompt
	}

	// Add tools if provided.
	if len(req.Tools) > 0 {
		tools := make([]map[string]any, len(req.Tools))
		for i, t := range req.Tools {
			tools[i] = map[string]any{
				"name":         t.Name,
				"description":  t.Description,
				"input_schema": t.Parameters,
			}
		}
		anthropicReq["tools"] = tools
	}
	if req.ToolChoice != "" {
		// Anthropic accepts tool_choice as an object: {"type": "auto"|"any"|"tool"}
		// Map from OpenAI-style strings.
		switch req.ToolChoice {
		case "required":
			anthropicReq["tool_choice"] = map[string]any{"type": "any"}
		case "none":
			// Anthropic doesn't have a direct "none" — omit tools or don't send tool_choice.
		default:
			anthropicReq["tool_choice"] = map[string]any{"type": req.ToolChoice}
		}
	}

	body, err := json.Marshal(anthropicReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.config.BaseURL+"/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

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
		return nil, fmt.Errorf("anthropic error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var anthropicResp struct {
		Content []struct {
			Type  string         `json:"type"`
			Text  string         `json:"text,omitempty"`
			ID    string         `json:"id,omitempty"`
			Name  string         `json:"name,omitempty"`
			Input map[string]any `json:"input,omitempty"`
		} `json:"content"`
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(respBody, &anthropicResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	// Extract text content and tool_use blocks.
	var textContent string
	var toolCalls []ToolCall
	for _, block := range anthropicResp.Content {
		switch block.Type {
		case "text":
			textContent += block.Text
		case "tool_use":
			// Serialize Input back to JSON string for our unified ToolCall format.
			argsBytes, _ := json.Marshal(block.Input)
			toolCalls = append(toolCalls, ToolCall{
				ID:        block.ID,
				Name:      block.Name,
				Arguments: string(argsBytes),
			})
		}
	}

	if textContent == "" && len(toolCalls) == 0 {
		return nil, fmt.Errorf("no text content or tool calls in response")
	}

	return &ChatResponse{
		Content:      textContent,
		Model:        anthropicResp.Model,
		InputTokens:  anthropicResp.Usage.InputTokens,
		OutputTokens: anthropicResp.Usage.OutputTokens,
		FinishReason: anthropicResp.StopReason,
		Latency:      time.Since(start),
		ToolCalls:    toolCalls,
	}, nil
}

// StreamChat implements StreamingProvider.StreamChat for Anthropic.
func (p *AnthropicProvider) StreamChat(ctx context.Context, req *ChatRequest, onDelta func(delta string)) (*ChatResponse, error) {
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

	var systemPrompt string
	var messages []map[string]string
	for _, msg := range req.Messages {
		if msg.Role == "system" {
			if systemPrompt != "" {
				systemPrompt += "\n\n"
			}
			systemPrompt += msg.Content
			continue
		}
		messages = append(messages, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}

	anthropicReq := map[string]any{
		"model":       model,
		"max_tokens":  maxTokens,
		"temperature": temperature,
		"messages":    messages,
		"stream":      true,
	}
	if systemPrompt != "" {
		anthropicReq["system"] = systemPrompt
	}

	body, err := json.Marshal(anthropicReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpClient := &http.Client{}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.config.BaseURL+"/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.config.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("anthropic error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var fullContent strings.Builder
	var finalModel string
	var inputTokens, outputTokens int
	var stopReason string

	scanner := bufio.NewScanner(resp.Body)
	// Increase buffer for potentially large SSE lines.
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")

		var event struct {
			Type  string `json:"type"`
			Delta struct {
				Type       string `json:"type"`
				Text       string `json:"text"`
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
			Message struct {
				Model string `json:"model"`
				Usage struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Usage struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}

		switch event.Type {
		case "message_start":
			finalModel = event.Message.Model
			inputTokens = event.Message.Usage.InputTokens
		case "content_block_delta":
			if event.Delta.Type == "text_delta" && event.Delta.Text != "" {
				fullContent.WriteString(event.Delta.Text)
				onDelta(event.Delta.Text)
			}
		case "message_delta":
			outputTokens = event.Usage.OutputTokens
			stopReason = event.Delta.StopReason
		case "message_stop":
			// Stream complete.
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan anthropic stream: %w", err)
	}

	return &ChatResponse{
		Content:      fullContent.String(),
		Model:        finalModel,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		FinishReason: stopReason,
		Latency:      time.Since(start),
	}, nil
}

// AnalyzeEvents implements Provider.AnalyzeEvents for Anthropic.
func (p *AnthropicProvider) AnalyzeEvents(ctx context.Context, events []map[string]any) (*SecurityAnalysis, error) {
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

// ExplainEvent implements Provider.ExplainEvent for Anthropic.
func (p *AnthropicProvider) ExplainEvent(ctx context.Context, event map[string]any) (*EventExplanation, error) {
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
		MaxTokens: 1024,
	})
	if err != nil {
		return nil, err
	}

	return ParseEventExplanation(resp.Content), nil
}

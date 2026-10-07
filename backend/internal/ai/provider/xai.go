package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// XAIProvider implements the Provider interface for xAI (Grok).
// xAI uses an OpenAI-compatible API at https://api.x.ai/v1.
type XAIProvider struct {
	config     Config
	httpClient *http.Client
}

// NewXAIProvider creates a new xAI provider.
func NewXAIProvider(cfg Config) *XAIProvider {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.x.ai/v1"
	}
	if cfg.Model == "" {
		cfg.Model = "grok-3-mini"
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 4096
	}
	if cfg.Temperature == 0 {
		cfg.Temperature = 0.7
	}

	return &XAIProvider{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

func (p *XAIProvider) Name() string {
	return "xai"
}

// Chat implements Provider.Chat for xAI (OpenAI-compatible API).
func (p *XAIProvider) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
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

	xaiReq := map[string]any{
		"model":       model,
		"messages":    req.Messages,
		"max_tokens":  maxTokens,
		"temperature": temperature,
	}

	body, err := json.Marshal(xaiReq)
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
		return nil, fmt.Errorf("xai error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var xaiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
		Model string `json:"model"`
	}

	if err := json.Unmarshal(respBody, &xaiResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if len(xaiResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	return &ChatResponse{
		Content:      xaiResp.Choices[0].Message.Content,
		Model:        xaiResp.Model,
		InputTokens:  xaiResp.Usage.PromptTokens,
		OutputTokens: xaiResp.Usage.CompletionTokens,
		FinishReason: xaiResp.Choices[0].FinishReason,
		Latency:      time.Since(start),
	}, nil
}

// AnalyzeEvents implements Provider.AnalyzeEvents for xAI.
func (p *XAIProvider) AnalyzeEvents(ctx context.Context, events []map[string]any) (*SecurityAnalysis, error) {
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		return nil, fmt.Errorf("marshal events: %w", err)
	}

	resp, err := p.Chat(ctx, &ChatRequest{
		Messages: []Message{
			{Role: "system", Content: SecurityAnalysisSystemPrompt},
			{Role: "user", Content: fmt.Sprintf("Analyze these security events and provide a structured threat assessment:\n\n%s", string(eventsJSON))},
		},
	})
	if err != nil {
		return nil, err
	}

	return ParseSecurityAnalysis(resp.Content), nil
}

// ExplainEvent implements Provider.ExplainEvent for xAI.
func (p *XAIProvider) ExplainEvent(ctx context.Context, event map[string]any) (*EventExplanation, error) {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("marshal event: %w", err)
	}

	resp, err := p.Chat(ctx, &ChatRequest{
		Messages: []Message{
			{Role: "system", Content: EventExplanationSystemPrompt},
			{Role: "user", Content: fmt.Sprintf("Explain this security event in simple terms:\n\n%s", string(eventJSON))},
		},
		MaxTokens: 1024,
	})
	if err != nil {
		return nil, err
	}

	return ParseEventExplanation(resp.Content), nil
}

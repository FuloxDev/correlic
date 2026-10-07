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

// GeminiProvider implements the Provider interface for Google Gemini.
type GeminiProvider struct {
	config     Config
	httpClient *http.Client
}

// NewGeminiProvider creates a new Google Gemini provider.
func NewGeminiProvider(cfg Config) *GeminiProvider {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://generativelanguage.googleapis.com/v1beta"
	}
	if cfg.Model == "" {
		cfg.Model = "gemini-2.0-flash-lite" // Free tier model
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 4096
	}
	if cfg.Temperature == 0 {
		cfg.Temperature = 0.7
	}

	return &GeminiProvider{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (p *GeminiProvider) Name() string {
	return "gemini"
}

// Chat implements Provider.Chat for Gemini.
func (p *GeminiProvider) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	start := time.Now()

	model := p.config.Model
	if req.Model != "" {
		model = req.Model
	}

	// Convert messages to Gemini format
	contents := make([]map[string]any, 0, len(req.Messages))
	systemInstruction := ""

	for _, msg := range req.Messages {
		if msg.Role == "system" {
			systemInstruction = msg.Content
			continue
		}

		role := msg.Role
		if role == "assistant" {
			role = "model"
		}

		contents = append(contents, map[string]any{
			"role": role,
			"parts": []map[string]any{
				{"text": msg.Content},
			},
		})
	}

	// Build Gemini request
	geminiReq := map[string]any{
		"contents": contents,
		"generationConfig": map[string]any{
			"maxOutputTokens": p.config.MaxTokens,
			"temperature":     p.config.Temperature,
		},
	}

	if systemInstruction != "" {
		geminiReq["systemInstruction"] = map[string]any{
			"parts": []map[string]any{
				{"text": systemInstruction},
			},
		}
	}

	body, err := json.Marshal(geminiReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// Gemini uses API key in URL
	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", p.config.BaseURL, model, p.config.APIKey)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

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
		return nil, fmt.Errorf("gemini error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var geminiResp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		UsageMetadata struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
		} `json:"usageMetadata"`
	}

	if err := json.Unmarshal(respBody, &geminiResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if len(geminiResp.Candidates) == 0 {
		return nil, fmt.Errorf("no candidates in response")
	}

	content := ""
	for _, part := range geminiResp.Candidates[0].Content.Parts {
		content += part.Text
	}

	return &ChatResponse{
		Content:      content,
		Model:        model,
		InputTokens:  geminiResp.UsageMetadata.PromptTokenCount,
		OutputTokens: geminiResp.UsageMetadata.CandidatesTokenCount,
		FinishReason: geminiResp.Candidates[0].FinishReason,
		Latency:      time.Since(start),
	}, nil
}

// AnalyzeEvents implements Provider.AnalyzeEvents for Gemini.
func (p *GeminiProvider) AnalyzeEvents(ctx context.Context, events []map[string]any) (*SecurityAnalysis, error) {
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

// ExplainEvent implements Provider.ExplainEvent for Gemini.
func (p *GeminiProvider) ExplainEvent(ctx context.Context, event map[string]any) (*EventExplanation, error) {
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

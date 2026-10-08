package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// SlackSender delivers notifications via Slack incoming webhooks using Block Kit.
type SlackSender struct {
	client *http.Client
}

// NewSlackSender creates a Slack sender with a 10-second timeout, no redirect
// following and an SSRF-guarded dialer (see newOutboundClient).
func NewSlackSender() *SlackSender {
	return &SlackSender{client: newOutboundClient()}
}

// Send delivers a payload to a Slack incoming webhook as Block Kit blocks.
func (s *SlackSender) Send(ctx context.Context, endpoint Endpoint, payload map[string]any) error {
	webhookURL, _ := endpoint.Config["webhook_url"].(string)
	if webhookURL == "" {
		return fmt.Errorf("slack endpoint has no webhook_url configured")
	}
	// Re-validate at send time: the DNS answer may have changed since the
	// endpoint was configured.
	if err := validateOutboundURL(ctx, webhookURL); err != nil {
		return fmt.Errorf("slack webhook_url rejected: %w", err)
	}

	slackPayload := buildSlackBlocks(payload)
	body, err := json.Marshal(slackPayload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("slack returned status %d: %w", resp.StatusCode, &HTTPStatusError{Status: resp.StatusCode})
}

// buildSlackBlocks constructs a Slack Block Kit message from the webhook payload.
func buildSlackBlocks(payload map[string]any) map[string]any {
	inc, _ := payload["incident"].(map[string]any)
	eventType, _ := payload["event"].(string)

	severity, _ := inc["severity"].(string)
	title, _ := inc["title"].(string)
	summary, _ := inc["summary"].(string)
	hostID, _ := inc["host_id"].(string)
	incID, _ := inc["id"].(string)

	emoji := severityEmoji(severity)
	header := fmt.Sprintf("%s *%s* — %s", emoji, strings.ToUpper(severity), title)
	if eventType == "incident.escalated" {
		header = fmt.Sprintf("%s *ESCALATED to %s* — %s", emoji, strings.ToUpper(severity), title)
	}

	// MITRE techniques
	mitre := ""
	if techniques, ok := inc["mitre_techniques"].([]any); ok && len(techniques) > 0 {
		var parts []string
		for _, t := range techniques {
			if s, ok := t.(string); ok {
				parts = append(parts, "`"+s+"`")
			}
		}
		mitre = strings.Join(parts, " ")
	}

	contextElements := []map[string]any{
		{"type": "mrkdwn", "text": fmt.Sprintf("*Host:* %s", hostID)},
		{"type": "mrkdwn", "text": fmt.Sprintf("*Incident:* %s", incID)},
	}
	if mitre != "" {
		contextElements = append(contextElements, map[string]any{
			"type": "mrkdwn", "text": fmt.Sprintf("*MITRE:* %s", mitre),
		})
	}

	blocks := []map[string]any{
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": header}},
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": summary}},
		{"type": "context", "elements": contextElements},
	}

	return map[string]any{"blocks": blocks}
}

func severityEmoji(severity string) string {
	switch severity {
	case "critical":
		return ":red_circle:"
	case "high":
		return ":large_orange_circle:"
	case "medium":
		return ":large_yellow_circle:"
	default:
		return ":white_circle:"
	}
}

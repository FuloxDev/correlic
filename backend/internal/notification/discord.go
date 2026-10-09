package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DiscordSender delivers notifications to a Discord channel webhook as one
// embed per incident. Only https://discord.com/api/webhooks/... and the
// discordapp.com alias are accepted (see isDiscordWebhookURL).
type DiscordSender struct {
	client       *http.Client
	dashboardURL string
}

// NewDiscordSender creates a Discord sender with the shared SSRF-guarded
// outbound client (10 s timeout, no redirects).
func NewDiscordSender() *DiscordSender {
	return &DiscordSender{client: newOutboundClient()}
}

// WithDashboardURL sets the dashboard base URL used for the embed link.
func (s *DiscordSender) WithDashboardURL(base string) *DiscordSender {
	s.dashboardURL = strings.TrimRight(base, "/")
	return s
}

// discordColors are the embed side-bar colours per severity (decimal RGB).
var discordColors = map[string]int{
	"critical": 0xE02424, // red
	"high":     0xF97316, // orange
	"medium":   0xEAB308, // yellow
	"low":      0x22C55E, // green
}

// Send posts the incident as an embed.
func (s *DiscordSender) Send(ctx context.Context, endpoint Endpoint, payload map[string]any) error {
	webhookURL := getString(endpoint.Config, "webhook_url")
	if webhookURL == "" {
		return fmt.Errorf("discord endpoint has no webhook_url configured")
	}
	// Re-validate at send time: the endpoint may predate the host allowlist
	// and the DNS answer may have changed since it was configured.
	if err := validateOutboundURL(ctx, webhookURL); err != nil {
		return fmt.Errorf("discord webhook_url rejected: %w", err)
	}
	if u, err := url.Parse(webhookURL); err != nil {
		return fmt.Errorf("discord webhook_url rejected: %w", ErrInvalidURL)
	} else if err := isDiscordWebhookURL(u); err != nil {
		return fmt.Errorf("discord webhook_url rejected: %w: %v", ErrInvalidURL, err)
	}

	body, err := json.Marshal(buildDiscordMessage(payload, s.dashboardURL))
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Correlic-Webhook/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("discord request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))

	// Discord answers 204 No Content; accept any 2xx.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("discord returned status %d: %w", resp.StatusCode, &HTTPStatusError{Status: resp.StatusCode})
}

// buildDiscordMessage renders the webhook payload as a Discord embed.
func buildDiscordMessage(payload map[string]any, dashboardURL string) map[string]any {
	f := parseIncidentFields(payload)
	color, ok := discordColors[f.Severity]
	if !ok {
		color = 0x94A3B8 // slate for unknown severities
	}

	fields := []map[string]any{
		{"name": "Severity", "value": strings.ToUpper(f.Severity), "inline": true},
		{"name": "Host", "value": orDash(f.HostID), "inline": true},
		{"name": "Findings", "value": fmt.Sprintf("%d", f.FindingCount), "inline": true},
	}
	if rule := ruleLabel(f); rule != "" {
		fields = append(fields, map[string]any{"name": "Rule", "value": rule, "inline": false})
	}
	if len(f.MITRE) > 0 {
		fields = append(fields, map[string]any{"name": "MITRE ATT&CK", "value": strings.Join(f.MITRE, ", "), "inline": false})
	}
	fields = append(fields, map[string]any{"name": "Incident", "value": "`" + orDash(f.ID) + "`", "inline": false})

	embed := map[string]any{
		"title":       truncate(f.headline(), 256),
		"description": truncate(f.Summary, 2048),
		"color":       color,
		"fields":      fields,
		"footer":      map[string]any{"text": "Correlic"},
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}
	if link := incidentURL(dashboardURL, f.ID); link != "" {
		embed["url"] = link
	}
	return map[string]any{
		"username": "Correlic",
		// No @everyone/@here or user mentions can be injected through incident
		// text: mentions are disabled for the whole message.
		"allowed_mentions": map[string]any{"parse": []string{}},
		"embeds":           []map[string]any{embed},
	}
}

// ruleLabel names the detection rules behind the incident: the detection
// ids when the payload carries them, else the incident category.
func ruleLabel(f incidentFields) string {
	if len(f.DetectionIDs) > 0 {
		return strings.Join(f.DetectionIDs, ", ")
	}
	return f.Category
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

func pathEscape(s string) string {
	return url.PathEscape(s)
}

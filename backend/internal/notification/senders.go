package notification

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/correlic/correlic-backend/internal/secrets"
)

// ErrUnsupportedChannel is returned by Senders.Send for a channel type no
// sender handles.
var ErrUnsupportedChannel = errors.New("unsupported channel type")

// SenderOptions configures the senders shared by the delivery worker and
// the endpoint test handler.
type SenderOptions struct {
	// Cipher opens sealed secrets (SMTP passwords, webhook HMAC secrets).
	// Nil is allowed: endpoints without sealed secrets still work, deliveries
	// that need one fail with secrets.ErrNoCipher.
	Cipher *secrets.Cipher
	// DashboardURL is the public base URL of the dashboard (FRONTEND_URL).
	// When set, Discord embeds and emails link to /incidents/<id>.
	DashboardURL string
}

// Senders holds one sender per channel type and dispatches by
// Endpoint.ChannelType.
type Senders struct {
	Webhook *WebhookSender
	Slack   *SlackSender
	Discord *DiscordSender
	Email   *EmailSender
	Syslog  *SyslogSender
}

// NewSenders builds the full sender set.
func NewSenders(opts SenderOptions) *Senders {
	base := strings.TrimRight(strings.TrimSpace(opts.DashboardURL), "/")
	return &Senders{
		Webhook: NewWebhookSender().WithCipher(opts.Cipher),
		Slack:   NewSlackSender(),
		Discord: NewDiscordSender().WithDashboardURL(base),
		Email:   NewEmailSender().WithCipher(opts.Cipher).WithDashboardURL(base),
		Syslog:  NewSyslogSender(),
	}
}

// Send delivers payload through the sender for endpoint.ChannelType.
func (s *Senders) Send(ctx context.Context, endpoint Endpoint, payload map[string]any) error {
	if s == nil {
		return ErrUnsupportedChannel
	}
	switch endpoint.ChannelType {
	case ChannelWebhook:
		return s.Webhook.Send(ctx, endpoint, payload)
	case ChannelSlack:
		return s.Slack.Send(ctx, endpoint, payload)
	case ChannelDiscord:
		return s.Discord.Send(ctx, endpoint, payload)
	case ChannelEmail:
		return s.Email.Send(ctx, endpoint, payload)
	case ChannelSyslog:
		return s.Syslog.Send(ctx, endpoint, payload)
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedChannel, endpoint.ChannelType)
	}
}

// incidentFields is the subset of the delivery payload every channel renders.
type incidentFields struct {
	Event        string
	ID           string
	Severity     string
	Title        string
	Summary      string
	HostID       string
	Category     string
	MITRE        []string
	DetectionIDs []string
	FindingCount int
	Confidence   float64
	StartedAt    string
}

// parseIncidentFields reads the webhook payload (see buildWebhookPayload).
func parseIncidentFields(payload map[string]any) incidentFields {
	inc, _ := payload["incident"].(map[string]any)
	f := incidentFields{
		Event:    getString(payload, "event"),
		ID:       getString(inc, "id"),
		Severity: strings.ToLower(getString(inc, "severity")),
		Title:    getString(inc, "title"),
		Summary:  getString(inc, "summary"),
		HostID:   getString(inc, "host_id"),
		Category: getString(inc, "category"),
	}
	f.StartedAt = getString(inc, "started_at")
	if n, ok := getInt(inc, "finding_count"); ok {
		f.FindingCount = n
	}
	if c, ok := inc["confidence"].(float64); ok {
		f.Confidence = c
	}
	f.MITRE = anyStrings(inc["mitre_techniques"])
	f.DetectionIDs = anyStrings(inc["detection_ids"])
	if f.Severity == "" {
		f.Severity = "medium"
	}
	return f
}

// anyStrings flattens a []any or []string of strings.
func anyStrings(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// headline is the one-line title shared by Discord, email and syslog.
func (f incidentFields) headline() string {
	sev := strings.ToUpper(f.Severity)
	switch f.Event {
	case "incident.escalated":
		return fmt.Sprintf("ESCALATED to %s: %s", sev, f.Title)
	case "test":
		return fmt.Sprintf("TEST (%s): %s", sev, f.Title)
	default:
		return fmt.Sprintf("%s: %s", sev, f.Title)
	}
}

// incidentURL returns the dashboard link for the incident, or "" without a
// dashboard base URL.
func incidentURL(base, incidentID string) string {
	if base == "" || incidentID == "" {
		return ""
	}
	return base + "/incidents/" + pathEscape(incidentID)
}

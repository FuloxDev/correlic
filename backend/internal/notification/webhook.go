package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// WebhookSender delivers notifications via HTTP POST with HMAC-SHA256 signing.
type WebhookSender struct {
	client *http.Client
}

// NewWebhookSender creates a sender with a 10-second timeout, no redirect
// following and an SSRF-guarded dialer (see newOutboundClient).
func NewWebhookSender() *WebhookSender {
	return &WebhookSender{client: newOutboundClient()}
}

// Send delivers a payload to a webhook endpoint.
func (s *WebhookSender) Send(ctx context.Context, endpoint Endpoint, payload map[string]any) error {
	urlStr, _ := endpoint.Config["url"].(string)
	if urlStr == "" {
		return fmt.Errorf("webhook endpoint has no URL configured")
	}
	// Re-validate at send time: the DNS answer may have changed since the
	// endpoint was configured.
	if err := validateOutboundURL(ctx, urlStr); err != nil {
		return fmt.Errorf("webhook url rejected: %w", err)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Correlic-Webhook/1.0")

	// HMAC-SHA256 signature if secret is configured
	if secret, _ := endpoint.Config["secret"].(string); secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Correlic-Signature", "sha256="+sig)
	}

	// Custom headers (framing/routing headers are dropped).
	if headers, ok := endpoint.Config["headers"].(map[string]any); ok {
		applyCustomHeaders(req, headers)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("webhook returned status %d: %w", resp.StatusCode, &HTTPStatusError{Status: resp.StatusCode})
}

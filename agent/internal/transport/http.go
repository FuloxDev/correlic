package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/model"
)

// backendErrorResponse is the response from the backend when an error occurs.
type backendErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// BackendError is the error returned when the backend rejects a request.
type BackendError struct {
	Status int
	Code   string
	Msg    string
}

// Error returns a string representation of the error.
func (e *BackendError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("backend rejected request: status=%d code=%s error=%s", e.Status, e.Code, e.Msg)
	}
	if e.Msg != "" {
		return fmt.Sprintf("backend rejected request: status=%d error=%s", e.Status, e.Msg)
	}
	return fmt.Sprintf("backend rejected request: status=%d", e.Status)
}

// HTTPTransport is the transport for the agent.
// KeyValidationResult is the response from {correlic_api_url}/keys/verify (optional remote key server).
type KeyValidationResult struct {
	Valid     bool       `json:"valid"`
	UserID    string     `json:"userId,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Error     string     `json:"error,omitempty"`
	Code      string     `json:"code,omitempty"`
}

type HTTPTransport struct {
	client         *http.Client
	backendURL     string
	telemetryURL   string
	apiKey         string
	correlicAPIURL string // optional remote key server; empty disables ValidateKey
}

// ValidateKey validates the API key against the optional remote key server.
func (t *HTTPTransport) ValidateKey(ctx context.Context) (*KeyValidationResult, error) {
	if t.correlicAPIURL == "" {
		return nil, fmt.Errorf("correlic_api_url not configured")
	}

	reqURL := fmt.Sprintf("%s/keys/verify", t.correlicAPIURL)
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("x-api-key", t.apiKey)

	// Use a plain HTTP client (no mTLS) for the remote key server
	plainClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := plainClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("key server unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 401 {
		var result KeyValidationResult
		_ = json.Unmarshal(body, &result)
		result.Valid = false
		if result.Error == "" {
			result.Error = "invalid or expired API key"
		}
		return &result, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status %d from key server", resp.StatusCode)
	}

	var result KeyValidationResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &result, nil
}

func tlsConfigFromFiles(caFile string, clientCertFile string, clientKeyFile string) (*tls.Config, error) {
	// keep defaults (system roots, no client cert) if nothing is configured.
	if caFile == "" && clientCertFile == "" && clientKeyFile == "" {
		return nil, nil
	}
	if (clientCertFile != "" && clientKeyFile == "") || (clientCertFile == "" && clientKeyFile != "") {
		return nil, fmt.Errorf("tls client cert and key must be set together")
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read tls ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(pem); !ok {
			return nil, fmt.Errorf("parse tls ca file: no certs found")
		}
		cfg.RootCAs = pool
	}

	if clientCertFile != "" && clientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// NewHTTPTransport creates a new HTTPTransport with the given API key and backend URL.
func NewHTTPTransport(apiKey string, backendURL string) *HTTPTransport {
	return NewHTTPTransportWithTelemetryURL(apiKey, backendURL, "")
}

// NewHTTPTransportWithTelemetryURL creates a new HTTPTransport with the given API key, backend URL, and telemetry URL.
func NewHTTPTransportWithTelemetryURL(apiKey string, backendURL string, telemetryURL string) *HTTPTransport {
	t, _ := NewHTTPTransportWithTelemetryURLAndTLS(apiKey, backendURL, telemetryURL, "", "", "")
	return t
}

// NewHTTPTransportWithTelemetryURLAndTLS creates a new HTTPTransport with the given API key, backend URL, telemetry URL,
// and optional TLS settings (CA + client certificate for mTLS).
func NewHTTPTransportWithTelemetryURLAndTLS(apiKey string, backendURL string, telemetryURL string, tlsCAFile string, tlsClientCertFile string, tlsClientKeyFile string) (*HTTPTransport, error) {
	if telemetryURL == "" {
		telemetryURL = backendURL
	}

	tlsCfg, err := tlsConfigFromFiles(tlsCAFile, tlsClientCertFile, tlsClientKeyFile)
	if err != nil {
		return nil, err
	}
	rt := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 3 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 3 * time.Second,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
	}
	if tlsCfg != nil {
		rt.TLSClientConfig = tlsCfg
	}

	return &HTTPTransport{
		backendURL:   backendURL,
		telemetryURL: telemetryURL,
		apiKey:       apiKey,
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: rt,
		},
	}, nil
}

// SetCorrelicAPIURL sets the optional remote key server URL used by ValidateKey.
func (t *HTTPTransport) SetCorrelicAPIURL(url string) {
	t.correlicAPIURL = url
}

// SendHeartbeat sends a heartbeat to the backend.
func (t *HTTPTransport) SendHeartbeat(
	ctx context.Context,
	hb model.Heartbeat,
) error {
	return t.sendJSON(ctx, t.backendURL, "/heartbeat", hb, "heartbeat")
}

// SendTelemetryBatch sends a batch of telemetry events to the backend.
func (t *HTTPTransport) SendTelemetryBatch(
	ctx context.Context,
	batch model.TelemetryBatch,
) error {
	return t.sendJSON(ctx, t.telemetryURL, "/telemetry", batch, "telemetry")
}

// SendCanonicalEvents POSTs canonical event(s) to telemetry_url/ingest/events (single or array).
func (t *HTTPTransport) SendCanonicalEvents(ctx context.Context, events []event.Event) error {
	if len(events) == 0 {
		return nil
	}
	var payload any = events
	if len(events) == 1 {
		payload = events[0]
	}
	return t.sendJSON(ctx, t.telemetryURL, "/ingest/events", payload, "ingest/events")
}

func (t *HTTPTransport) ListApprovals(ctx context.Context, status string, agentID string, limit int) ([]model.Approval, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 2000 {
		limit = 2000
	}
	q := url.Values{}
	if strings.TrimSpace(status) != "" {
		q.Set("status", strings.TrimSpace(status))
	}
	if strings.TrimSpace(agentID) != "" {
		q.Set("agent_id", strings.TrimSpace(agentID))
	}
	q.Set("limit", strconv.Itoa(limit))

	var out []model.Approval
	err := t.getJSON(ctx, t.telemetryURL, "/approvals?"+q.Encode(), &out, "approvals")
	return out, err
}

func (t *HTTPTransport) DecideApproval(ctx context.Context, approvalID string, status string, reason string) error {
	approvalID = strings.TrimSpace(approvalID)
	status = strings.TrimSpace(strings.ToLower(status))
	if approvalID == "" {
		return fmt.Errorf("approval_id required")
	}
	if status != "approved" && status != "rejected" {
		return fmt.Errorf("invalid status")
	}
	req := map[string]any{
		"status": status,
		"reason": strings.TrimSpace(reason),
	}
	return t.sendJSON(ctx, t.telemetryURL, "/approvals/"+approvalID, req, "approval_decision")
}

func (t *HTTPTransport) CheckApproval(ctx context.Context, agentID string, kind string, subject map[string]any) (*model.ApprovalCheckResponse, error) {
	agentID = strings.TrimSpace(agentID)
	kind = strings.TrimSpace(kind)
	if agentID == "" || kind == "" {
		return nil, fmt.Errorf("agent_id and kind required")
	}
	req := map[string]any{
		"agent_id": agentID,
		"kind":     kind,
		"subject":  subject,
	}
	var out model.ApprovalCheckResponse
	if err := t.postJSON(ctx, t.telemetryURL, "/approvals/check", req, &out, "approval_check"); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetAIPatterns fetches the list of AI agent patterns from the backend.
func (t *HTTPTransport) GetAIPatterns(ctx context.Context) ([]string, error) {
	var resp struct {
		Patterns []string `json:"patterns"`
	}
	if err := t.getJSON(ctx, t.backendURL, "/api/v1/ai/patterns", &resp, "get_patterns"); err != nil {
		return nil, err
	}
	return resp.Patterns, nil
}

// sendJSON sends a JSON payload to the backend.
func (t *HTTPTransport) sendJSON(ctx context.Context, baseURL string, path string, payload any, kind string) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// create a new request with the given context, method, URL, and body.
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		baseURL+path,
		bytes.NewReader(data),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(t.apiKey) != "" {
		req.Header.Set("Authorization", t.apiKey)
	}

	// send the request to the backend.
	resp, err := t.client.Do(req)
	if err != nil {
		slog.Warn(kind+" request failed", "url", baseURL+path, "error", err)
		return err
	}
	// close the response body.
	defer resp.Body.Close()

	// if the response status code is greater than or equal to 300, parse the backend error.
	if resp.StatusCode >= 300 {
		return parseBackendError(resp, kind)
	}

	slog.Debug(kind+" delivered", "status", resp.StatusCode)
	return nil
}

func (t *HTTPTransport) postJSON(ctx context.Context, baseURL string, path string, payload any, out any, kind string) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(t.apiKey) != "" {
		req.Header.Set("Authorization", t.apiKey)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return parseBackendError(resp, kind)
	}
	if out != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if len(body) == 0 {
			return nil
		}
		if err := json.Unmarshal(body, out); err != nil {
			return err
		}
	}
	slog.Debug(kind+" delivered", "status", resp.StatusCode)
	return nil
}

func (t *HTTPTransport) getJSON(ctx context.Context, baseURL string, path string, out any, kind string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
	if err != nil {
		return err
	}
	if strings.TrimSpace(t.apiKey) != "" {
		req.Header.Set("Authorization", t.apiKey)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return parseBackendError(resp, kind)
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}

// parseBackendError parses the backend error response.
func parseBackendError(resp *http.Response, kind string) error {
	// limit the response body to 1MiB.
	limited := io.LimitReader(resp.Body, 1<<20) // 1MiB
	// read the response body.
	body, _ := io.ReadAll(limited)

	var berr backendErrorResponse
	if err := json.Unmarshal(body, &berr); err == nil && (berr.Error != "" || berr.Code != "") {
		// Do not log secrets; backend should not include them in errors.
		slog.Warn(kind+" rejected by backend",
			"status", resp.StatusCode,
			"code", berr.Code,
			"error", berr.Error,
		)
		return &BackendError{Status: resp.StatusCode, Code: berr.Code, Msg: berr.Error}
	}

	// Fallback: keep message generic, but include status for debugging.
	slog.Warn(kind+" rejected by backend", "status", resp.StatusCode)
	return &BackendError{Status: resp.StatusCode, Msg: string(bytes.TrimSpace(body))}
}

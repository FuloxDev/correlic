package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// CorrelicClient talks to the Correlic API plane on behalf of the MCP tools.
// Every request carries the configured API key; the key's org and role
// decide what the tools can see and do.
type CorrelicClient struct {
	BaseURL       string
	Authorization string
	HTTP          *http.Client
}

// TLSOptions configures the client certificate and CA used for the API
// plane, which requires mTLS.
type TLSOptions struct {
	CAFile         string
	ClientCertFile string
	ClientKeyFile  string
}

// NewClient builds a client for baseURL. apiKey is sent as
// "Authorization: Bearer <key>" (a value that already carries a scheme is
// sent unchanged). TLS options may be empty when the API is reachable
// without mTLS (for example through a proxy).
func NewClient(baseURL, apiKey string, tlsOpts TLSOptions) (*CorrelicClient, error) {
	auth := strings.TrimSpace(apiKey)
	if auth != "" && !strings.Contains(auth, " ") {
		auth = "Bearer " + auth
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if tlsOpts.CAFile != "" {
		pem, err := os.ReadFile(tlsOpts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s holds no certificates", tlsOpts.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if tlsOpts.ClientCertFile != "" || tlsOpts.ClientKeyFile != "" {
		if tlsOpts.ClientCertFile == "" || tlsOpts.ClientKeyFile == "" {
			return nil, errors.New("client certificate and key must be set together")
		}
		cert, err := tls.LoadX509KeyPair(tlsOpts.ClientCertFile, tlsOpts.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	transport.TLSClientConfig = tlsCfg
	return &CorrelicClient{
		BaseURL:       strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		Authorization: auth,
		HTTP:          &http.Client{Timeout: 15 * time.Second, Transport: transport},
	}, nil
}

// APIError is a non-2xx answer from the API plane.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("correlic api error %d: %s", e.Status, e.Message)
}

// DoGET performs a GET and returns the response body.
func (c *CorrelicClient) DoGET(ctx context.Context, path string, q url.Values) ([]byte, error) {
	return c.Do(ctx, http.MethodGet, path, q, nil)
}

// Do performs a request with an optional JSON body and returns the response
// body. A non-2xx status is returned as *APIError whose message is the
// server's error text (JSON `{"error": ...}` bodies are unwrapped).
func (c *CorrelicClient) Do(ctx context.Context, method, path string, q url.Values, body any) ([]byte, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://localhost:8080"
	}
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.Authorization) != "" {
		req.Header.Set("Authorization", c.Authorization)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{Status: resp.StatusCode, Message: errorMessage(out, resp.Status)}
	}
	return out, nil
}

// errorMessage extracts a readable message from an error body.
func errorMessage(body []byte, fallback string) string {
	msg := strings.TrimSpace(string(body))
	var obj struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &obj) == nil {
		if obj.Error != "" {
			msg = obj.Error
		} else if obj.Message != "" {
			msg = obj.Message
		}
	}
	if msg == "" {
		msg = fallback
	}
	if len(msg) > 512 {
		msg = msg[:512] + "…"
	}
	return msg
}

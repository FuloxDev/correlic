package mcp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CorrelicClient struct {
	BaseURL       string
	Authorization string
	HTTP          *http.Client
}

func (c *CorrelicClient) DoGET(ctx context.Context, path string, q url.Values) ([]byte, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "http://localhost:8080"
	}
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.Authorization) != "" {
		req.Header.Set("Authorization", c.Authorization)
	}
	req.Header.Set("Accept", "application/json")

	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("correlic api error %s: %s", resp.Status, msg)
	}
	return body, nil
}

package enforcer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/correlic/correlic-agent/internal/health"
	"github.com/correlic/correlic-agent/internal/transport"
)

const syncComponent = "block_rule_sync"

type RuleSync struct {
	enforcer    *Enforcer
	baseURL     string // e.g. "https://localhost:8081"
	apiKey      string
	client      *http.Client
	interval    time.Duration
	lastVersion string
	cachePath   string // local file cache for offline boot
	logger      *slog.Logger
}

type syncResponse struct {
	Version string      `json:"version"`
	Rules   []BlockRule `json:"rules"`
}

func NewRuleSync(enf *Enforcer, baseURL, apiKey string, interval time.Duration, logger *slog.Logger, tlsCfg *tls.Config) *RuleSync {
	// Determine cache path
	homeDir, _ := os.UserHomeDir()
	cachePath := filepath.Join(homeDir, ".correlic", "block_rules_cache.json")

	if tlsCfg == nil {
		// No client certificate configured: still verify the server against
		// the system roots rather than accepting any certificate.
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	return &RuleSync{
		enforcer: enf,
		baseURL:  baseURL,
		apiKey:   apiKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
		interval:  interval,
		cachePath: cachePath,
		logger:    logger.With("component", "block_rule_sync"),
	}
}

func (s *RuleSync) Start(ctx context.Context) {
	// Load from local cache first (offline boot support)
	s.loadLocalCache()

	// Initial fetch
	s.fetchAndUpdate(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.fetchAndUpdate(ctx)
		}
	}
}

func (s *RuleSync) fetchAndUpdate(ctx context.Context) {
	rules, version, err := s.fetchRules(ctx)
	if err != nil {
		// Keep the cached rules; surface the failure at WARN once per minute.
		if transport.IsAuthError(err) {
			health.ReportAuthRejected(syncComponent, transport.StatusOf(err), err)
		} else {
			health.ReportFailure(syncComponent, transport.StatusOf(err), err, 0)
		}
		s.logger.Debug("block rule sync failed, using cached rules", "error", err)
		return
	}
	health.ReportOK(syncComponent)
	if version != "" && version == s.lastVersion {
		return // no changes
	}
	s.enforcer.UpdateRules(rules)
	s.lastVersion = version
	s.saveLocalCache(rules, version)
	s.logger.Info("block rules synced", "version", shortVersion(version), "count", len(rules))
}

func (s *RuleSync) fetchRules(ctx context.Context) ([]BlockRule, string, error) {
	url := s.baseURL + "/agent/block-rules"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	if s.lastVersion != "" {
		req.Header.Set("If-None-Match", s.lastVersion)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch block rules: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, s.lastVersion, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, "", &transport.BackendError{Status: resp.StatusCode, Msg: string(body)}
	}

	var sr syncResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, "", fmt.Errorf("decode block rules: %w", err)
	}
	return sr.Rules, sr.Version, nil
}

type cacheFile struct {
	Version string      `json:"version"`
	Rules   []BlockRule `json:"rules"`
	SavedAt time.Time   `json:"saved_at"`
}

func (s *RuleSync) loadLocalCache() {
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		return // no cache file — first boot
	}
	var cf cacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		s.logger.Warn("corrupt block rules cache, ignoring", "error", err)
		return
	}
	s.enforcer.UpdateRules(cf.Rules)
	s.lastVersion = cf.Version
	s.logger.Info("loaded block rules from cache", "count", len(cf.Rules), "saved_at", cf.SavedAt)
}

func (s *RuleSync) saveLocalCache(rules []BlockRule, version string) {
	cf := cacheFile{
		Version: version,
		Rules:   rules,
		SavedAt: time.Now(),
	}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return
	}
	// Ensure directory exists
	os.MkdirAll(filepath.Dir(s.cachePath), 0700)
	os.WriteFile(s.cachePath, data, 0600)
}

// shortVersion abbreviates a rule-set version for logs.
func shortVersion(v string) string {
	if len(v) > 20 {
		return v[:20] + "..."
	}
	return v
}

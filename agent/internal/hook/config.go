// Package hook implements correlic-hook: a small cross-platform binary that
// Claude Code and Cursor run on every tool call. It records what the AI did
// (command, file, URL, session) as canonical ai_tool_call events, can deny a
// tool call that matches one of the organisation's block rules, and ships
// events to the telemetry plane with the same credentials as the agent.
package hook

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is ~/.correlic/hook.yaml. The keys are a subset of agent.yaml so an
// agent config can be pointed at directly (CORRELIC_HOOK_CONFIG=.../agent.yaml);
// unknown keys are ignored.
type Config struct {
	TelemetryURL      string `yaml:"telemetry_url"`
	BackendURL        string `yaml:"backend_url"` // fallback for telemetry_url (agent.yaml compatibility)
	APIKey            string `yaml:"api_key"`     // agent-type key
	TLSCAFile         string `yaml:"tls_ca_file"`
	TLSClientCertFile string `yaml:"tls_client_cert_file"`
	TLSClientKeyFile  string `yaml:"tls_client_key_file"`
	// AllowInsecureHTTP permits an http:// telemetry URL (local development only).
	AllowInsecureHTTP bool `yaml:"allow_insecure_http"`
	// HostID overrides the host id the events carry. Empty: the agent's host
	// id when readable, else a stable per-user id (see ResolveHostID).
	HostID string `yaml:"host_id"`
	// BlockEnabled evaluates block rules on pre-tool events (default true).
	BlockEnabled bool `yaml:"block_enabled"`
	// CacheDir holds the block-rule cache and the spool of undelivered events
	// (default ~/.correlic/hook).
	CacheDir string `yaml:"cache_dir"`

	// Path is the file the config was loaded from ("" when only the
	// environment configured the hook). Not a yaml key.
	Path string `yaml:"-"`
}

// Env variable names read by the hook.
const (
	EnvConfig        = "CORRELIC_HOOK_CONFIG"
	EnvTelemetryURL  = "CORRELIC_TELEMETRY_URL"
	EnvAPIKey        = "CORRELIC_API_KEY"
	EnvTLSCAFile     = "CORRELIC_TLS_CA_FILE"
	EnvTLSClientCert = "CORRELIC_TLS_CLIENT_CERT_FILE"
	EnvTLSClientKey  = "CORRELIC_TLS_CLIENT_KEY_FILE"
	EnvDebug         = "CORRELIC_HOOK_DEBUG"
)

// ErrNotConfigured is returned when neither a config file nor the environment
// names a telemetry URL. The hook then fails open.
var ErrNotConfigured = errors.New("correlic-hook is not configured: write ~/.correlic/hook.yaml or set CORRELIC_TELEMETRY_URL and CORRELIC_API_KEY")

// CorrelicDir is the per-user directory the hook keeps its files in.
func CorrelicDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".correlic"), nil
}

// DefaultConfigPath is ~/.correlic/hook.yaml.
func DefaultConfigPath() (string, error) {
	dir, err := CorrelicDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hook.yaml"), nil
}

// Load reads the config file named by getenv(EnvConfig), else
// ~/.correlic/hook.yaml (a missing default file is not an error), then
// applies the environment overrides and validates the result.
func Load(getenv func(string) string) (Config, error) {
	path := strings.TrimSpace(getenv(EnvConfig))
	explicit := path != ""
	if !explicit {
		p, err := DefaultConfigPath()
		if err != nil {
			return Config{}, err
		}
		path = p
	}
	return LoadFrom(path, explicit, getenv)
}

// LoadFrom loads path (which must exist when explicit is true) and applies
// the environment overrides from getenv.
func LoadFrom(path string, explicit bool, getenv func(string) string) (Config, error) {
	cfg := Config{BlockEnabled: true}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse %s: %w", path, err)
		}
		cfg.Path = path
	case errors.Is(err, os.ErrNotExist) && !explicit:
		// optional default file
	default:
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}

	if v := strings.TrimSpace(getenv(EnvTelemetryURL)); v != "" {
		cfg.TelemetryURL = v
	}
	if v := strings.TrimSpace(getenv(EnvAPIKey)); v != "" {
		cfg.APIKey = v
	}
	if v := strings.TrimSpace(getenv(EnvTLSCAFile)); v != "" {
		cfg.TLSCAFile = v
	}
	if v := strings.TrimSpace(getenv(EnvTLSClientCert)); v != "" {
		cfg.TLSClientCertFile = v
	}
	if v := strings.TrimSpace(getenv(EnvTLSClientKey)); v != "" {
		cfg.TLSClientKeyFile = v
	}

	if err := cfg.finalize(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// finalize fills defaults and validates.
func (c *Config) finalize() error {
	c.TelemetryURL = strings.TrimRight(strings.TrimSpace(c.TelemetryURL), "/")
	c.BackendURL = strings.TrimRight(strings.TrimSpace(c.BackendURL), "/")
	if c.TelemetryURL == "" {
		c.TelemetryURL = c.BackendURL
	}
	if c.TelemetryURL == "" {
		return ErrNotConfigured
	}
	switch {
	case strings.HasPrefix(c.TelemetryURL, "https://"):
	case strings.HasPrefix(c.TelemetryURL, "http://"):
		if !c.AllowInsecureHTTP {
			return fmt.Errorf("telemetry_url %q uses http://; set allow_insecure_http: true to permit it", c.TelemetryURL)
		}
	default:
		return fmt.Errorf("telemetry_url %q must start with https://", c.TelemetryURL)
	}
	c.APIKey = strings.TrimSpace(c.APIKey)
	if c.APIKey == "" && c.TLSClientCertFile == "" {
		return errors.New("api_key (an agent-type key) or a tls client certificate is required")
	}
	if (c.TLSClientCertFile == "") != (c.TLSClientKeyFile == "") {
		return errors.New("tls_client_cert_file and tls_client_key_file must be set together")
	}
	if c.CacheDir == "" {
		dir, err := CorrelicDir()
		if err != nil {
			return err
		}
		c.CacheDir = filepath.Join(dir, "hook")
	}
	c.HostID = strings.TrimSpace(c.HostID)
	return nil
}

// Redacted returns a copy safe for printing (no API key).
func (c Config) Redacted() Config {
	if c.APIKey != "" {
		c.APIKey = "***"
	}
	return c
}

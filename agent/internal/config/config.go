package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

/*
Config holds the configuration parameters for the agent
*/
type Config struct {
	BackendURL            string        `yaml:"backend_url"`
	TelemetryURL          string        `yaml:"telemetry_url"`
	HeartbeatInterval     time.Duration `yaml:"heartbeat_interval"`
	ProcessExecEnabled    bool          `yaml:"process_exec_enabled"`
	EBPFEnabled           bool          `yaml:"ebpf_enabled"`            // Prefer eBPF over /proc polling (default: true on Linux)
	FileMonitorEnabled    bool          `yaml:"file_monitor_enabled"`    // Monitor credential file access (requires eBPF)
	NetworkMonitorEnabled bool          `yaml:"network_monitor_enabled"` // Monitor outbound connections (requires eBPF)
	DNSMonitorEnabled     bool          `yaml:"dns_monitor_enabled"`     // Monitor DNS queries (requires eBPF)
	BindMonitorEnabled    bool          `yaml:"bind_monitor_enabled"`    // Monitor socket binds (requires eBPF)
	UnlinkMonitorEnabled  bool          `yaml:"unlink_monitor_enabled"`  // Monitor file deletions (requires eBPF)
	SetuidMonitorEnabled  bool          `yaml:"setuid_monitor_enabled"`  // Monitor privilege escalation (requires eBPF)
	ForkMonitorEnabled    bool          `yaml:"fork_monitor_enabled"`    // Monitor process creation (requires eBPF)
	Profile               string        `yaml:"profile"`
	LogLevel              string        `yaml:"log_level"`
	APIKey                string        `yaml:"api_key"`
	CorrelicAPIURL        string        `yaml:"correlic_api_url"`
	TLSCAFile             string        `yaml:"tls_ca_file"`
	TLSClientCertFile     string        `yaml:"tls_client_cert_file"`
	TLSClientKeyFile      string        `yaml:"tls_client_key_file"`
	// AllowInsecureHTTP permits http:// backend/telemetry URLs. The API key is
	// sent in a request header, so this must only be used on trusted networks
	// (e.g. local development).
	AllowInsecureHTTP bool `yaml:"allow_insecure_http"`

	// macOS-specific (ignored on Linux/Windows)
	PollInterval       time.Duration `yaml:"poll_interval"`        // macOS polling interval for lsof/fsevents (default 2s)
	FSEventsWatchPaths []string      `yaml:"fsevents_watch_paths"` // Additional FSEvents watch paths
	EsloggerEnabled    bool          `yaml:"eslogger_enabled"`     // Endpoint Security events via /usr/bin/eslogger (macOS 13+, root, Full Disk Access; default: true)

	// Windows-specific (ignored on Linux/macOS)
	ETWEnabled bool `yaml:"etw_enabled"` // Use ETW for telemetry collection (default: true on Windows)

	// Soft-block enforcer
	BlockEnabled         bool          `yaml:"block_enabled"`          // default: false
	BlockSyncInterval    time.Duration `yaml:"block_sync_interval"`    // default: 30s
	BlockEmergencyBypass bool          `yaml:"block_emergency_bypass"` // panic button
}

// removedKeys are config keys that older agents accepted but that no longer
// have any effect. They are ignored with a warning so pre-1.0.1 agent.yaml
// files keep working; any other unknown key is a hard error.
var removedKeys = map[string]bool{
	"approvals_poll_interval":   true,
	"approvals_ui_enabled":      true,
	"approvals_ui_addr":         true,
	"approval_gate_enforced":    true,
	"notify_enabled":            true,
	"disable_proc_fallback":     true,
	"process_exec_interval":     true,
	"process_exec_emit_initial": true,
	"esf_enabled":               true,
	"service_name":              true,
}

// DefaultHeartbeatInterval is the heartbeat period when heartbeat_interval is unset.
const DefaultHeartbeatInterval = 30 * time.Second

/*
Default returns the default configuration values
*/
func Default() Config {
	return Config{
		BackendURL:            "https://localhost:8080",
		TelemetryURL:          "",
		HeartbeatInterval:     DefaultHeartbeatInterval,
		ProcessExecEnabled:    false,
		EBPFEnabled:           true,  // Prefer eBPF when available
		FileMonitorEnabled:    false, // Credential file monitoring (enable explicitly)
		NetworkMonitorEnabled: false, // Network connection monitoring (enable explicitly)
		DNSMonitorEnabled:     false, // DNS query monitoring (enable explicitly)
		BindMonitorEnabled:    false, // Socket bind monitoring (enable explicitly)
		UnlinkMonitorEnabled:  false, // File deletion monitoring (enable explicitly)
		SetuidMonitorEnabled:  false, // Privilege escalation monitoring (enable explicitly)
		ForkMonitorEnabled:    false, // Process creation monitoring (enable explicitly)
		Profile:               "developer",
		LogLevel:              "info",
		EsloggerEnabled:       true,  // Endpoint Security via eslogger on macOS 13+ (falls back to polling)
		ETWEnabled:            true,  // Prefer ETW when available (Windows)
		BlockEnabled:          false, // Soft-block disabled by default
		BlockSyncInterval:     30 * time.Second,
		BlockEmergencyBypass:  false,
	}
}

/*
Load reads the configuration from the user's home directory.
*/
func Load() (Config, error) {
	//define default config
	cfg := Default()

	// get user's home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return cfg, err
	}

	// construct config file path
	path := filepath.Join(home, ".correlic", "agent.yaml")

	return LoadFromPath(path)
}

// LoadFromPath reads config from an explicit path. If the file does not exist, returns defaults.
// Use LoadRequired when a missing file must be an error.
func LoadFromPath(path string) (Config, error) {
	cfg := Default()
	path = strings.TrimSpace(path)
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// if file does not exist, return defaults
		if os.IsNotExist(err) {
			return cfg, nil // defaults only
		}
		return cfg, err
	}
	return parse(path, data)
}

// LoadRequired reads config from an explicit path and fails when the file
// does not exist or cannot be parsed. Used for CORRELIC_CONFIG and --config,
// where silently falling back to defaults would hide an operator mistake.
func LoadRequired(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Default(), errors.New("config path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Default(), fmt.Errorf("read config %s: %w", path, err)
	}
	cfg, err := parse(path, data)
	if err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

// parse decodes YAML into a Config, rejecting unknown keys (except the
// documented removed keys, which are ignored with a warning), resolves
// relative TLS paths and validates the result.
func parse(path string, data []byte) (Config, error) {
	cfg := Default()

	// First pass: a generic decode so removed keys can be stripped with a
	// warning instead of failing the strict decode below.
	var raw map[string]any
	err := yaml.Unmarshal(data, &raw)
	if err != nil {
		return cfg, err
	}
	if raw == nil {
		raw = map[string]any{}
	}
	var removed []string
	for k := range raw {
		if removedKeys[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(removed)
	for _, k := range removed {
		slog.Warn("ignoring removed config key "+k, "config", path)
		delete(raw, k)
	}

	// Keep the original bytes when nothing was removed so decode errors
	// report the operator's own line numbers.
	cleaned := data
	if len(removed) > 0 {
		cleaned, err = yaml.Marshal(raw)
		if err != nil {
			return cfg, err
		}
	}

	// Second pass: strict decode. Unknown keys are almost always typos
	// (e.g. "file_monitor_enable") that would otherwise silently disable a
	// feature.
	dec := yaml.NewDecoder(bytes.NewReader(cleaned))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return cfg, err
	}

	// Resolve relative file paths relative to the config file directory.
	// This makes generated configs portable (run agent from any cwd).
	baseDir := filepath.Dir(path)
	cfg.TLSCAFile = resolvePath(baseDir, cfg.TLSCAFile)
	cfg.TLSClientCertFile = resolvePath(baseDir, cfg.TLSClientCertFile)
	cfg.TLSClientKeyFile = resolvePath(baseDir, cfg.TLSClientKeyFile)

	// validate config
	return cfg, validate(cfg)
}

func resolvePath(baseDir, p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(baseDir, p)
}

// LoadFromPathOrDefault loads from explicit CLI path if provided, otherwise from
// $CORRELIC_CONFIG, otherwise falls back to agent.yaml next to the executable,
// otherwise ~/.correlic/agent.yaml.
//
// An explicit path (CLI flag or CORRELIC_CONFIG) must exist and parse; the
// default search locations fall back to built-in defaults when missing.
func LoadFromPathOrDefault(cliPath string) (Config, error) {
	cfg, _, err := Resolve(cliPath)
	return cfg, err
}

// Resolve is LoadFromPathOrDefault that also returns the path the config was
// loaded from ("" when only defaults were used).
func Resolve(cliPath string) (Config, string, error) {
	if p := strings.TrimSpace(cliPath); p != "" {
		cfg, err := LoadRequired(p)
		return cfg, p, err
	}
	if p := strings.TrimSpace(os.Getenv("CORRELIC_CONFIG")); p != "" {
		cfg, err := LoadRequired(p)
		return cfg, p, err
	}
	// Try agent.yaml next to the executable (works for Windows service where
	// CORRELIC_CONFIG env var may not be visible to the SYSTEM account).
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		// Check both <exe_dir>/agent.yaml and <exe_dir>/../agent.yaml
		for _, candidate := range []string{
			filepath.Join(exeDir, "agent.yaml"),
			filepath.Join(exeDir, "..", "agent.yaml"),
		} {
			if _, err := os.Stat(candidate); err == nil {
				cfg, err := LoadFromPath(candidate)
				return cfg, candidate, err
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Default(), "", err
	}
	path := filepath.Join(home, ".correlic", "agent.yaml")
	cfg, err := LoadFromPath(path)
	if err != nil {
		return cfg, path, err
	}
	if _, statErr := os.Stat(path); statErr != nil {
		path = "" // defaults only
	}
	return cfg, path, nil
}

// isHTTPS reports whether u uses the https scheme.
func isHTTPS(u string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(u)), "https://")
}

/*
validate checks the configuration for correctness
*/
func validate(cfg Config) error {
	if cfg.BackendURL == "" {
		return errors.New("backend_url must not be empty")
	}
	// telemetry_url is optional; defaults to backend_url if unset.
	if cfg.HeartbeatInterval < 10*time.Second {
		return errors.New("heartbeat_interval too low (min 10s)")
	}
	if cfg.BlockSyncInterval != 0 && cfg.BlockSyncInterval < 5*time.Second {
		return errors.New("block_sync_interval too low (min 5s)")
	}
	if cfg.Profile != "developer" {
		return errors.New("unsupported profile")
	}
	switch strings.ToLower(cfg.LogLevel) {
	case "", "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("unsupported log_level %q (debug|info|warn|error)", cfg.LogLevel)
	}
	if (cfg.TLSClientCertFile != "" && cfg.TLSClientKeyFile == "") || (cfg.TLSClientCertFile == "" && cfg.TLSClientKeyFile != "") {
		return errors.New("tls_client_cert_file and tls_client_key_file must be set together")
	}
	// The API key travels in a request header, so plain http is only allowed
	// when the operator opts in explicitly.
	if !cfg.AllowInsecureHTTP {
		if !isHTTPS(cfg.BackendURL) {
			return errors.New("backend_url must start with https:// (set allow_insecure_http: true to override)")
		}
		if cfg.TelemetryURL != "" && !isHTTPS(cfg.TelemetryURL) {
			return errors.New("telemetry_url must start with https:// (set allow_insecure_http: true to override)")
		}
	}
	// api_key is optional when running with mTLS client identity configured.
	// If no client cert is configured, require api_key for auth.
	if cfg.APIKey == "" && cfg.TLSClientCertFile == "" {
		return errors.New("api_key missing (required when tls_client_cert_file is not set)")
	}
	return nil
}

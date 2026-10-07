package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

/*
Config holds the configuration parameters for the agent
*/
type Config struct {
	BackendURL             string        `yaml:"backend_url"`
	TelemetryURL           string        `yaml:"telemetry_url"`
	HeartbeatInterval      time.Duration `yaml:"heartbeat_interval"`
	ProcessExecEnabled     bool          `yaml:"process_exec_enabled"`
	ProcessExecInterval    time.Duration `yaml:"process_exec_interval"`
	ProcessExecEmitInitial bool          `yaml:"process_exec_emit_initial"` // When true (e.g. in container), emit processes already running at startup so Exec events > 0
	EBPFEnabled            bool          `yaml:"ebpf_enabled"`              // Prefer eBPF over /proc polling (default: true on Linux)
	DisableProcFallback    bool          `yaml:"disable_proc_fallback"`     // If true, don't fall back to /proc when eBPF fails
	FileMonitorEnabled     bool          `yaml:"file_monitor_enabled"`      // Monitor credential file access (requires eBPF)
	NetworkMonitorEnabled  bool          `yaml:"network_monitor_enabled"`   // Monitor outbound connections (requires eBPF)
	DNSMonitorEnabled      bool          `yaml:"dns_monitor_enabled"`       // Monitor DNS queries (requires eBPF)
	BindMonitorEnabled     bool          `yaml:"bind_monitor_enabled"`      // Monitor socket binds (requires eBPF)
	UnlinkMonitorEnabled   bool          `yaml:"unlink_monitor_enabled"`    // Monitor file deletions (requires eBPF)
	SetuidMonitorEnabled   bool          `yaml:"setuid_monitor_enabled"`    // Monitor privilege escalation (requires eBPF)
	ForkMonitorEnabled     bool          `yaml:"fork_monitor_enabled"`      // Monitor process creation (requires eBPF)
	NotifyEnabled          bool          `yaml:"notify_enabled"`
	ApprovalGateEnforced   bool          `yaml:"approval_gate_enforced"`
	ApprovalsPollInterval  time.Duration `yaml:"approvals_poll_interval"`
	ApprovalsUIEnabled     bool          `yaml:"approvals_ui_enabled"`
	ApprovalsUIAddr        string        `yaml:"approvals_ui_addr"`
	Profile                string        `yaml:"profile"`
	LogLevel               string        `yaml:"log_level"`
	APIKey                 string        `yaml:"api_key"`
	CorrelicAPIURL         string        `yaml:"correlic_api_url"`
	TLSCAFile              string        `yaml:"tls_ca_file"`
	TLSClientCertFile      string        `yaml:"tls_client_cert_file"`
	TLSClientKeyFile       string        `yaml:"tls_client_key_file"`

	// macOS-specific (ignored on Linux/Windows)
	PollInterval       time.Duration `yaml:"poll_interval"`         // macOS polling interval for lsof/fsevents (default 2s)
	FSEventsWatchPaths []string      `yaml:"fsevents_watch_paths"`  // Additional FSEvents watch paths
	ESFEnabled         bool          `yaml:"esf_enabled"`           // Use ESF when available (Phase 2)

	// Windows-specific (ignored on Linux/macOS)
	ETWEnabled  bool   `yaml:"etw_enabled"`   // Use ETW for telemetry collection (default: true on Windows)
	ServiceName string `yaml:"service_name"`  // Windows service name (default: "CorrelicAgent")

	// Soft-block enforcer
	BlockEnabled         bool          `yaml:"block_enabled"`          // default: false
	BlockSyncInterval    time.Duration `yaml:"block_sync_interval"`    // default: 30s
	BlockEmergencyBypass bool          `yaml:"block_emergency_bypass"` // panic button
}

/*
Default returns the default configuration values
*/
func Default() Config {
	return Config{
		BackendURL:             "https://localhost:8080",
		TelemetryURL:           "",
		HeartbeatInterval:      60 * time.Second,
		ProcessExecEnabled:     false,
		ProcessExecInterval:    10 * time.Second,
		ProcessExecEmitInitial: false,
		EBPFEnabled:            true,  // Prefer eBPF when available
		DisableProcFallback:    false, // Allow fallback to /proc
		FileMonitorEnabled:     false, // Credential file monitoring (enable explicitly)
		NetworkMonitorEnabled:  false, // Network connection monitoring (enable explicitly)
		DNSMonitorEnabled:      false, // DNS query monitoring (enable explicitly)
		BindMonitorEnabled:     false, // Socket bind monitoring (enable explicitly)
		UnlinkMonitorEnabled:   false, // File deletion monitoring (enable explicitly)
		SetuidMonitorEnabled:   false, // Privilege escalation monitoring (enable explicitly)
		ForkMonitorEnabled:     false, // Process creation monitoring (enable explicitly)
		NotifyEnabled:          true,
		ApprovalGateEnforced:   true,
		ApprovalsPollInterval:  10 * time.Second,
		ApprovalsUIEnabled:     true,
		ApprovalsUIAddr:        "127.0.0.1:8787",
		Profile:                "developer",
		LogLevel:               "info",
		ETWEnabled:             true,            // Prefer ETW when available (Windows)
		ServiceName:            "CorrelicAgent", // Windows service name
		BlockEnabled:           false,           // Soft-block disabled by default
		BlockSyncInterval:      30 * time.Second,
		BlockEmergencyBypass:   false,
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

	// unmarshal YAML data into config struct
	if err := yaml.Unmarshal(data, &cfg); err != nil {
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
// $CORRELIC_CONFIG, otherwise falls back to ~/.correlic/agent.yaml.
func LoadFromPathOrDefault(cliPath string) (Config, error) {
	if p := strings.TrimSpace(cliPath); p != "" {
		return LoadFromPath(p)
	}
	if p := strings.TrimSpace(os.Getenv("CORRELIC_CONFIG")); p != "" {
		return LoadFromPath(p)
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
				return LoadFromPath(candidate)
			}
		}
	}
	cfg, err := Load()
	if err != nil {
		return cfg, err
	}
	// If config file missing, be a bit more explicit in logs upstream by returning defaults + nil.
	return cfg, nil
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
		return errors.New("heartbeat_interval too low")
	}
	if cfg.ProcessExecInterval != 0 && cfg.ProcessExecInterval < 250*time.Millisecond {
		return errors.New("process_exec_interval too low (min 250ms)")
	}
	if cfg.ApprovalsPollInterval != 0 && cfg.ApprovalsPollInterval < 2*time.Second {
		return errors.New("approvals_poll_interval too low (min 2s)")
	}
	if cfg.Profile != "developer" {
		return errors.New("unsupported profile")
	}
	if (cfg.TLSClientCertFile != "" && cfg.TLSClientKeyFile == "") || (cfg.TLSClientCertFile == "" && cfg.TLSClientKeyFile != "") {
		return errors.New("tls_client_cert_file and tls_client_key_file must be set together")
	}
	// If any TLS/mTLS knobs are configured, require https URLs to avoid accidentally sending HTTP to an HTTPS server.
	if cfg.TLSCAFile != "" || cfg.TLSClientCertFile != "" || cfg.TLSClientKeyFile != "" {
		if !strings.HasPrefix(strings.ToLower(cfg.BackendURL), "https://") {
			return errors.New("backend_url must start with https:// when TLS is configured")
		}
		if cfg.TelemetryURL != "" && !strings.HasPrefix(strings.ToLower(cfg.TelemetryURL), "https://") {
			return errors.New("telemetry_url must start with https:// when TLS is configured")
		}
	}
	// api_key is optional when running with mTLS client identity configured.
	// If no client cert is configured, require api_key for auth.
	if cfg.APIKey == "" && cfg.TLSClientCertFile == "" {
		return errors.New("api_key missing (required when tls_client_cert_file is not set)")
	}
	return nil
}

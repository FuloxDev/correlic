package hook

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadFrom_FileWithDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook.yaml")
	os.WriteFile(path, []byte("telemetry_url: https://telemetry.example:8081/\napi_key: agent-key\n"), 0o600)

	cfg, err := LoadFrom(path, true, envOf(nil))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if cfg.TelemetryURL != "https://telemetry.example:8081" || cfg.APIKey != "agent-key" {
		t.Errorf("cfg = %+v", cfg)
	}
	if !cfg.BlockEnabled {
		t.Error("block_enabled should default to true")
	}
	if cfg.CacheDir == "" || !strings.HasSuffix(filepath.ToSlash(cfg.CacheDir), ".correlic/hook") {
		t.Errorf("cache_dir default = %q", cfg.CacheDir)
	}
	if cfg.Path != path {
		t.Errorf("Path = %q", cfg.Path)
	}
}

func TestLoadFrom_AgentYAMLIsAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	os.WriteFile(path, []byte(`backend_url: "https://localhost:8080"
telemetry_url: ""
api_key: "k"
tls_ca_file: "/etc/correlic/ca.crt"
profile: "developer"
ebpf_enabled: true
block_enabled: false
`), 0o600)
	cfg, err := LoadFrom(path, true, envOf(nil))
	if err != nil {
		t.Fatalf("LoadFrom(agent.yaml): %v", err)
	}
	if cfg.TelemetryURL != "https://localhost:8080" {
		t.Errorf("telemetry_url should fall back to backend_url, got %q", cfg.TelemetryURL)
	}
	if cfg.BlockEnabled {
		t.Error("block_enabled: false in the file must win over the default")
	}
	if cfg.TLSCAFile != "/etc/correlic/ca.crt" {
		t.Errorf("tls_ca_file = %q", cfg.TLSCAFile)
	}
}

func TestLoadFrom_EnvOverridesAndMissingDefaultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	env := envOf(map[string]string{
		EnvTelemetryURL: "https://env.example",
		EnvAPIKey:       "env-key",
		EnvTLSCAFile:    "/ca.pem",
	})
	cfg, err := LoadFrom(path, false, env)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if cfg.TelemetryURL != "https://env.example" || cfg.APIKey != "env-key" || cfg.TLSCAFile != "/ca.pem" {
		t.Errorf("env overrides not applied: %+v", cfg)
	}
	if cfg.Path != "" {
		t.Errorf("Path should be empty without a file, got %q", cfg.Path)
	}

	if _, err := LoadFrom(path, true, env); err == nil {
		t.Error("explicit missing file must be an error")
	}
}

func TestLoadFrom_Validation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "none.yaml")
	if _, err := LoadFrom(path, false, envOf(nil)); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no url: err = %v, want ErrNotConfigured", err)
	}
	_, err := LoadFrom(path, false, envOf(map[string]string{EnvTelemetryURL: "http://x", EnvAPIKey: "k"}))
	if err == nil || !strings.Contains(err.Error(), "allow_insecure_http") {
		t.Errorf("http without allow_insecure_http: err = %v", err)
	}
	_, err = LoadFrom(path, false, envOf(map[string]string{EnvTelemetryURL: "https://x"}))
	if err == nil || !strings.Contains(err.Error(), "api_key") {
		t.Errorf("missing key: err = %v", err)
	}
	_, err = LoadFrom(path, false, envOf(map[string]string{EnvTelemetryURL: "https://x", EnvAPIKey: "k", EnvTLSClientCert: "/c.crt"}))
	if err == nil || !strings.Contains(err.Error(), "together") {
		t.Errorf("cert without key: err = %v", err)
	}

	cfg, err := LoadFrom(path, false, envOf(map[string]string{EnvTelemetryURL: "http://localhost:8081", EnvAPIKey: "k"}))
	if err == nil {
		t.Fatalf("expected error for http without allow_insecure_http, got cfg %+v", cfg)
	}
	if r := cfg.Redacted(); r.APIKey != "" {
		t.Errorf("Redacted on zero config = %+v", r)
	}
	full := Config{APIKey: "secret"}
	if full.Redacted().APIKey != "***" {
		t.Error("Redacted must mask the key")
	}
}

func TestLoad_UsesEnvConfigPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	os.WriteFile(path, []byte("telemetry_url: https://a\napi_key: k\ncache_dir: "+filepath.ToSlash(dir)+"/cache\nhost_id: host-override\n"), 0o600)
	cfg, err := Load(envOf(map[string]string{EnvConfig: path}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Path != path || cfg.HostID != "host-override" || cfg.CacheDir != filepath.ToSlash(dir)+"/cache" {
		t.Errorf("cfg = %+v", cfg)
	}
}

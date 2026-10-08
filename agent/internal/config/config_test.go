package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRequired_MissingFileIsError(t *testing.T) {
	_, err := LoadRequired(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for missing explicit config")
	}
}

func TestLoadRequired_ParseErrorIsError(t *testing.T) {
	p := writeTemp(t, "backend_url: [unterminated\n")
	_, err := LoadRequired(p)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestParse_InstallerKeysAccepted(t *testing.T) {
	p := writeTemp(t, `
backend_url: "https://localhost:8080"
telemetry_url: "https://localhost:8081"
api_key: "k"
tls_ca_file: "ca.crt"
tls_client_cert_file: "client.crt"
tls_client_key_file: "client.key"
profile: "developer"
log_level: "info"
heartbeat_interval: 30s
ebpf_enabled: true
process_exec_enabled: true
file_monitor_enabled: true
network_monitor_enabled: true
dns_monitor_enabled: true
bind_monitor_enabled: true
unlink_monitor_enabled: true
setuid_monitor_enabled: true
fork_monitor_enabled: true
block_enabled: true
block_sync_interval: 30s
block_emergency_bypass: false
etw_enabled: true
poll_interval: 2s
fsevents_watch_paths: ["/Users"]
eslogger_enabled: true
correlic_api_url: "https://keys.example"
allow_insecure_http: false
`)
	cfg, err := LoadRequired(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HeartbeatInterval != 30*time.Second || !cfg.ForkMonitorEnabled || !cfg.BlockEnabled {
		t.Errorf("fields not decoded: %+v", cfg)
	}
	if !filepath.IsAbs(cfg.TLSCAFile) || filepath.Dir(cfg.TLSCAFile) != filepath.Dir(p) {
		t.Errorf("relative tls path not resolved: %q", cfg.TLSCAFile)
	}
}

func TestParse_RemovedKeysWarnNotFail(t *testing.T) {
	p := writeTemp(t, `
backend_url: "https://localhost:8080"
api_key: "k"
notify_enabled: true
approval_gate_enforced: true
approvals_poll_interval: 10s
approvals_ui_enabled: true
approvals_ui_addr: "127.0.0.1:8787"
process_exec_interval: 10s
process_exec_emit_initial: false
disable_proc_fallback: false
esf_enabled: false
service_name: "CorrelicAgent"
`)
	if _, err := LoadRequired(p); err != nil {
		t.Fatalf("removed keys must be ignored, got: %v", err)
	}
}

func TestParse_UnknownKeyRejected(t *testing.T) {
	p := writeTemp(t, `
backend_url: "https://localhost:8080"
api_key: "k"
file_monitor_enable: true
`)
	_, err := LoadRequired(p)
	if err == nil || !strings.Contains(err.Error(), "file_monitor_enable") {
		t.Fatalf("expected unknown-field error naming the key, got: %v", err)
	}
}

func TestValidate_RequiresHTTPSUnlessAllowed(t *testing.T) {
	p := writeTemp(t, "backend_url: \"http://localhost:8080\"\napi_key: \"k\"\n")
	if _, err := LoadRequired(p); err == nil {
		t.Fatal("http backend_url must be rejected by default")
	}
	p = writeTemp(t, "backend_url: \"http://localhost:8080\"\napi_key: \"k\"\nallow_insecure_http: true\n")
	if _, err := LoadRequired(p); err != nil {
		t.Fatalf("allow_insecure_http should permit http: %v", err)
	}
	p = writeTemp(t, "backend_url: \"https://a\"\ntelemetry_url: \"http://b\"\napi_key: \"k\"\n")
	if _, err := LoadRequired(p); err == nil {
		t.Fatal("http telemetry_url must be rejected by default")
	}
}

func TestValidate_LogLevel(t *testing.T) {
	p := writeTemp(t, "backend_url: \"https://a\"\napi_key: \"k\"\nlog_level: verbose\n")
	if _, err := LoadRequired(p); err == nil {
		t.Fatal("bad log_level must be rejected")
	}
}

func TestDefaultHeartbeat(t *testing.T) {
	if Default().HeartbeatInterval != 30*time.Second {
		t.Errorf("default heartbeat_interval = %v, want 30s", Default().HeartbeatInterval)
	}
}

func TestEsloggerEnabled_DefaultsTrue(t *testing.T) {
	if !Default().EsloggerEnabled {
		t.Fatal("eslogger_enabled must default to true")
	}
	p := writeTemp(t, "backend_url: \"https://a\"\napi_key: \"k\"\n")
	cfg, err := LoadRequired(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.EsloggerEnabled {
		t.Error("eslogger_enabled must stay true when the key is absent")
	}
	p = writeTemp(t, "backend_url: \"https://a\"\napi_key: \"k\"\neslogger_enabled: false\n")
	cfg, err = LoadRequired(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EsloggerEnabled {
		t.Error("eslogger_enabled: false not honoured")
	}
}

func TestResolve_EnvPathMustExist(t *testing.T) {
	t.Setenv("CORRELIC_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	if _, _, err := Resolve(""); err == nil {
		t.Fatal("CORRELIC_CONFIG pointing at a missing file must fail")
	}
}

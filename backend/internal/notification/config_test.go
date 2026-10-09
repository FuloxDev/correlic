package notification

import (
	"errors"
	"strings"
	"testing"

	"github.com/correlic/correlic-backend/internal/secrets"
)

func testCipher(t *testing.T) *secrets.Cipher {
	t.Helper()
	c, err := secrets.NewCipher("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestValidateConfigDiscord(t *testing.T) {
	useFakeResolver(t)
	lookupIPAlias(t, "discord.com", "93.184.216.34")
	lookupIPAlias(t, "discordapp.com", "93.184.216.34")
	lookupIPAlias(t, "discord.com.public.example", "93.184.216.34")
	cases := []struct {
		name string
		url  string
		ok   bool
	}{
		{"discord.com", "https://discord.com/api/webhooks/123/abc", true},
		{"discordapp.com", "https://discordapp.com/api/webhooks/123/abc", true},
		{"http scheme", "http://discord.com/api/webhooks/123/abc", false},
		{"other host", "https://public.example/api/webhooks/123/abc", false},
		{"lookalike host", "https://discord.com.public.example/api/webhooks/1/a", false},
		{"wrong path", "https://discord.com/api/channels/1", false},
		{"bare path", "https://discord.com/api/webhooks/", false},
		{"odd port", "https://discord.com:8443/api/webhooks/1/a", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := map[string]any{"webhook_url": tc.url}
			err := ValidateConfig(ChannelDiscord, cfg)
			if tc.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected %q to be rejected", tc.url)
			}
			var ce *ConfigError
			if !errors.As(err, &ce) {
				t.Fatalf("error is not a ConfigError: %T", err)
			}
		})
	}
}

func TestValidateConfigEmail(t *testing.T) {
	good := func() map[string]any {
		return map[string]any{
			"smtp_host": "smtp.example.com",
			"from":      "Correlic <alerts@example.com>",
			"to":        []any{"a@example.com", "b@example.com"},
			"username":  "alerts",
			"password":  "hunter2",
		}
	}
	cfg := good()
	if err := ValidateConfig(ChannelEmail, cfg); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg["smtp_port"] != defaultSMTPPort || cfg["security"] != EmailSecurityStartTLS {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if to, _ := cfg["to"].([]any); len(to) != 2 {
		t.Fatalf("to not normalized: %#v", cfg["to"])
	}

	// A comma-separated string is accepted for "to" (what a form field sends).
	cfg = good()
	cfg["to"] = "x@example.com, y@example.com"
	if err := ValidateConfig(ChannelEmail, cfg); err != nil {
		t.Fatalf("comma list rejected: %v", err)
	}
	if to, _ := cfg["to"].([]any); len(to) != 2 {
		t.Fatalf("comma list not split: %#v", cfg["to"])
	}

	bad := []struct {
		name string
		mut  func(map[string]any)
	}{
		{"no host", func(c map[string]any) { delete(c, "smtp_host") }},
		{"url host", func(c map[string]any) { c["smtp_host"] = "smtp://smtp.example.com" }},
		{"host with port", func(c map[string]any) { c["smtp_host"] = "smtp.example.com:587" }},
		{"bad port", func(c map[string]any) { c["smtp_port"] = 70000 }},
		{"bad security", func(c map[string]any) { c["security"] = "ssl" }},
		{"no from", func(c map[string]any) { delete(c, "from") }},
		{"bad from", func(c map[string]any) { c["from"] = "not an address" }},
		{"no to", func(c map[string]any) { c["to"] = []any{} }},
		{"bad to", func(c map[string]any) { c["to"] = []any{"ok@example.com", "nope"} }},
		{"to not list", func(c map[string]any) { c["to"] = 42 }},
		{"prefix newline", func(c map[string]any) { c["subject_prefix"] = "[x]\r\nBcc: evil@example.com" }},
		{"prefix too long", func(c map[string]any) { c["subject_prefix"] = strings.Repeat("x", 65) }},
		{"cleartext auth", func(c map[string]any) { c["security"] = "none" }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			c := good()
			tc.mut(c)
			if err := ValidateConfig(ChannelEmail, c); err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}

	// Cleartext without a username is allowed (a local relay), and so is
	// cleartext auth to localhost.
	c := good()
	c["security"] = "none"
	delete(c, "username")
	if err := ValidateConfig(ChannelEmail, c); err != nil {
		t.Fatalf("cleartext without auth should be accepted: %v", err)
	}
	c = good()
	c["security"] = "none"
	c["smtp_host"] = "127.0.0.1"
	if err := ValidateConfig(ChannelEmail, c); err != nil {
		t.Fatalf("cleartext auth to loopback should be accepted: %v", err)
	}
}

func TestValidateConfigSyslog(t *testing.T) {
	cfg := map[string]any{"host": "logs.internal"}
	if err := ValidateConfig(ChannelSyslog, cfg); err != nil {
		t.Fatalf("minimal config rejected: %v", err)
	}
	if cfg["protocol"] != SyslogUDP || cfg["port"] != defaultSyslogUDPPort || cfg["facility"] != "local0" {
		t.Fatalf("defaults not applied: %+v", cfg)
	}

	cfg = map[string]any{"host": "logs.internal", "protocol": "tcp+tls", "facility": 20}
	if err := ValidateConfig(ChannelSyslog, cfg); err != nil {
		t.Fatalf("tls config rejected: %v", err)
	}
	if cfg["port"] != defaultSyslogTLSPort || cfg["facility"] != "local4" {
		t.Fatalf("tls defaults / numeric facility not applied: %+v", cfg)
	}

	bad := []map[string]any{
		{},
		{"host": "udp://logs.internal"},
		{"host": "logs.internal", "protocol": "ssl"},
		{"host": "logs.internal", "facility": "bogus"},
		{"host": "logs.internal", "facility": 24},
		{"host": "logs.internal", "port": 0},
		{"host": "logs.internal", "protocol": "udp", "ca_file": "/etc/ssl/certs/ca-certificates.crt"},
		{"host": "logs.internal", "protocol": "tcp+tls", "ca_file": "relative/ca.pem"},
		{"host": "logs.internal", "protocol": "tcp+tls", "ca_file": "/nonexistent/ca.pem"},
		{"host": "logs.internal", "insecure_skip_verify": "yes"},
	}
	for i, c := range bad {
		if err := ValidateConfig(ChannelSyslog, c); err == nil {
			t.Errorf("case %d: expected rejection for %+v", i, c)
		}
	}
}

func TestValidateConfigUnknownType(t *testing.T) {
	if err := ValidateConfig("pager", map[string]any{}); err == nil {
		t.Fatal("unknown channel type accepted")
	}
	if IsChannelType("pager") || !IsChannelType("email") {
		t.Fatal("IsChannelType wrong")
	}
}

func TestSealMergeRedactResolve(t *testing.T) {
	c := testCipher(t)

	cfg := map[string]any{"smtp_host": "h", "password": "hunter2"}
	if err := SealSecrets(c, ChannelEmail, cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg["password"]; ok {
		t.Fatal("plaintext password still present after sealing")
	}
	sealed, _ := cfg["password_encrypted"].(string)
	if sealed == "" || sealed == "hunter2" {
		t.Fatalf("password not sealed: %q", sealed)
	}

	// The API never returns the secret, only whether one is set.
	red := Redacted(Endpoint{ChannelType: ChannelEmail, Config: cfg})
	if _, ok := red.Config["password_encrypted"]; ok {
		t.Fatal("redacted config leaks the sealed value")
	}
	if red.Config["password_set"] != true || red.Config["smtp_host"] != "h" {
		t.Fatalf("redacted config wrong: %+v", red.Config)
	}
	if _, ok := cfg["password_encrypted"]; !ok {
		t.Fatal("Redacted must not modify the original config")
	}

	// A replacement config without a password keeps the stored one; a new
	// plaintext replaces it.
	repl := map[string]any{"smtp_host": "h2", "password": ""}
	MergeSecrets(ChannelEmail, cfg, repl)
	if repl["password_encrypted"] != sealed {
		t.Fatal("stored password not carried over")
	}
	repl = map[string]any{"smtp_host": "h2", "password": "new"}
	MergeSecrets(ChannelEmail, cfg, repl)
	if _, ok := repl["password_encrypted"]; ok {
		t.Fatal("new plaintext must win over the stored value")
	}

	// Resolve opens the sealed value, falls back to legacy plaintext, and
	// reports a missing cipher.
	if got, err := ResolveSecret(c, cfg, "password"); err != nil || got != "hunter2" {
		t.Fatalf("resolve sealed: %q %v", got, err)
	}
	if got, err := ResolveSecret(nil, map[string]any{"secret": "legacy"}, "secret"); err != nil || got != "legacy" {
		t.Fatalf("resolve legacy: %q %v", got, err)
	}
	if _, err := ResolveSecret(nil, cfg, "password"); !errors.Is(err, secrets.ErrNoCipher) {
		t.Fatalf("resolve without cipher: %v", err)
	}
	if got, err := ResolveSecret(c, map[string]any{}, "password"); err != nil || got != "" {
		t.Fatalf("resolve unset: %q %v", got, err)
	}

	// Sealing without a cipher must not leave plaintext behind.
	cfg = map[string]any{"url": "https://x", "secret": "s"}
	if err := SealSecrets(nil, ChannelWebhook, cfg); !errors.Is(err, secrets.ErrNoCipher) {
		t.Fatalf("expected ErrNoCipher, got %v", err)
	}
	if _, ok := cfg["secret"]; ok {
		t.Fatal("plaintext secret left in config after failed sealing")
	}

	// Legacy plaintext secrets stay redacted and flagged.
	red = Redacted(Endpoint{ChannelType: ChannelWebhook, Config: map[string]any{"url": "u", "secret": "legacy"}})
	if _, ok := red.Config["secret"]; ok || red.Config["secret_set"] != true {
		t.Fatalf("legacy secret not redacted: %+v", red.Config)
	}
}

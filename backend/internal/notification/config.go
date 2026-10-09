package notification

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/correlic/correlic-backend/internal/secrets"
)

// Channel types a notification endpoint can have. The dashboard offers the
// same list; the API rejects anything else.
const (
	ChannelWebhook = "webhook"
	ChannelSlack   = "slack"
	ChannelDiscord = "discord"
	ChannelEmail   = "email"
	ChannelSyslog  = "syslog"
)

// ChannelTypes lists every supported channel type in display order.
var ChannelTypes = []string{ChannelWebhook, ChannelSlack, ChannelDiscord, ChannelEmail, ChannelSyslog}

// ChannelTypesMessage is the client-facing message for an unknown type.
var ChannelTypesMessage = "channel_type must be one of: " + strings.Join(ChannelTypes, ", ")

// IsChannelType reports whether t is a supported channel type.
func IsChannelType(t string) bool {
	for _, c := range ChannelTypes {
		if c == t {
			return true
		}
	}
	return false
}

// secretKeys lists, per channel type, the config keys that hold a secret.
// A secret is stored under "<key>_encrypted" (sealed with the LLM key) and
// never returned by the API; see SealSecrets, MergeSecrets and Redacted.
var secretKeys = map[string][]string{
	ChannelWebhook: {"secret"},
	ChannelEmail:   {"password"},
}

// EncryptedSuffix marks a sealed secret in an endpoint's config.
const EncryptedSuffix = "_encrypted"

// ConfigError is a validation failure whose message is safe to return to
// API clients.
type ConfigError struct{ Msg string }

func (e *ConfigError) Error() string { return e.Msg }

func configErrorf(format string, args ...any) error {
	return &ConfigError{Msg: fmt.Sprintf(format, args...)}
}

// Limits on free-form config values.
const (
	maxEmailRecipients   = 50
	maxSubjectPrefixLen  = 64
	defaultSMTPPort      = 587
	defaultSyslogUDPPort = 514
	defaultSyslogTLSPort = 6514
)

// ValidateConfig checks the channel-specific config of a notification
// endpoint, runs the outbound URL guard for HTTP channels and normalizes
// defaults in place (ports, security mode, facility). It returns a
// *ConfigError with a client-safe message on failure. Secrets may be present
// in plaintext (new value) or sealed (existing endpoint); both are accepted.
func ValidateConfig(channelType string, config map[string]any) error {
	if config == nil {
		return configErrorf("config is required")
	}
	switch channelType {
	case ChannelWebhook:
		return validateHTTPURL(config, "url", nil)
	case ChannelSlack:
		return validateHTTPURL(config, "webhook_url", nil)
	case ChannelDiscord:
		return validateHTTPURL(config, "webhook_url", isDiscordWebhookURL)
	case ChannelEmail:
		return validateEmailConfig(config)
	case ChannelSyslog:
		return validateSyslogConfig(config)
	default:
		return configErrorf("%s", ChannelTypesMessage)
	}
}

// validateHTTPURL checks that config[key] is an http(s) URL that passes the
// SSRF guard and, when extra is set, the channel's host allowlist.
func validateHTTPURL(config map[string]any, key string, extra func(*url.URL) error) error {
	raw := strings.TrimSpace(getString(config, key))
	if raw == "" {
		return configErrorf("config requires '%s'", key)
	}
	if err := ValidateOutboundURL(raw); err != nil {
		log.Printf("WARN: notification endpoint %s rejected: %v", key, err)
		return configErrorf("%s rejected: %s", key, CategorizeSendError(err))
	}
	if extra != nil {
		u, _ := url.Parse(raw)
		if err := extra(u); err != nil {
			return configErrorf("%s rejected: %v", key, err)
		}
	}
	config[key] = raw
	return nil
}

// discordWebhookHosts are the only hosts a Discord endpoint may post to.
var discordWebhookHosts = map[string]bool{
	"discord.com":    true,
	"discordapp.com": true,
}

// isDiscordWebhookURL accepts https://discord.com/api/webhooks/... and the
// discordapp.com alias only. Anything else is not a Discord webhook, and
// restricting the host keeps a Discord endpoint from being pointed at an
// arbitrary public server.
func isDiscordWebhookURL(u *url.URL) error {
	if u == nil {
		return errors.New("invalid url")
	}
	if strings.ToLower(u.Scheme) != "https" {
		return errors.New("must use https")
	}
	host := strings.ToLower(u.Hostname())
	if !discordWebhookHosts[host] {
		return errors.New("host must be discord.com or discordapp.com")
	}
	if u.Port() != "" && u.Port() != "443" {
		return errors.New("port must be 443")
	}
	if !strings.HasPrefix(u.Path, "/api/webhooks/") || len(u.Path) <= len("/api/webhooks/") {
		return errors.New("path must start with /api/webhooks/")
	}
	return nil
}

// Email security modes.
const (
	EmailSecurityStartTLS = "starttls"
	EmailSecurityTLS      = "tls"
	EmailSecurityNone     = "none"
)

func validateEmailConfig(config map[string]any) error {
	host := strings.TrimSpace(getString(config, "smtp_host"))
	if host == "" {
		return configErrorf("email config requires 'smtp_host'")
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/ \t") {
		return configErrorf("smtp_host must be a host name or address, not a URL")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip == nil && strings.Contains(host, ":") {
		return configErrorf("smtp_host must not include a port; use smtp_port")
	}
	config["smtp_host"] = host

	port, err := getPort(config, "smtp_port", defaultSMTPPort)
	if err != nil {
		return err
	}
	config["smtp_port"] = port

	security := strings.ToLower(strings.TrimSpace(getString(config, "security")))
	switch security {
	case "":
		security = EmailSecurityStartTLS
	case EmailSecurityStartTLS, EmailSecurityTLS, EmailSecurityNone:
	default:
		return configErrorf("security must be one of: starttls, tls, none")
	}
	config["security"] = security

	from := strings.TrimSpace(getString(config, "from"))
	if from == "" {
		return configErrorf("email config requires 'from'")
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return configErrorf("from is not a valid email address")
	}
	config["from"] = from

	to, err := getStringList(config, "to")
	if err != nil {
		return configErrorf("to must be a list of email addresses")
	}
	if len(to) == 0 {
		return configErrorf("email config requires at least one 'to' address")
	}
	if len(to) > maxEmailRecipients {
		return configErrorf("to may hold at most %d addresses", maxEmailRecipients)
	}
	clean := make([]any, 0, len(to))
	for _, addr := range to {
		addr = strings.TrimSpace(addr)
		if _, err := mail.ParseAddress(addr); err != nil {
			return configErrorf("to contains an invalid email address")
		}
		clean = append(clean, addr)
	}
	config["to"] = clean

	prefix := getString(config, "subject_prefix")
	if len(prefix) > maxSubjectPrefixLen {
		return configErrorf("subject_prefix may be at most %d characters", maxSubjectPrefixLen)
	}
	if strings.ContainsAny(prefix, "\r\n") {
		return configErrorf("subject_prefix must not contain line breaks")
	}
	username := getString(config, "username")
	if strings.ContainsAny(username, "\r\n\x00") {
		return configErrorf("username invalid")
	}
	if security == EmailSecurityNone && username != "" {
		// net/smtp refuses PLAIN auth on a cleartext connection to anything but
		// localhost; say so at configuration time rather than at delivery.
		if !isLocalhostName(host) && !isLoopbackLiteral(host) {
			return configErrorf("security 'none' cannot be combined with a username (credentials would be sent in cleartext); use starttls or tls")
		}
	}
	return nil
}

func isLoopbackLiteral(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// Syslog transports.
const (
	SyslogUDP    = "udp"
	SyslogTCP    = "tcp"
	SyslogTCPTLS = "tcp+tls"
)

// syslogFacilities maps RFC 5424 facility names to their numeric codes.
var syslogFacilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
	"uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11, "ntp": 12, "security": 13, "console": 14, "solaris-cron": 15,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

func validateSyslogConfig(config map[string]any) error {
	host := strings.TrimSpace(getString(config, "host"))
	if host == "" {
		return configErrorf("syslog config requires 'host'")
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/ \t") {
		return configErrorf("host must be a host name or address, not a URL")
	}
	config["host"] = host

	protocol := strings.ToLower(strings.TrimSpace(getString(config, "protocol")))
	switch protocol {
	case "":
		protocol = SyslogUDP
	case SyslogUDP, SyslogTCP, SyslogTCPTLS:
	default:
		return configErrorf("protocol must be one of: udp, tcp, tcp+tls")
	}
	config["protocol"] = protocol

	defPort := defaultSyslogUDPPort
	if protocol == SyslogTCPTLS {
		defPort = defaultSyslogTLSPort
	}
	port, err := getPort(config, "port", defPort)
	if err != nil {
		return err
	}
	config["port"] = port

	facility := strings.ToLower(strings.TrimSpace(getString(config, "facility")))
	if facility == "" {
		if n, ok := getInt(config, "facility"); ok {
			if n < 0 || n > 23 {
				return configErrorf("facility must be a name (local0..local7, auth, daemon, ...) or 0-23")
			}
			facility = facilityName(n)
		} else {
			facility = "local0"
		}
	}
	if _, ok := syslogFacilities[facility]; !ok {
		if n, err := strconv.Atoi(facility); err == nil && n >= 0 && n <= 23 {
			facility = facilityName(n)
		} else {
			return configErrorf("facility must be a name (local0..local7, auth, daemon, ...) or 0-23")
		}
	}
	config["facility"] = facility

	caFile := strings.TrimSpace(getString(config, "ca_file"))
	if caFile != "" {
		if protocol != SyslogTCPTLS {
			return configErrorf("ca_file is only used with protocol tcp+tls")
		}
		if !filepath.IsAbs(caFile) {
			return configErrorf("ca_file must be an absolute path on the backend host")
		}
		if _, err := loadCertPool(caFile); err != nil {
			return configErrorf("ca_file could not be read as a PEM certificate bundle")
		}
	}
	config["ca_file"] = caFile
	if v, ok := config["insecure_skip_verify"]; ok {
		if _, isBool := v.(bool); !isBool {
			return configErrorf("insecure_skip_verify must be true or false")
		}
	}
	return nil
}

func facilityName(n int) string {
	for name, code := range syslogFacilities {
		if code == n {
			return name
		}
	}
	return "local0"
}

// --- secrets ---

// SealSecrets encrypts the plaintext secrets of config in place: each secret
// key is replaced by "<key>_encrypted". A plaintext secret that is absent or
// empty is left alone (an update may omit it to keep the stored value; see
// MergeSecrets). Without a cipher the plaintext is removed and an error is
// returned so a secret is never written in the clear.
func SealSecrets(c *secrets.Cipher, channelType string, config map[string]any) error {
	for _, key := range secretKeys[channelType] {
		plain, _ := config[key].(string)
		delete(config, key)
		if plain == "" {
			continue
		}
		if c == nil {
			return secrets.ErrNoCipher
		}
		sealed, err := c.Encrypt(plain)
		if err != nil {
			return err
		}
		config[key+EncryptedSuffix] = sealed
	}
	return nil
}

// MergeSecrets carries the sealed secrets of an existing config over to a
// replacement config that does not set a new plaintext value for them, so a
// PUT that resends the redacted config (or leaves the password field blank)
// keeps the stored password.
func MergeSecrets(channelType string, existing, replacement map[string]any) {
	if existing == nil || replacement == nil {
		return
	}
	for _, key := range secretKeys[channelType] {
		if plain, _ := replacement[key].(string); plain != "" {
			continue
		}
		if sealed, ok := existing[key+EncryptedSuffix]; ok {
			replacement[key+EncryptedSuffix] = sealed
		} else if legacy, ok := existing[key].(string); ok && legacy != "" && replacement[key] == nil {
			// Endpoints created before secrets were sealed keep working until
			// the secret is re-entered, at which point it is sealed.
			replacement[key] = legacy
		}
	}
}

// Redacted returns a copy of e whose secrets are removed. Each secret key
// becomes "<key>_set": true/false so the dashboard can show that a value
// exists without ever receiving it. This is what every API response carries.
func Redacted(e Endpoint) Endpoint {
	out := e
	out.Config = make(map[string]any, len(e.Config)+1)
	for k, v := range e.Config {
		out.Config[k] = v
	}
	for _, key := range secretKeys[e.ChannelType] {
		_, hasSealed := out.Config[key+EncryptedSuffix]
		legacy, _ := out.Config[key].(string)
		delete(out.Config, key+EncryptedSuffix)
		delete(out.Config, key)
		out.Config[key+"_set"] = hasSealed || legacy != ""
	}
	return out
}

// ResolveSecret returns the plaintext of a secret config value: the sealed
// "<key>_encrypted" entry opened with c, or the legacy plaintext entry. It
// returns "" when the secret is not configured, and secrets.ErrNoCipher when
// a sealed value exists but this process has no cipher (LLM_ENCRYPTION_KEY
// unset).
func ResolveSecret(c *secrets.Cipher, config map[string]any, key string) (string, error) {
	if sealed, ok := config[key+EncryptedSuffix].(string); ok && sealed != "" {
		if c == nil {
			return "", secrets.ErrNoCipher
		}
		plain, err := c.Decrypt(sealed)
		if err != nil {
			return "", fmt.Errorf("decrypt %s: %w", key, err)
		}
		return plain, nil
	}
	plain, _ := config[key].(string)
	return plain, nil
}

// --- typed accessors (JSON numbers arrive as float64) ---

func getString(config map[string]any, key string) string {
	s, _ := config[key].(string)
	return s
}

func getInt(config map[string]any, key string) (int, bool) {
	switch v := config[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func getBool(config map[string]any, key string) bool {
	b, _ := config[key].(bool)
	return b
}

// getPort reads an optional port, applying def when absent.
func getPort(config map[string]any, key string, def int) (int, error) {
	if _, present := config[key]; !present || config[key] == "" {
		return def, nil
	}
	n, ok := getInt(config, key)
	if !ok || n < 1 || n > 65535 {
		return 0, configErrorf("%s must be a port number between 1 and 65535", key)
	}
	return n, nil
}

// getStringList reads a list of strings; a single comma-separated string is
// accepted too, since that is what a form field produces.
func getStringList(config map[string]any, key string) ([]string, error) {
	switch v := config[key].(type) {
	case nil:
		return nil, nil
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, errors.New("not a string")
			}
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	case string:
		var out []string
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	default:
		return nil, errors.New("not a list")
	}
}

// loadCertPool reads a PEM bundle into a cert pool (syslog tcp+tls ca_file).
func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificates found")
	}
	return pool, nil
}

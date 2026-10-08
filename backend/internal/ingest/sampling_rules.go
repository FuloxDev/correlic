package ingest

import (
	"strings"

	"github.com/correlic/correlic-backend/internal/event"
)

// SamplingRules defines which events to keep vs. drop.
type SamplingRules struct {
	// AlwaysKeep: critical event types that should never be sampled
	AlwaysKeep map[string]bool

	// SampleRates: event type -> probability of keeping (0.0 to 1.0)
	SampleRates map[string]float64

	// BenignProcesses: executables to always drop (shell utilities, etc.)
	BenignProcesses map[string]bool

	// HighValueProcesses: executables to always keep (docker, cursor, etc.)
	HighValueProcesses map[string]bool

	// UserWatchlist: user-defined file paths/patterns to always monitor
	// Example: []string{"/home/user/secrets.txt", "/opt/myapp/config.json", "*.wallet"}
	UserWatchlist []string
}

// DefaultSamplingRules returns production-ready sampling rules.
// Goal: Reduce data volume by 90% while keeping all high-value events.
func DefaultSamplingRules() *SamplingRules {
	return &SamplingRules{
		// Tier 1: Always keep (security-critical)
		AlwaysKeep: map[string]bool{
			"process_exec": true, // But filtered by process name
			"process_exit": false,
			"net_dns":      true, // Required for ai.suspicious_dns detection
			"ai_tool_call": true, // Every AI tool-hook call is an audit record (correlic-hook)
		},

		// Tier 2 & 3: Sample rates (must match agent event type names)
		SampleRates: map[string]float64{
			"net_connect": 0.1,  // Keep 10% of network connections
			"file_open":   0.05, // Keep 5% of file opens
		},

		// Tier 4: Benign processes to drop
		BenignProcesses: map[string]bool{
			"/bin/ls":     true,
			"/bin/ps":     true,
			"/usr/bin/ls": true,
			"/usr/bin/ps": true,
			// NOTE: /bin/cat removed - commonly used in credential theft (cat /etc/shadow, cat ~/.ssh/id_rsa)
		},

		// High-value processes to always keep
		HighValueProcesses: map[string]bool{
			"docker":  true,
			"cursor":  true,
			"kubectl": true,
		},

		// User-defined watchlist (empty by default, can be configured per-organization)
		// Examples of what users might want to monitor:
		// - Cryptocurrency wallets: "*.wallet", ".bitcoin/", ".ethereum/"
		// - Proprietary files: "/opt/company/secrets/", "*.proprietary"
		// - Custom configs: "/home/*/myapp.conf"
		UserWatchlist: []string{
			// Add user-specific patterns here or load from config/database
		},
	}
}

// IsAlwaysKeep returns true if the event type should always be kept.
func (r *SamplingRules) IsAlwaysKeep(eventType string) bool {
	keep, exists := r.AlwaysKeep[eventType]
	return exists && keep
}

// IsBenignProcess returns true if the process is known to be benign.
func (r *SamplingRules) IsBenignProcess(evt *event.Event) bool {
	if evt.Process == nil || evt.Process.ExePath == "" {
		return false
	}

	exePath := evt.Process.ExePath
	for benign := range r.BenignProcesses {
		if strings.Contains(exePath, benign) {
			return true
		}
	}

	return false
}

// IsSuspicious returns true if the event exhibits suspicious characteristics.
func (r *SamplingRules) IsSuspicious(evt *event.Event) bool {
	// Check for high-value processes
	if evt.Process != nil && evt.Process.ExePath != "" {
		for hvProc := range r.HighValueProcesses {
			if strings.Contains(evt.Process.ExePath, hvProc) {
				return true
			}
		}
	}

	// Check for suspicious file paths (credentials, keys, configs, etc.)
	if evt.Target != nil && evt.Target.FilePath != "" {
		// First check user-defined watchlist (highest priority)
		for _, pattern := range r.UserWatchlist {
			if matchesPattern(evt.Target.FilePath, pattern) {
				return true
			}
		}

		// Then check built-in suspicious patterns
		if _, ok := MatchSuspiciousPath(evt.Target.FilePath); ok {
			return true
		}
	}

	return false
}

// builtinSuspiciousPaths are the file-path patterns that mark an event as
// suspicious regardless of the process (see matchesPattern for the syntax).
// They are shared with the AI tool-hook detection rule
// (detection/ai_pack: ai.tool_call_sensitive_path).
var builtinSuspiciousPaths = []string{
	// SSH & Crypto Keys
	".ssh/",
	"id_rsa",
	"id_ed25519",
	"id_ecdsa",
	"id_dsa",
	".pem",
	".key",
	"authorized_keys",
	"known_hosts",

	// Cloud Provider Credentials
	".aws/",
	".azure/",
	".gcloud/",
	".kube/",
	"credentials",
	"config", // AWS/kubectl config

	// System Authentication & Passwords
	"/etc/shadow",
	"/etc/passwd",
	"/etc/group",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/security/",
	"password",
	"secret",
	"token",
	"api_key",
	"apikey",

	// Container & Orchestration Secrets
	"/run/secrets/",     // Docker secrets
	"/var/run/secrets/", // Kubernetes secrets
	"docker.sock",
	".dockercfg",
	".docker/config.json",

	// Database Credentials & Configs
	".pgpass",
	".my.cnf",
	"database.yml",
	"db.conf",
	".env", // Environment files often contain secrets

	// Application Secrets
	".npmrc",
	".pypirc",
	".netrc",
	"settings.py", // Django settings
	"application.properties",
	"application.yml",

	// Certificate & TLS
	".crt",
	".cert",
	".p12",
	".pfx",
	"ca-bundle",

	// Kernel & System Internals (potential privilege escalation)
	"/proc/",
	"/sys/kernel/",
	"/dev/mem",
	"/dev/kmem",
	"/boot/",

	// Sensitive System Configs
	"/etc/crontab",
	"/etc/cron.",
	"/etc/ssh/sshd_config",
	"/etc/pam.d/",
	"/etc/ld.so.conf",

	// Logs (may contain sensitive data)
	"/var/log/auth.log",
	"/var/log/secure",
	"/var/log/audit/",

	// Browser & Email Data
	".mozilla/",
	".thunderbird/",
	"cookies.sqlite",
	"logins.json",

	// Version Control (may contain secrets)
	".git/config",
	".gitconfig",
	".svn/",

	// Windows credential stores (paths normalized to forward slashes)
	"C:/Windows/System32/config/SAM",
	"C:/Windows/System32/config/SYSTEM",
	"C:/Windows/System32/config/SECURITY",
	"/AppData/Roaming/Microsoft/Protect/",   // DPAPI master keys
	"/AppData/Local/Microsoft/Credentials/", // Windows Credential Manager
	"ntds.dit",                              // Active Directory database

	// Windows persistence paths
	"C:/Windows/System32/Tasks/",
	"/Start Menu/Programs/Startup/",
}

// MatchSuspiciousPath reports the first built-in suspicious-path pattern that
// path matches, for callers outside the sampler (detection rules on hook
// events). The per-org user watchlist is not consulted here.
func MatchSuspiciousPath(path string) (pattern string, ok bool) {
	if path == "" {
		return "", false
	}
	for _, p := range builtinSuspiciousPaths {
		if matchesPattern(path, p) {
			return p, true
		}
	}
	return "", false
}

// GetSampleRate returns the sample rate for an event type.
func (r *SamplingRules) GetSampleRate(eventType string) float64 {
	if rate, ok := r.SampleRates[eventType]; ok {
		return rate
	}
	return 1.0 // Default: keep all if not specified
}

// matchesPattern matches a file path against a suspicious-path pattern:
//
//   - patterns containing "*" are simple globs: a single "*" splits the pattern into a
//     required prefix and suffix ("*.key", "/home/*/.ssh/"); multiple "*" are matched
//     as ordered segments ("/home/*/.aws/*");
//   - patterns starting with "/" are absolute path prefixes ("/etc/shadow" matches
//     "/etc/shadow" and "/etc/shadow-");
//   - every other pattern is a substring (".ssh/", "id_rsa", "credentials"), so
//     "/home/alice/.ssh/id_rsa" matches ".ssh/" even though it is not a prefix.
func matchesPattern(path, pattern string) bool {
	if pattern == "" {
		return false
	}

	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			return strings.HasPrefix(path, parts[0]) && strings.HasSuffix(path, parts[1])
		}
		return matchGlobSegments(path, parts)
	}

	if strings.HasPrefix(pattern, "/") {
		return strings.HasPrefix(path, pattern)
	}

	return strings.Contains(path, pattern)
}

// matchGlobSegments matches path against the literal segments of a multi-"*" pattern:
// the first segment must be a prefix, the last a suffix, and the middle ones must
// appear in order in between.
func matchGlobSegments(path string, parts []string) bool {
	if len(parts) == 0 {
		return true
	}
	if !strings.HasPrefix(path, parts[0]) {
		return false
	}
	rest := path[len(parts[0]):]
	last := parts[len(parts)-1]
	if !strings.HasSuffix(rest, last) {
		return false
	}
	rest = rest[:len(rest)-len(last)]
	for _, seg := range parts[1 : len(parts)-1] {
		if seg == "" {
			continue
		}
		idx := strings.Index(rest, seg)
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(seg):]
	}
	return true
}

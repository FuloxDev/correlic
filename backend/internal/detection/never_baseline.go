package detection

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/correlic/correlic-backend/internal/event"
)

// NeverBaselineChecker is satisfied by storage.NeverBaselineStore.
// Allows the detection layer to check user-defined never-baseline rules
// without importing the storage package.
type NeverBaselineChecker interface {
	MatchesAny(orgID, signalType, pattern string) bool
}

// SystemNeverBaselineEntry represents a single hardcoded never-baseline rule
// for display on the Never Baseline management page.
type SystemNeverBaselineEntry struct {
	SignalType  string `json:"signal_type"`
	Pattern    string `json:"pattern"`
	Category   string `json:"category"`  // "file_suffix", "file_dir", "file_name", "port", "domain", "binary"
	Source     string `json:"source"`    // always "system"
}

// SystemNeverBaselineEntries returns all hardcoded never-baseline rules as structs
// so the API can expose them for display. These entries cannot be deleted.
func SystemNeverBaselineEntries() []SystemNeverBaselineEntry {
	var out []SystemNeverBaselineEntry
	for _, s := range neverBaselineFileSuffixes {
		out = append(out, SystemNeverBaselineEntry{SignalType: "file_pattern", Pattern: s, Category: "file_suffix", Source: "system"})
	}
	for _, d := range neverBaselineFileDirs {
		out = append(out, SystemNeverBaselineEntry{SignalType: "file_pattern", Pattern: d, Category: "file_dir", Source: "system"})
	}
	for _, n := range neverBaselineFileNames {
		out = append(out, SystemNeverBaselineEntry{SignalType: "file_pattern", Pattern: n, Category: "file_name", Source: "system"})
	}
	for port := range neverBaselinePorts {
		out = append(out, SystemNeverBaselineEntry{SignalType: "network_dest", Pattern: strconv.Itoa(port), Category: "port", Source: "system"})
	}
	for _, d := range neverBaselineDomainSuffixes {
		out = append(out, SystemNeverBaselineEntry{SignalType: "dns_domain", Pattern: d, Category: "domain", Source: "system"})
	}
	for bin := range neverBaselineBinaries {
		out = append(out, SystemNeverBaselineEntry{SignalType: "binary", Pattern: bin, Category: "binary", Source: "system"})
	}
	return out
}

// neverBaselineFileSuffixes are file name suffixes that must NEVER be auto-baselined.
// These represent crypto material and key files.
var neverBaselineFileSuffixes = []string{
	".pem", "_rsa", "_ecdsa", "_ed25519", ".key", ".p12", ".pfx",
	".asc", ".gpg", ".pgp", // GPG/PGP keys
}

// neverBaselineFileDirs are directory segments — any file inside these dirs is never-baselined.
// Uses strings.Contains on the full path for reliable matching on absolute paths.
var neverBaselineFileDirs = []string{
	"/.ssh/",
	"/.azure/",
	"/.config/gcloud/",
	"/.kube/cache/",
	"/etc/sudoers.d/",
	// Persistence mechanisms
	"/var/spool/cron/",
	"/etc/cron.d/",
	"/etc/cron.daily/",
	"/etc/cron.hourly/",
	"/etc/cron.weekly/",
	"/etc/cron.monthly/",
	"/etc/init.d/",
	"/etc/systemd/system/",
	"/.git/hooks/",
	"/etc/pam.d/",
	"/etc/ld.so.conf.d/",
	"/etc/modules-load.d/",
}

// neverBaselineFileNames are exact basenames that must NEVER be auto-baselined.
var neverBaselineFileNames = []string{
	"shadow", "passwd", "sudoers", ".gitconfig",
	// Persistence mechanisms
	"crontab", "authorized_keys", "rc.local",
	"ld.so.preload", "sshrc", "krb5.keytab",
	"terraform.tfstate", ".git-credentials",
}

// neverBaselineExactParentDirs are directories where files directly inside them should
// never be baselined, but files in deeper subdirectories are OK.
// E.g. "/home/CLAUDE.md" is blocked but "/home/fulox/project/file.go" is allowed.
var neverBaselineExactParentDirs = []string{
	"/home",
	"/tmp",
	"/",
}

// neverBaselinePorts are ports commonly used by C2 frameworks, exploit tools, and
// reverse shells. Connections to these ports must never be passively baselined.
var neverBaselinePorts = map[int]bool{
	4444:  true, // Metasploit default
	5555:  true, // Common RAT
	1337:  true, // Common hacker port
	6666:  true, // IRC (C2)
	6667:  true, // IRC (C2)
	8888:  true, // Common alt HTTP (malware C2)
	9001:  true, // Tor default
	9050:  true, // Tor SOCKS
	9150:  true, // Tor Browser SOCKS
	31337: true, // Back Orifice
	4443:  true, // Alt HTTPS C2
	3333:  true, // Crypto mining pool
	2375:  true, // Docker API (unencrypted)
}

// neverBaselineDomainSuffixes are domain patterns that should never be passively
// baselined. Uses suffix matching since domains are not file paths.
var neverBaselineDomainSuffixes = []string{
	".onion",
	".i2p",
	"pastebin.com",
	"paste.ee",
	"ghostbin.com",
	"transfer.sh",
	"file.io",
	"0x0.st",
	"dpaste.org",
	"anonfiles.com",
	"ngrok.io",
	"ngrok-free.app",
}

// neverBaselineBinaries are binary names that must NEVER be auto-baselined.
// These are commonly used in attacks or post-exploitation.
var neverBaselineBinaries = map[string]bool{
	// Reverse shell / tunneling
	"nc":    true,
	"ncat":  true,
	"socat": true,
	"nmap":  true,

	// Data exfiltration / encoding
	"base64": true,
	"xxd":    true,

	// User manipulation
	"useradd":  true,
	"usermod":  true,
	"passwd":   true,
	"visudo":   true,
	"chpasswd": true,

	// Permission manipulation
	"chmod":  true,
	"chown":  true,
	"setcap": true,

	// Privilege escalation
	"sudo":    true,
	"su":      true,
	"pkexec":  true,
	"doas":    true,
	"nsenter": true,
	"capsh":   true,
	"mount":   true,

	// Kernel module manipulation
	"modprobe": true,
	"insmod":   true,
	"rmmod":    true,

	// Persistence commands
	"crontab": true,

	// New privilege escalation binaries
	"setpriv":    true,
	"runuser":    true,
	"debugfs":    true,
	"newuidmap":  true,
	"newgidmap":  true,
	"chroot":     true,
	"machinectl": true,

	// Process injection / debugging
	"strace": true,
	"ltrace": true,
	"gdb":    true,

	// Raw disk access
	"dd": true,

	// Packet capture
	"tcpdump": true,
	"tshark":  true,

	// Firewall manipulation
	"iptables":  true,
	"ip6tables": true,
	"nft":       true,

	// Data transfer tools
	"rclone": true,
	"sshpass": true,
}

// IsNeverBaselinePattern checks if a signal_type + pattern combination should never
// be baselined. Used by LearnFromFinding to prevent users from creating dangerous
// user_confirmed baselines (e.g. "Allow Always" on SSH key access).
// Pass dynamic=nil and orgID="" to skip the user-defined check.
func IsNeverBaselinePattern(signalType, pattern string, dynamic NeverBaselineChecker, orgID string) bool {
	if dynamic != nil && dynamic.MatchesAny(orgID, signalType, pattern) {
		return true
	}
	return isNeverBaselinePatternHardcoded(signalType, pattern)
}

// isNeverBaselinePatternHardcoded checks only the compile-time never-baseline lists.
func isNeverBaselinePatternHardcoded(signalType, pattern string) bool {
	switch signalType {
	case "file_pattern", "credential_file", "persistence_path", "code_tamper", "file_activity":
		// Strip the trailing /** to get the directory path for checking
		dirPath := strings.TrimSuffix(pattern, "/**")
		if dirPath == "" {
			return false
		}
		// Check crypto material suffixes
		for _, suffix := range neverBaselineFileSuffixes {
			if strings.HasSuffix(dirPath, suffix) {
				return true
			}
		}
		// Check sensitive directory containment
		for _, dir := range neverBaselineFileDirs {
			if strings.Contains(dirPath+"/", dir) {
				return true
			}
		}
		// Check exact basename matches
		basename := filepath.Base(dirPath)
		for _, name := range neverBaselineFileNames {
			if basename == name {
				return true
			}
		}
		// For exact file patterns (not directory wildcards), check parent dir restrictions
		isWildcard := strings.HasSuffix(pattern, "/**")
		if !isWildcard {
			// Check if file is directly inside a never-baseline parent dir
			parentDir := filepath.Dir(dirPath)
			for _, dir := range neverBaselineExactParentDirs {
				if parentDir == dir {
					return true
				}
			}
			// Never baseline files directly in a user's home directory
			if isDirectlyInUserHome(dirPath) {
				return true
			}
		}

	case "network_dest":
		// Extract port from "ip:port" or "cidr:port" pattern
		if idx := strings.LastIndex(pattern, ":"); idx >= 0 {
			portStr := pattern[idx+1:]
			port := 0
			for _, ch := range portStr {
				if ch >= '0' && ch <= '9' {
					port = port*10 + int(ch-'0')
				} else {
					port = 0
					break
				}
			}
			if port > 0 && neverBaselinePorts[port] {
				return true
			}
		}

	case "dns_domain":
		domain := strings.ToLower(pattern)
		for _, suffix := range neverBaselineDomainSuffixes {
			if strings.HasSuffix(domain, suffix) {
				return true
			}
		}

	case "binary":
		basename := filepath.Base(pattern)
		if neverBaselineBinaries[basename] {
			return true
		}
	}

	return false
}

// IsNeverBaselineEvent checks if an event should never be passively baselined.
func IsNeverBaselineEvent(evt *event.Event) bool {
	if evt == nil {
		return false
	}

	switch evt.Type {
	case "file_open", "file_write":
		return isNeverBaselineFile(evt)
	case "process_exec":
		return isNeverBaselineBinary(evt)
	case "net_connect":
		return isNeverBaselineNetConnect(evt)
	case "net_dns":
		return isNeverBaselineDNS(evt)
	default:
		return false
	}
}

// isNeverBaselineFile checks if a file path matches the never-baseline lists.
// Uses string containment and suffix matching instead of filepath.Match,
// which cannot match across path separators on absolute paths.
func isNeverBaselineFile(evt *event.Event) bool {
	path := ""
	if evt.Target != nil {
		path = evt.Target.FilePath
	}
	if path == "" {
		return false
	}

	basename := filepath.Base(path)

	// Check crypto material suffixes
	for _, suffix := range neverBaselineFileSuffixes {
		if strings.HasSuffix(basename, suffix) {
			return true
		}
	}

	// Check sensitive directory containment
	for _, dir := range neverBaselineFileDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}

	// Check exact basename matches
	for _, name := range neverBaselineFileNames {
		if basename == name {
			return true
		}
	}

	// Check if file is directly inside a never-baseline parent dir
	parentDir := filepath.Dir(path)
	for _, dir := range neverBaselineExactParentDirs {
		if parentDir == dir {
			return true
		}
	}

	// Never baseline files directly in a user's home directory (/home/<user>/<file>).
	// These are dotfiles and configs, not project files.
	if isDirectlyInUserHome(path) {
		return true
	}

	return false
}

// isDirectlyInUserHome returns true if path is a file sitting directly inside
// /home/<user>/ (depth=3, e.g. /home/fulox/.npmrc) but NOT deeper paths
// like /home/fulox/projects/file.go.
func isDirectlyInUserHome(path string) bool {
	if !strings.HasPrefix(path, "/home/") {
		return false
	}
	// /home/<user>/<file> → split on "/" gives ["", "home", "user", "file"]
	parts := strings.Split(path, "/")
	return len(parts) == 4
}

// isNeverBaselineBinary checks if a binary name is in the never-baseline list.
func isNeverBaselineBinary(evt *event.Event) bool {
	if evt.Process == nil {
		return false
	}

	// Check comm (short name)
	comm := evt.Process.Comm
	if comm != "" {
		basename := filepath.Base(comm)
		if neverBaselineBinaries[basename] {
			return true
		}
	}

	// Check exe path basename
	exePath := evt.Process.ExePath
	if exePath != "" {
		basename := filepath.Base(exePath)
		if neverBaselineBinaries[basename] {
			return true
		}
	}

	return false
}

// isNeverBaselineNetConnect checks if a network connection targets a high-risk port.
func isNeverBaselineNetConnect(evt *event.Event) bool {
	if evt.Target == nil {
		return false
	}
	return neverBaselinePorts[evt.Target.Port]
}

// isNeverBaselineDNS checks if a domain matches the never-baseline suffix list.
func isNeverBaselineDNS(evt *event.Event) bool {
	if evt.Target == nil || evt.Target.Domain == "" {
		return false
	}
	domain := strings.ToLower(evt.Target.Domain)
	for _, suffix := range neverBaselineDomainSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

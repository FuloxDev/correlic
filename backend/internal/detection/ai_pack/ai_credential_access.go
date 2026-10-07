package ai_pack

import (
	"path/filepath"
	"strings"

	"github.com/correlic/correlic-backend/internal/detection"
)

// credentialAccessIgnoredDirs are well-known AI agent and IDE configuration directories
// that contain files with credential-like names but are not actual credentials.
var credentialAccessIgnoredDirs = []string{
	"/.vscode/",
	"/.claude/",
	"/.cursor/",
	"/.continue/",
	"/.copilot/",
	"/.codeium/",
	"/.aider/",
	"/.config/Code/",
	"/.config/cursor/",
	"/.config/Claude/",
	"/.config/gh/",
	"/.config/git/",
	// Note: /.docker/ and /.kube/ intentionally NOT ignored — they contain
	// real credential files (config.json, config) detected via tier2SensitivePaths.
	"/.npm/",
	"/.yarn/",
	"/.pnpm/",
	"/.cargo/",
	"/.rustup/",
	"/.local/share/",
}

// tier1SensitiveDirs are directory segments — any file inside these is Tier 1 sensitive.
// Uses strings.Contains for reliable matching on absolute paths (filepath.Match
// with "*" does NOT cross "/" boundaries, making patterns like "*/etc/shadow" dead code).
var tier1SensitiveDirs = []string{
	"/.ssh/",
	"/etc/sudoers.d/",
	"/run/secrets/",
	// Windows DPAPI and Credential Manager
	"/AppData/Roaming/Microsoft/Protect/",  // DPAPI master keys
	"/AppData/Local/Microsoft/Credentials/", // Windows Credential Manager
}

// sshNonCredentialBasenames are files in /.ssh/ that are NOT credentials.
// These are configuration/metadata files handled by other detections (ai.persistence).
// Without this exclusion, a single .ssh/config access would fire both
// ai.credential_access AND ai.persistence, creating a false attack chain.
var sshNonCredentialBasenames = map[string]bool{
	"config":      true, // SSH client config (persistence vector via ProxyCommand, not a credential)
	"known_hosts": true, // Host fingerprints, not secrets
	"environment": true, // SSH env setup, not secrets
}

// tier1SensitiveBasenames are exact basenames that are always Tier 1 sensitive.
var tier1SensitiveBasenames = map[string]bool{
	"shadow":          true,
	"passwd":          true,
	"sudoers":         true,
	"authorized_keys": true,
	"krb5.keytab":     true, // Kerberos keytab
	// Windows SAM database and registry hives
	"SAM":      true, // C:\Windows\System32\config\SAM — local account password hashes
	"SYSTEM":   true, // C:\Windows\System32\config\SYSTEM — needed to decrypt SAM
	"SECURITY": true, // C:\Windows\System32\config\SECURITY — LSA secrets
	"ntds.dit": true, // Active Directory database — all domain password hashes
}

// tier2SensitiveDirs are directory segments for Tier 2 sensitive files.
// Note: /.aws/ and /.kube/ are handled via tier2SensitivePaths (require specific basenames)
// to avoid flagging every file in those directories.
var tier2SensitiveDirs = []string{}

// tier2SensitiveBasenames are exact basenames that are Tier 2 sensitive regardless of directory.
var tier2SensitiveBasenames = map[string]bool{
	".env":             true,
	".netrc":           true,
	".npmrc":           true,
	".pypirc":          true,
	".git-credentials": true, // Git credential store (plaintext)
	".boto":            true, // GCS credentials
	".s3cfg":           true, // S3 credentials
	".dockercfg":       true, // Legacy Docker auth
	"terraform.tfstate": true, // Contains plaintext secrets
}

// tier2SensitivePaths are (dir, basename) pairs that require both to match.
// This prevents false positives from bare basenames like "credentials" or "config.json"
// appearing outside their expected directories.
var tier2SensitivePaths = []struct{ dir, basename string }{
	{"/.aws/", "credentials"},
	{"/.aws/", "config"},
	{"/.kube/", "config"},
	{"/.docker/", "config.json"},
}

// tier1SensitiveExtensions are always-high-risk credential material.
var tier1SensitiveExtensions = map[string]bool{
	".pem":      true,
	".key":      true,
	".p12":      true,
	".pfx":      true,
	".jks":      true,
	".keystore": true,
	".asc":      true, // GPG armored key
	".gpg":      true, // GPG binary key
	".pgp":      true, // PGP key
}

// AICredentialAccess detects when an AI agent reads sensitive credential files.
type AICredentialAccess struct{}

func (d *AICredentialAccess) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.credential_access",
		Pack:            "ai",
		Name:            "AI Credential Access",
		Severity:        "critical",
		Description:     "AI agent process accessed sensitive credential files (SSH keys, cloud credentials, certificates)",
		Tags:            []string{"ai", "credentials", "sensitive-files"},
		MITRETechniques: []string{"T1552", "T1552.004"},
	}
}

func (d *AICredentialAccess) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"file_open"},
		WindowSecs: 0, // No look-back needed, works on single event
	}
}

func (d *AICredentialAccess) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt.Process == nil || evt.Target == nil || evt.Target.FilePath == "" {
		return nil
	}

	// Check if the process belongs to an AI agent tree
	isAI, aiType, err := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if err != nil || !isAI {
		return nil
	}

	filePath := evt.Target.FilePath
	fileSize := evt.Target.FileSize

	// Skip well-known AI agent and IDE configuration directories — not real credentials.
	if isIgnoredCredentialPath(filePath) {
		return nil
	}

	// Zero-byte suppression: empty files are not real credentials.
	if fileSize == 0 {
		return nil
	}

	// Non-existent files cannot contain credentials (PATHEXT probes).
	// Windows PATH resolution generates file_open events for files that don't exist.
	if evt.Context != nil {
		if fe, ok := evt.Context["file_exists"]; ok {
			if fe == false || fe == "false" {
				return nil
			}
		}
	}

	// SSH reading its own config directory is expected behavior, not credential theft.
	if evt.Process != nil {
		comm := strings.ToLower(evt.Process.Comm)
		if (comm == "ssh" || comm == "ssh.exe" || comm == "scp" || comm == "sftp") && strings.Contains(filePath, "/.ssh/") {
			return nil
		}
	}

	// /proc/*/environ contains process environment variables — often has secrets.
	if strings.HasPrefix(filePath, "/proc/") && strings.HasSuffix(filePath, "/environ") {
		return []detection.Finding{
			{
				Title:      "AI agent read process environment variables",
				Summary:    aiType + " process accessed " + filePath,
				Confidence: 0.85,
				Context: map[string]any{
					"ai_type":          aiType,
					"file_path":        filePath,
					"pid":              evt.Process.PID,
					"comm":             evt.Process.Comm,
					"signal_type":      "credential_file",
					"pattern":          "/proc/*/environ",
					"mitre_techniques": []string{"T1552"},
				},
			},
		}
	}

	isTier1 := isTier1SensitiveFile(filePath)
	isTier2 := isTier2SensitiveFile(filePath)
	isKeyword := isCredentialKeywordFile(filePath)

	// Fire on Tier 1, Tier 2, or keyword-matched filenames.
	if !isTier1 && !isTier2 && !isKeyword {
		return nil
	}

	confidence := credentialConfidence(filePath, fileSize, isKeyword)
	signalType := "credential_file"
	if isKeyword && !isTier1 && !isTier2 {
		signalType = "keyword_heuristic"
	}

	// Pick specific MITRE technique: T1552.004 for private keys, T1552 for general credentials
	mitreTechniques := []string{"T1552"}
	ext := strings.ToLower(filepath.Ext(filePath))
	basename := filepath.Base(filePath)
	if tier1SensitiveExtensions[ext] || strings.Contains(basename, "_rsa") ||
		strings.Contains(basename, "_ecdsa") || strings.Contains(basename, "_ed25519") ||
		strings.Contains(filePath, "/.ssh/") {
		mitreTechniques = []string{"T1552.004"}
	}

	return []detection.Finding{
		{
			Title:      "AI agent accessed sensitive credentials",
			Summary:    aiType + " process accessed " + filePath,
			Confidence: confidence,
			Context: map[string]any{
				"ai_type":          aiType,
				"file_path":        filePath,
				"file_size":        fileSize,
				"pid":              evt.Process.PID,
				"comm":             evt.Process.Comm,
				"signal_type":      signalType,
				"pattern":          filepath.ToSlash(filepath.Dir(filePath)) + "/**",
				"mitre_techniques": mitreTechniques,
			},
		},
	}
}

// isIgnoredCredentialPath returns true if the path is inside a well-known AI agent
// or IDE configuration directory that should never trigger credential alerts.
func isIgnoredCredentialPath(path string) bool {
	for _, dir := range credentialAccessIgnoredDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}
	return false
}

// isCredentialKeywordFile returns true if the filename contains credential-related keywords.
// Excludes source code files — "ai_credential_access.go" contains the word "credential"
// but reading source code is not credential theft.
func isCredentialKeywordFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))

	// Skip source code files — they may contain credential-related words in their
	// names (ai_credential_access.go, token_store.py) but are not actual credentials.
	sourceExts := []string{".go", ".py", ".js", ".ts", ".java", ".rs", ".rb", ".php",
		".cs", ".cpp", ".c", ".h", ".swift", ".kt", ".scala", ".md", ".yml", ".yaml"}
	for _, ext := range sourceExts {
		if strings.HasSuffix(base, ext) {
			return false
		}
	}

	for _, kw := range []string{"token", "secret", "apikey", "password", "credential", "private_key"} {
		if strings.Contains(base, kw) {
			return true
		}
	}
	return false
}

// credentialConfidence returns a confidence score for a credential access finding.
// Crypto extensions score highest; SSH/path patterns depend on file size; keyword matches score lower.
func credentialConfidence(filePath string, fileSize int64, isKeyword bool) float64 {
	// Keyword-only match (not tier1): lower confidence regardless of size.
	if isKeyword && !isTier1SensitiveFile(filePath) {
		return 0.60
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	isCryptoExt := tier1SensitiveExtensions[ext]

	if isCryptoExt {
		if fileSize >= 100 && fileSize <= 10240 {
			return 0.95
		}
		return 0.85 // crypto extension but size outside ideal range
	}

	// SSH key path or other tier1 pattern.
	switch {
	case fileSize == -1:
		return 0.80 // unknown size (stat failed)
	case fileSize >= 100 && fileSize <= 10240:
		return 0.90
	case fileSize > 102400:
		return 0.50 // unusually large — unlikely to be a real key
	default:
		return 0.75 // size outside ideal range but plausible
	}
}

func isTier1SensitiveFile(path string) bool {
	// Check crypto material extensions
	ext := strings.ToLower(filepath.Ext(path))
	if tier1SensitiveExtensions[ext] {
		return true
	}

	// Check sensitive directory containment (/.ssh/, /etc/sudoers.d/, /run/secrets/)
	basename := filepath.Base(path)
	for _, dir := range tier1SensitiveDirs {
		if strings.Contains(path, dir) {
			// /.ssh/ contains non-credential files (config, known_hosts) that are
			// handled by ai.persistence. Exclude them to prevent double-firing.
			// Strip all Windows PATHEXT extensions (config.exe, config.bat, config.lnk → config).
			checkName := basename
			for _, pext := range []string{".exe", ".bat", ".cmd", ".com", ".lnk", ".vbs", ".vbe", ".wsf", ".wsh", ".msc", ".ps1"} {
				if strings.HasSuffix(strings.ToLower(checkName), pext) {
					checkName = checkName[:len(checkName)-len(pext)]
					break
				}
			}
			if dir == "/.ssh/" && sshNonCredentialBasenames[checkName] {
				continue
			}
			return true
		}
	}

	// Check exact sensitive basenames (shadow, passwd, sudoers, authorized_keys)
	if tier1SensitiveBasenames[basename] {
		return true
	}

	// Check SSH key name patterns (_rsa, _ecdsa, _ed25519)
	if strings.Contains(basename, "_rsa") || strings.Contains(basename, "_ecdsa") ||
		strings.Contains(basename, "_ed25519") {
		return true
	}

	return false
}

func isTier2SensitiveFile(path string) bool {
	basename := filepath.Base(path)

	// Check directory containment (/.aws/, /.kube/)
	for _, dir := range tier2SensitiveDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}

	// Check exact basenames (.env, .netrc, .npmrc, .pypirc)
	if tier2SensitiveBasenames[basename] {
		return true
	}

	// Check .env.* variants (e.g. .env.production, .env.local)
	if strings.HasPrefix(basename, ".env.") {
		return true
	}

	// Check (dir, basename) pairs that require both to match
	for _, p := range tier2SensitivePaths {
		if strings.Contains(path, p.dir) && basename == p.basename {
			return true
		}
	}

	return false
}

// isSensitiveFile is used by correlated rules (e.g. read-then-network exfiltration).
func isSensitiveFile(path string) bool {
	return isTier1SensitiveFile(path) || isTier2SensitiveFile(path)
}

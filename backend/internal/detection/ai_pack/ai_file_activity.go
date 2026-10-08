package ai_pack

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/correlic/correlic-backend/internal/detection"
)

// fileAlwaysNoise are paths that fire constantly from runtime internals and add
// no investigative value. Any file_open inside these directories is dropped.
var fileAlwaysNoise = []string{
	// Linux
	"/proc/",
	"/sys/",
	"/dev/",
	"/run/",
	"/tmp/.X11-unix/",
	// Windows
	"C:/Windows/Prefetch/",
	"C:/Windows/Temp/",
	"C:/Windows/WinSxS/",
	"C:/Windows/assembly/",
	"/AppData/Local/Temp/",
	"/AppData/Local/Microsoft/Windows/",
}

// fileExtNoise are extensions that are runtime artifacts (shared libs, caches,
// compiled bytecode). Tracking them creates massive noise with zero signal.
var fileExtNoise = map[string]bool{
	".so":    true,
	".pyc":   true,
	".pyo":   true,
	".class": true,
	".o":     true,
	".a":     true,
	".dylib": true,
	// Windows
	".dll": true,
	".pdb": true,
	".mui": true,
	".nls": true,
	".tmp": true,
	".log": true,
	// Windows PATHEXT probes — editors check every extension when searching PATH.
	// Excluded: .js/.jse (legitimate code files that ARE security-relevant)
	".bat": true,
	".cmd": true,
	".com": true,
	".vbs": true,
	".vbe": true,
	".wsf": true,
	".wsh": true,
	".msc": true,
}

// VCS directory probes — editors scan for repo roots by walking up directories.
var fileVCSProbes = map[string]bool{
	".git": true, ".svn": true, ".hg": true, ".bzr": true,
	".fslckout": true, "_FOSSIL_": true, ".gitmodules": true,
}

// Temp/build/cache directory segments — auto-generated artifacts.
var fileTempBuildNoise = []string{
	"/go-build/",
	"/node_modules/.cache/",
	"/__pycache__/",
	"/.cache/",
	"/go/pkg/mod/",
}

// AIFileActivity is a catch-all rule that tracks every file opened by an AI
// agent. It fires at low severity for visibility — users suppress noise via
// "Allow Always" baselines while keeping a full audit trail of file access.
//
// This rule explicitly skips files that are already covered by higher-severity
// rules (credential_access, code_tampering, persistence) to avoid duplicates.
//
// Dual-baseline support: findings carry signal_type="file_activity" with the
// exact file path as pattern. Users can "Allow File" (exact path) or
// "Allow Directory" (parent dir glob) from the UI.
type AIFileActivity struct{}

func (d *AIFileActivity) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.file_activity",
		Pack:            "ai",
		Name:            "AI File Activity",
		Severity:        "low",
		Description:     "AI agent accessed a file — tracked for audit visibility until baselined",
		Tags:            []string{"ai", "audit", "file", "activity"},
		MITRETechniques: []string{"T1083"},
	}
}

func (d *AIFileActivity) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"file_open"},
		WindowSecs: 0,
	}
}

func (d *AIFileActivity) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt.Process == nil || evt.Target == nil || evt.Target.FilePath == "" {
		return nil
	}

	isAI, aiType, err := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if err != nil || !isAI {
		return nil
	}

	filePath := evt.Target.FilePath

	// Skip command-line strings that were incorrectly captured as file paths.
	// Shell operators (&&, ||, eval) never appear in legitimate file paths.
	if strings.Contains(filePath, " && ") || strings.Contains(filePath, " || ") ||
		strings.Contains(filePath, "eval '") || strings.Contains(filePath, "shopt ") ||
		len(filePath) > 4096 {
		return nil
	}

	// Skip runtime noise — kernel/proc/dev/sys paths fire constantly.
	for _, prefix := range fileAlwaysNoise {
		if strings.HasPrefix(filePath, prefix) {
			return nil
		}
	}

	// Skip VCS directory probes (editors checking for .git, .svn, etc.)
	fileName := filepath.Base(filePath)
	if fileVCSProbes[fileName] {
		return nil
	}

	// Skip temp/build/cache paths
	for _, noise := range fileTempBuildNoise {
		if strings.Contains(filePath, noise) {
			return nil
		}
	}

	// Skip noisy file extensions (shared libs, bytecode, object files).
	ext := strings.ToLower(filepath.Ext(filePath))
	if fileExtNoise[ext] {
		return nil
	}

	// Skip PATHEXT probes — files that don't exist (Windows PATH resolution attempts).
	// When a command like "reg" is run, Windows checks every PATH directory for
	// reg.exe, reg.bat, reg.cmd, etc. These generate file_open events for files
	// that don't exist. The agent sets file_exists=false for these.
	if evt.Context != nil {
		if fe, ok := evt.Context["file_exists"]; ok {
			if fe == false || fe == "false" {
				return nil
			}
		}
	}

	// Skip files already covered by higher-severity detection rules to avoid
	// duplicate findings. credential_access handles sensitive credentials,
	// code_tampering handles CI/CD and dependency files, persistence handles
	// cron/systemd/ssh paths.
	if isSensitiveFile(filePath) {
		return nil
	}
	if isCodeTamperTarget(filePath) {
		return nil
	}
	if isPersistencePath(filePath) {
		return nil
	}

	// Skip zero-byte files — usually placeholders or locks, not real access.
	// Note: FileSize == -1 means stat failed (locked file, race condition) — still
	// process these as they may be legitimate file accesses. Directory filtering is
	// handled agent-side via IsDir() check before dispatch.
	if evt.Target.FileSize == 0 {
		return nil
	}

	dirPath := filepath.ToSlash(filepath.Dir(filePath))

	title := fmt.Sprintf("AI agent accessed: %s", fileName)
	summary := fmt.Sprintf("%s accessed %s", aiType, filePath)

	fctx := map[string]any{
		"ai_type":     aiType,
		"file_path":   filePath,
		"file_name":   fileName,
		"dir_path":    dirPath,
		"pid":         evt.Process.PID,
		"ppid":        evt.Process.PPID,
		"comm":        evt.Process.Comm,
		"signal_type": "file_activity",
		"pattern":     filePath,
	}
	if evt.Target.FileSize > 0 {
		fctx["file_size"] = evt.Target.FileSize
	}
	if evt.Process.SessionID != "" {
		fctx["session_id"] = evt.Process.SessionID
	}

	return []detection.Finding{
		{
			Title:      title,
			Summary:    summary,
			Severity:   "low",
			Confidence: 0.25,
			Context:    fctx,
		},
	}
}

// isCodeTamperTarget checks if a file would be caught by ai.code_tampering.
// Mirrors the logic in ai_code_tampering.go without importing it.
func isCodeTamperTarget(path string) bool {
	basename := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(path))

	// CI/CD configs
	ciFiles := map[string]bool{
		"Dockerfile": true, "docker-compose.yml": true, "docker-compose.yaml": true,
		".dockerignore": true, "Jenkinsfile": true, "Makefile": true,
		".travis.yml": true, ".circleci/config.yml": true,
	}
	if ciFiles[basename] {
		return true
	}
	// GitHub Actions
	if strings.Contains(path, "/.github/workflows/") {
		return true
	}

	// Dependency manifests
	depFiles := map[string]bool{
		"package.json": true, "package-lock.json": true,
		"yarn.lock": true, "pnpm-lock.yaml": true,
		"go.mod": true, "go.sum": true,
		"requirements.txt": true, "Pipfile": true, "Pipfile.lock": true,
		"Gemfile": true, "Gemfile.lock": true,
		"Cargo.toml": true, "Cargo.lock": true,
		"composer.json": true, "composer.lock": true,
		"pom.xml": true, "build.gradle": true,
	}
	if depFiles[basename] {
		return true
	}

	// Credential-overlap guard: .pem/.key/.crt are credential_access territory
	credExts := map[string]bool{".pem": true, ".key": true, ".crt": true}
	return credExts[ext]
}

// isPersistencePath checks if a file would be caught by ai.persistence.
func isPersistencePath(path string) bool {
	persistDirs := []string{
		"/var/spool/cron/", "/etc/cron.d/", "/etc/cron.daily/",
		"/etc/cron.hourly/", "/etc/cron.weekly/", "/etc/cron.monthly/",
		"/etc/init.d/", "/etc/systemd/system/", "/.git/hooks/",
	}
	for _, dir := range persistDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}

	persistFiles := map[string]bool{
		"authorized_keys": true, "crontab": true, "rc.local": true,
		".bashrc": true, ".bash_profile": true, ".profile": true,
		".zshrc": true, ".zprofile": true,
	}
	basename := filepath.Base(path)
	return persistFiles[basename]
}

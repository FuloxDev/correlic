package ai_pack

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/correlic/correlic-backend/internal/detection"
)

// cicdConfigBasenames are CI/CD configuration files (critical severity).
var cicdConfigBasenames = map[string]bool{
	".gitlab-ci.yml":          true,
	"Jenkinsfile":             true,
	".travis.yml":             true,
	"bitbucket-pipelines.yml": true,
	"azure-pipelines.yml":     true,
	"cloudbuild.yaml":         true, // GCP Cloud Build
	"appveyor.yml":            true,
	".drone.yml":              true,
}

// cicdConfigDirs are CI/CD directory segments — files inside these are critical.
var cicdConfigDirs = []string{
	"/.github/workflows/",
	"/.circleci/",
}

// dockerfileBasenames are container config files (critical severity).
var dockerfileBasenames = map[string]bool{
	"Dockerfile":          true,
	"docker-compose.yml":  true,
	"docker-compose.yaml": true,
	"Containerfile":       true, // Podman
	"kustomization.yaml":  true, // Kubernetes Kustomize
}

// dependencyManifestBasenames are package manager manifest files (high severity).
var dependencyManifestBasenames = map[string]bool{
	// JavaScript / Node.js
	"package.json": true, "package-lock.json": true,
	"yarn.lock": true, "pnpm-lock.yaml": true,
	// Go
	"go.mod": true, "go.sum": true,
	// Python
	"requirements.txt": true, "Pipfile": true, "Pipfile.lock": true,
	"setup.py": true, "setup.cfg": true, "pyproject.toml": true,
	// Ruby
	"Gemfile": true, "Gemfile.lock": true,
	// Rust
	"Cargo.toml": true, "Cargo.lock": true,
	// Java / JVM
	"pom.xml": true, "build.gradle": true, "build.gradle.kts": true,
	// PHP
	"composer.json": true, "composer.lock": true,
	// Terraform / IaC
	".terraform.lock.hcl": true,
	// Helm
	"Chart.yaml": true,
	// Nix
	"flake.nix": true,
}

// authSourceKeywords are keywords that identify security-critical source code.
var authSourceKeywords = []string{
	"auth", "middleware", "security", "permission",
	"login", "session", "token", "oauth", "jwt", "crypto",
}

// sourceCodeExtensions are file extensions recognized as source code.
var sourceCodeExtensions = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true,
	".jsx": true, ".tsx": true, ".java": true, ".rb": true,
	".rs": true, ".php": true, ".cs": true, ".cpp": true,
	".c": true, ".h": true, ".hpp": true, ".scala": true,
	".kt": true, ".swift": true, ".yml": true, ".yaml": true,
}

// credentialExtensions are extensions handled by ai.credential_access — skip to avoid overlap.
var credentialExtensions = map[string]bool{
	".pem": true, ".key": true, ".crt": true, ".cert": true,
	".p12": true, ".pfx": true,
}

// AICodeTampering detects AI agent modification of security-critical source files,
// CI/CD configs, or dependency manifests.
type AICodeTampering struct{}

func (d *AICodeTampering) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.code_tampering",
		Pack:            "ai",
		Name:            "AI Code Tampering",
		Severity:        "high",
		Description:     "AI agent modified security-critical source files, CI/CD configs, or dependency manifests",
		Tags:            []string{"ai", "supply-chain", "code-tampering", "ci-cd"},
		MITRETechniques: []string{"T1195.002", "T1554", "T1059.006"},
	}
}

func (d *AICodeTampering) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"file_open"},
		WindowSecs: 0,
	}
}

func (d *AICodeTampering) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt.Process == nil || evt.Target == nil || evt.Target.FilePath == "" {
		return nil
	}

	isAI, aiType, err := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if err != nil || !isAI {
		return nil
	}

	filePath := evt.Target.FilePath
	basename := filepath.Base(filePath)
	ext := filepath.Ext(basename)
	isWrite := isWriteOpen(evt.Context)

	// Skip credential file extensions — handled by ai.credential_access
	if credentialExtensions[ext] {
		return nil
	}

	// Code tampering is about modification. Read-only opens are not tampering —
	// AI agents legitimately read CI/CD configs and manifests during normal work.
	// Only fire on writes to reduce false positives.
	if !isWrite {
		return nil
	}

	var severity string
	var confidence float64
	var category string

	switch {
	// Critical: CI/CD config basenames
	case cicdConfigBasenames[basename]:
		severity = "critical"
		confidence = 0.90
		category = "cicd"

	// Critical: CI/CD config directories
	case matchesAnyContains(filePath, cicdConfigDirs):
		severity = "critical"
		confidence = 0.90
		category = "cicd"

	// Critical: Dockerfile / docker-compose
	case dockerfileBasenames[basename]:
		severity = "critical"
		confidence = 0.90
		category = "dockerfile"

	// High: dependency manifests
	case dependencyManifestBasenames[basename]:
		severity = "high"
		confidence = 0.80
		category = "dependency"

	// Medium: auth-related source code
	case isAuthSourceFile(basename, ext):
		severity = "medium"
		confidence = 0.70
		category = "auth_source"

	default:
		return nil
	}

	title := fmt.Sprintf("AI agent modified %s file: %s", category, basename)
	summary := fmt.Sprintf("%s accessed %s (%s)", aiType, filePath, category)

	fctx := map[string]any{
		"ai_type":     aiType,
		"pid":         evt.Process.PID,
		"comm":        evt.Process.Comm,
		"file_path":   filePath,
		"category":    category,
		"signal_type": "code_tamper",
		"pattern":     filePath,
	}
	if evt.Process.SessionID != "" {
		fctx["session_id"] = evt.Process.SessionID
	}

	// Per-finding MITRE based on tamper category.
	switch category {
	case "cicd":
		fctx["mitre_techniques"] = []string{"T1195.002"} // Compromise Software Supply Chain
	case "dockerfile":
		fctx["mitre_techniques"] = []string{"T1610"} // Deploy Container
	case "dependency":
		fctx["mitre_techniques"] = []string{"T1195.002"} // Compromise Software Supply Chain
	case "auth_source":
		fctx["mitre_techniques"] = []string{"T1565.001"} // Stored Data Manipulation
	}

	return []detection.Finding{
		{
			Title:      title,
			Summary:    summary,
			Severity:   severity,
			Confidence: confidence,
			Context:    fctx,
		},
	}
}

// isAuthSourceFile returns true if the file is a source code file with an
// auth-related keyword in the basename.
func isAuthSourceFile(basename, ext string) bool {
	if !sourceCodeExtensions[ext] {
		return false
	}
	lower := strings.ToLower(basename)
	for _, kw := range authSourceKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

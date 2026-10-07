// Package normalize provides deterministic exec classification for process_exec signal quality.
//
// Classification is intentionally heuristic: e.g. gen→helper is project-specific; some runtimes
// (node vs nodejs, custom Python builds) may be misclassified. We do not drop events or change IDs.
// Do not add overrides or learning here until post Phase 16+.
package normalize

import (
	"path"
	"strings"
	"unicode"
)

// ExecClassification is the result of classifying a process_exec.
type ExecClassification struct {
	Class      string // primary | helper | shell | runtime | unknown
	Role       string // entrypoint | worker | fork | interpreter | ephemeral
	Group      string // stable grouping key (e.g. bash, python, docker)
	Normalized bool
}

const (
	ClassPrimary = "primary"
	ClassHelper  = "helper"
	ClassShell   = "shell"
	ClassRuntime = "runtime"
	ClassUnknown = "unknown"

	RoleEntrypoint  = "entrypoint"
	RoleWorker      = "worker"
	RoleFork        = "fork"
	RoleInterpreter = "interpreter"
	RoleEphemeral   = "ephemeral"
)

var (
	shellExes = map[string]bool{
		"bash": true, "sh": true, "zsh": true, "fish": true,
	}
	runtimeNames = []string{"python", "node", "ruby", "java", "go"}
	// helperExeBase: processes to classify as "helper" and drop during normalization.
	// These are high-volume, low-value for security monitoring.
	// SAFE TO DROP: internal implementation details of build tools, not user-visible commands.
	helperExeBase = map[string]bool{
		"gen": true, // project-specific: generated/control-character script noise

		// Go toolchain (spawned by "go run", "go build", etc.)
		"compile": true, // go tool compile
		"link":    true, // go tool link
		"asm":     true, // go tool asm
		"cgo":     true, // go tool cgo
		"cover":   true, // go tool cover
		"vet":     true, // go tool vet
		"buildid": true, // go tool buildid

		// Common compilers/linkers (internal workers)
		"cc":    true, // C compiler
		"cc1":   true, // GCC compiler proper
		"gcc":   true,
		"g++":   true,
		"clang": true,
		"ld":    true, // Linker
		"as":    true, // Assembler
		"ar":    true, // Archive tool

		// Build systems (orchestrators that spawn many workers)
		"make":  true,
		"cmake": true,
		"ninja": true,
		"meson": true,

		// Node.js/TypeScript build noise
		"tsc":          true, // TypeScript compiler
		"tsserver":     true, // TS language server
		"esbuild":      true, // Fast bundler
		"swc":          true, // Fast TS/JS compiler
		"node_modules": true, // Internal node paths

		// Linters/formatters (run constantly in IDEs, pure noise)
		"eslint":    true,
		"prettier":  true,
		"gofmt":     true,
		"goimports": true,

		// Path utilities (shell script helpers, no security value)
		"basename": true,
		"dirname":  true,
		"which":    true,
		"realpath": true,

		// Package managers (internal workers, not the main command)
		// Note: We DROP these because they spawn thousands of child processes
		// The parent npm/pip command itself gets through as "runtime"
	}
)

// ClassifyExec classifies a process_exec by exe path, argv, and ppid.
// Deterministic; no timing or PID history. Unknown/non-printable exePath yields Normalized=false.
func ClassifyExec(exePath string, argv []string, ppid int) ExecClassification {
	_ = ppid
	exePath = strings.TrimSpace(exePath)
	if exePath == "" || !isPrintable(exePath) {
		return ExecClassification{Class: ClassUnknown, Role: "", Group: "", Normalized: false}
	}
	base := strings.ToLower(path.Base(exePath))
	// Strip common suffixes for matching (e.g. python3.11 -> python3)
	if idx := strings.Index(base, "."); idx > 0 {
		base = base[:idx]
	}
	cls := ClassPrimary
	role := RoleEntrypoint
	group := base

	// Helper: gen or other known noise
	if helperExeBase[base] {
		cls = ClassHelper
		role = RoleFork
		group = base
		return ExecClassification{Class: cls, Role: role, Group: group, Normalized: true}
	}

	// Shell
	if shellExes[base] {
		cls = ClassShell
		role = RoleInterpreter
		group = "shell"
		if hasArg(argv, "-c") || exePath == "/bin/sh" {
			role = RoleEphemeral
		}
		return ExecClassification{Class: cls, Role: role, Group: group, Normalized: true}
	}

	// Runtime (e.g. python, python3, node, nodejs)
	for _, r := range runtimeNames {
		if base == r || strings.HasPrefix(base, r) {
			cls = ClassRuntime
			role = RoleInterpreter
			group = r
			if hasArg(argv, "-c") {
				role = RoleEphemeral
			}
			return ExecClassification{Class: cls, Role: role, Group: group, Normalized: true}
		}
	}

	// -c or /bin/sh without being in shell set
	if hasArg(argv, "-c") {
		role = RoleEphemeral
	}

	return ExecClassification{Class: cls, Role: role, Group: group, Normalized: true}
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 && r != '\t' || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

func hasArg(argv []string, want string) bool {
	for _, a := range argv {
		if strings.TrimSpace(a) == want {
			return true
		}
	}
	return false
}

// correlic-hook is the Claude Code / Cursor hook binary. With no arguments it
// processes one hook event from stdin (the only thing it ever prints on
// stdout is a deny decision); `setup` registers it with the AI tools, `test`
// sends a synthetic event, `version` prints the build version.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/hook"
)

var version = "dev"

const usageText = `correlic-hook — Correlic hook for Claude Code and Cursor

Usage:
  correlic-hook                 process one hook event from stdin (used by the AI tool)
  correlic-hook setup [flags]   register the hook with Claude Code and/or Cursor
  correlic-hook test            send one synthetic event and print the backend response
  correlic-hook version         print the version

Setup flags:
  --claude            only Claude Code (~/.claude/settings.json)
  --cursor            only Cursor (~/.cursor/hooks.json)
  --project <dir>     write <dir>/.claude/settings.json and <dir>/.cursor/hooks.json instead
  --global            write the user-global files (default)
  --binary <path>     path to register (default: this executable)

Configuration: ~/.correlic/hook.yaml (or $CORRELIC_HOOK_CONFIG), overridden by
CORRELIC_TELEMETRY_URL, CORRELIC_API_KEY, CORRELIC_TLS_CA_FILE,
CORRELIC_TLS_CLIENT_CERT_FILE and CORRELIC_TLS_CLIENT_KEY_FILE.
Diagnostics: ~/.correlic/hook.log (CORRELIC_HOOK_DEBUG=1 also prints to stderr).
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return hookMain(stdin, stdout)
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "correlic-hook %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return 0
	case "setup":
		return setupMain(args[1:], stdout, stderr)
	case "test":
		return testMain(stdout, stderr)
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usageText)
		return 0
	default:
		fmt.Fprintf(stderr, "correlic-hook: unknown command %q\n\n%s", args[0], usageText)
		return 2
	}
}

// hookMain processes one event. It always exits 0: the hook fails open, and
// a non-zero exit would surface as a hook error inside the AI tool.
func hookMain(stdin io.Reader, stdout io.Writer) (code int) {
	debug := os.Getenv(hook.EnvDebug) == "1"
	dir, _ := hook.CorrelicDir()
	logger, closeLog := hook.OpenLogger(dir, debug)
	defer closeLog()
	defer func() {
		if r := recover(); r != nil {
			logger.Error("panic in hook; failing open", "panic", r)
			code = 0
		}
	}()

	cfg, err := hook.Load(os.Getenv)
	if err != nil {
		logger.Warn("hook not configured; event not recorded", "error", err)
		return 0
	}
	client, err := hook.NewClient(cfg)
	if err != nil {
		logger.Warn("transport setup failed; event not recorded", "error", err)
		return 0
	}
	hostID, err := hook.ResolveHostID(cfg.HostID, dir)
	if err != nil {
		logger.Warn("host id unavailable; event not recorded", "error", err)
		return 0
	}
	home, _ := os.UserHomeDir()
	rt := &hook.Runtime{
		Config: cfg,
		Client: client,
		HostID: hostID,
		Actor:  hook.CurrentActor(),
		Home:   home,
		Logger: logger,
	}
	res, err := rt.Process(context.Background(), stdin, stdout)
	if err != nil {
		logger.Warn("hook event not processed", "error", err)
		return 0
	}
	if res.Event != nil {
		logger.Debug("hook event processed",
			"id", res.Event.ID, "decision", res.Event.Context["decision"],
			"delivered", res.Delivered, "spooled", res.Spooled, "drained", res.Drained)
	}
	return 0
}

func setupMain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	claude := fs.Bool("claude", false, "register with Claude Code only")
	cursor := fs.Bool("cursor", false, "register with Cursor only")
	project := fs.String("project", "", "project directory (default: user-global files)")
	global := fs.Bool("global", false, "write the user-global files (default)")
	binary := fs.String("binary", "", "hook binary path to register (default: this executable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *global && *project != "" {
		fmt.Fprintln(stderr, "correlic-hook setup: --global and --project are exclusive")
		return 2
	}
	bin := *binary
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(stderr, "correlic-hook setup: cannot resolve own path: %v\n", err)
			return 1
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		bin = exe
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	home, _ := os.UserHomeDir()
	res, err := hook.Setup(hook.SetupOptions{
		Claude: *claude, Cursor: *cursor, Project: *project, Binary: bin, Home: home,
	})
	if err != nil {
		fmt.Fprintf(stderr, "correlic-hook setup: %v\n", err)
		return 1
	}
	if res.ClaudeSettings != "" {
		fmt.Fprintf(stdout, "Claude Code: hooks registered in %s\n", res.ClaudeSettings)
	}
	if res.CursorHooks != "" {
		fmt.Fprintf(stdout, "Cursor:      hooks registered in %s\n", res.CursorHooks)
	}
	fmt.Fprintf(stdout, "Hook binary: %s\n", bin)
	if _, err := hook.Load(os.Getenv); err != nil {
		cfgPath, _ := hook.DefaultConfigPath()
		fmt.Fprintf(stdout, "\nNot configured yet (%v).\nWrite %s with telemetry_url and api_key (an agent-type key), then run `correlic-hook test`.\n", err, cfgPath)
	} else {
		fmt.Fprintln(stdout, "Run `correlic-hook test` to verify delivery. Restart Claude Code / Cursor to pick up the hooks.")
	}
	return 0
}

func testMain(stdout, stderr io.Writer) int {
	cfg, err := hook.Load(os.Getenv)
	if err != nil {
		fmt.Fprintf(stderr, "correlic-hook test: %v\n", err)
		return 1
	}
	r := cfg.Redacted()
	fmt.Fprintf(stdout, "config:        %s\n", orDefault(cfg.Path, "(environment only)"))
	fmt.Fprintf(stdout, "telemetry_url: %s\n", r.TelemetryURL)
	fmt.Fprintf(stdout, "block_enabled: %v\n", r.BlockEnabled)
	fmt.Fprintf(stdout, "cache_dir:     %s\n", r.CacheDir)
	if r.TLSClientCertFile != "" {
		fmt.Fprintf(stdout, "mtls:          %s\n", r.TLSClientCertFile)
	}

	client, err := hook.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "correlic-hook test: transport: %v\n", err)
		return 1
	}
	dir, _ := hook.CorrelicDir()
	hostID, err := hook.ResolveHostID(cfg.HostID, dir)
	if err != nil {
		fmt.Fprintf(stderr, "correlic-hook test: host id: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "host_id:       %s\n", hostID)

	ev := &hook.ToolEvent{
		Tool: hook.ToolClaudeCode, HookEvent: "PreToolUse", Phase: hook.PhasePre, Blockable: true,
		SessionID: "correlic-hook-test", ToolName: "Bash", ToolUseID: fmt.Sprintf("test-%d", time.Now().UnixNano()),
		Command: "echo correlic-hook test", Cwd: mustGetwd(), Workspace: mustGetwd(),
	}
	evt := hook.BuildEvent(ev, hostID, hook.CurrentActor(), time.Now(), hook.Decision{})
	evt.Context["synthetic"] = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ingest, err := client.SendCanonicalEventsWithResult(ctx, evt)
	if err != nil {
		fmt.Fprintf(stderr, "ingest/events:  FAILED: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "ingest/events: accepted=%d rejected=%d sampled=%d (event %s)\n", ingest.Accepted, ingest.Rejected, ingest.Sampled, evt.ID)

	rules, err := client.GetBlockRules(ctx, "")
	if err != nil {
		fmt.Fprintf(stderr, "block-rules:    FAILED: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "block-rules:   %d enabled rule(s), version %s\n", len(rules.Rules), shorten(rules.Version))
	return 0
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func mustGetwd() string {
	wd, _ := os.Getwd()
	return wd
}

func shorten(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}

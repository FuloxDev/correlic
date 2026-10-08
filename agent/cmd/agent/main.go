// cmd/agent is the Correlic host agent.
//
// It starts platform-specific collectors (eBPF on Linux, kqueue/FSEvents/lsof
// on macOS, ETW on Windows), sends heartbeats and ships telemetry and
// canonical events to the backend.
//
//	correlic-agent [--config /etc/correlic/agent.yaml]
//	correlic-agent check-compat
//	correlic-agent service install|uninstall|start|stop   (Windows)
//
// Configuration is read from --config, else $CORRELIC_CONFIG, else agent.yaml
// next to the executable, else ~/.correlic/agent.yaml. An explicit path must
// exist and parse.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/correlic/correlic-agent/internal/compat"
	"github.com/correlic/correlic-agent/internal/config"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/heartbeat"
	"github.com/correlic/correlic-agent/internal/hostid"
	"github.com/correlic/correlic-agent/internal/identity"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/logging"
	"github.com/correlic/correlic-agent/internal/patterns"
	"github.com/correlic/correlic-agent/internal/telemetry"
	"github.com/correlic/correlic-agent/internal/transport"
)

// shutdownTimeout caps how long main waits for collectors, the batcher, the
// ingest sink and the heartbeat to drain after SIGTERM.
const shutdownTimeout = 10 * time.Second

func main() {
	logger := logging.Init("info", nil)

	configPath, args, err := extractConfigFlag(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\nusage: %s [--config path] [check-compat|service install|uninstall|start|stop]\n", err, filepath.Base(os.Args[0]))
		os.Exit(2)
	}

	// Handle "check-compat" subcommand — prints compatibility report and exits.
	if len(args) > 0 && args[0] == "check-compat" {
		result := compat.RunChecks()
		fmt.Print(result.FormatReport())
		if !result.Compatible {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Handle "service install|uninstall|start|stop" subcommands (Windows only).
	// Must run BEFORE compat checks — service management doesn't need ETW/admin.
	if handleServiceCommand(logger, args) {
		return
	}

	// If running as a Windows service, delegate to the service handler.
	// Must run BEFORE compat checks — the service is already elevated.
	runAsService(logger, configPath)

	// Run platform compatibility checks before anything else.
	compatResult := compat.RunChecks()
	compatResult.LogReport(logger)
	if !compatResult.Compatible {
		failed := compatResult.RequiredFailed()
		logger.Error("compatibility check failed — agent cannot start",
			"failed_checks", len(failed),
			"version", compatResult.KernelVersion,
		)
		fmt.Fprintf(os.Stderr, "\n%s", compatResult.FormatReport())
		os.Exit(1)
	}
	for _, w := range compatResult.Warnings() {
		logger.Warn("optional feature unavailable", "check", w.Name, "detail", w.Description)
	}

	// Run the agent in interactive (console) mode.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rt, err := runAgent(ctx, logger, configPath)
	if err != nil {
		logger.Error("agent failed to start", "error", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("shutting down, draining collectors and queues", "signal", sig.String(), "deadline", shutdownTimeout)
	cancel()

	if rt.wait(shutdownTimeout) {
		logger.Info("shutdown complete")
	} else {
		logger.Warn("shutdown deadline exceeded; exiting with components still running")
	}
}

// runAgent contains the core agent logic — called from both interactive and service mode.
// Returns the runtime whose wait() blocks until all components have stopped,
// or an error instead of calling os.Exit so the service handler can shut down gracefully.
func runAgent(ctx context.Context, logger *slog.Logger, configPath string) (*agentRuntime, error) {
	cfg, cfgPath, err := config.Resolve(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config failed: %w", err)
	}
	logging.SetLevel(cfg.LogLevel)
	if cfgPath != "" {
		logger.Info("config loaded", "path", cfgPath, "log_level", cfg.LogLevel)
	} else {
		logger.Warn("no config file found; using built-in defaults (pass --config or set CORRELIC_CONFIG)")
	}

	telemetryURL := cfg.TelemetryURL
	if telemetryURL == "" {
		telemetryURL = cfg.BackendURL
	}
	if telemetryURL == "" {
		return nil, fmt.Errorf("telemetry_url or backend_url required")
	}
	if cfg.APIKey == "" && cfg.TLSClientCertFile == "" {
		return nil, fmt.Errorf("api_key required in config (agent-type key written by the installer to agent.yaml)")
	}

	agentID := os.Getenv("CORRELIC_AGENT_ID")
	if agentID == "" {
		agentID, err = identity.LoadOrCreateFrom(cfgPath)
		if err != nil {
			return nil, fmt.Errorf("agent identity failed: %w", err)
		}
	}
	logger.Info("agent starting", "agent_id", agentID, "version", version,
		"backend_url", cfg.BackendURL, "telemetry_url", telemetryURL)

	t, err := transport.NewHTTPTransportWithTelemetryURLAndTLS(
		cfg.APIKey,
		cfg.BackendURL,
		telemetryURL,
		cfg.TLSCAFile,
		cfg.TLSClientCertFile,
		cfg.TLSClientKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("transport failed: %w", err)
	}

	// Optional remote key server (correlic_api_url). Off unless configured.
	if cfg.CorrelicAPIURL != "" {
		t.SetCorrelicAPIURL(cfg.CorrelicAPIURL)

		logger.Info("validating API key against key server", "url", cfg.CorrelicAPIURL)
		keyResult, err := t.ValidateKey(ctx)
		if err != nil {
			logger.Warn("key server unreachable — continuing without remote validation", "error", err)
		} else if !keyResult.Valid {
			return nil, fmt.Errorf("API key is invalid or expired: %s (code: %s)", keyResult.Error, keyResult.Code)
		} else {
			logger.Info("API key validated", "expiresAt", keyResult.ExpiresAt)
		}
	}

	// Canonical events, telemetry batches and heartbeats must all carry the
	// same identity: the backend keys agents, certificate bindings and events
	// by this one value.
	hostID := agentID
	if _, err := hostid.GetOrCreate(); err != nil {
		logger.Warn("could not initialise the agent state directory", "error", err)
	}

	rt := newAgentRuntime(logger)

	// AI patterns: cached list first (so detection works while the backend is
	// unreachable), then a ctx-aware fetch with retries and a 5 minute refresh.
	pm := patterns.New(t, lineage.GetLineageTracker(), filepath.Join(hostid.StateDir(), patterns.CacheFileName), logger)
	pm.LoadCache()
	rt.spawn("ai_patterns", func() { pm.Run(ctx) })

	b := telemetry.NewBatcher(agentID, t)
	rt.spawn("telemetry_batcher", func() { b.Start(ctx) })

	// Heartbeats keep the agent visible to the backend (and bind the mTLS
	// certificate to the agent id on the first one).
	hb := &heartbeat.Runner{
		AgentID:   agentID,
		Profile:   cfg.Profile,
		Interval:  cfg.HeartbeatInterval,
		Version:   version,
		Transport: t,
		Emit:      b.Enqueue,
	}
	rt.spawn("heartbeat", func() { hb.Start(ctx) })

	var disp dispatch.Dispatcher

	if cfg.ProcessExecEnabled {
		s := dispatch.NewHTTPSink(t, 100)
		rt.spawn("ingest_sink", func() { s.Start(ctx) })
		logger.Info("live ingestion enabled", "target", telemetryURL+"/ingest/events")
		// Buffer size, rate limits and dedupe come from AGENT_* env vars (see .env.example).
		d := dispatch.NewBufferedDispatcherFromEnv(s)
		d.Start(ctx)
		disp = d
	}

	emit := func(eventType string, payload any) bool {
		ok := b.Enqueue(eventType, payload)

		// Convert the /proc scanner's synthetic process_exec events to canonical
		// events for graph dispatch. The eBPF, kqueue and ETW runners already
		// dispatch their own canonical events, so only scanner payloads qualify.
		// The payload map becomes the event context, so the scanner's
		// ai_session_id / is_ai / ai_type travel with it.
		if disp != nil && eventType == "process_exec" {
			if m, ok := payload.(map[string]any); ok && m["source"] == "proc_scanner" {
				pid := anyToInt(m["pid"])
				ppid := anyToInt(m["ppid"])
				comm, _ := m["comm"].(string)
				exe, _ := m["exe"].(string)

				ts := time.Now()
				ce := event.Event{
					SchemaVersion: 1,
					Type:          "process_exec",
					Timestamp:     ts,
					HostID:        hostID,
					Source:        "proc_scanner",
					Actor: &event.Actor{
						PID:     pid,
						PPID:    ppid,
						ExePath: exe,
						Comm:    comm,
						Role:    safeString(m, "role"),
						Cmdline: safeStringSlice(m, "cmdline"),
					},
					Context: m,
				}
				ce.ID = event.GenerateID(hostID, ts.UnixNano(), "proc", "exec", pid, comm)
				disp.Enqueue(ce)
			}
		}
		return ok
	}

	// Soft-block enforcer (all platforms); rules come from the telemetry plane.
	enf := startEnforcer(ctx, cfg, telemetryURL, logger, rt)

	// Platform-specific startup: eBPF runners on Linux, kqueue/FSEvents/lsof on macOS, ETW on Windows.
	startPlatformCollectors(ctx, platformDeps{
		cfg:           cfg,
		logger:        logger,
		hostID:        hostID,
		emit:          emit,
		disp:          disp,
		enf:           enf,
		patternsReady: pm.Ready(),
		rt:            rt,
	})

	return rt, nil
}

// anyToInt accepts the integer types scanners use for PIDs.
func anyToInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case uint32:
		return int(n)
	case uint64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func safeString(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func safeStringSlice(m map[string]any, key string) []string {
	v, _ := m[key].([]string)
	return v
}

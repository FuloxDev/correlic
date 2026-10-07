// cmd/agent is a minimal agent that sends process_exec telemetry when process_exec_enabled is true.
//
// It starts platform-specific collectors (eBPF on Linux, kqueue/FSEvents/lsof on macOS)
// so that events appear on the AI Proof page.
//
//	go run ./cmd/agent
//
// Or build and run:
//
//	go build -o correlic-agent ./cmd/agent
//	./correlic-agent
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/correlic/correlic-agent/internal/compat"
	"github.com/correlic/correlic-agent/internal/config"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/hostid"
	"github.com/correlic/correlic-agent/internal/identity"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/telemetry"
	"github.com/correlic/correlic-agent/internal/transport"
)

func main() {
	logger := slog.Default()

	// Handle "check-compat" subcommand — prints compatibility report and exits.
	if len(os.Args) > 1 && os.Args[1] == "check-compat" {
		result := compat.RunChecks()
		fmt.Print(result.FormatReport())
		if !result.Compatible {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Handle "service install|uninstall|start|stop" subcommands (Windows only).
	// Must run BEFORE compat checks — service management doesn't need ETW/admin.
	if handleServiceCommand(logger) {
		return
	}

	// If running as a Windows service, delegate to the service handler.
	// Must run BEFORE compat checks — the service is already elevated.
	runAsService(logger)

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

	if err := runAgent(ctx, logger); err != nil {
		logger.Error("agent failed to start", "error", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("shutting down, draining goroutines (10s deadline)...")
	cancel()

	done := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Second)
		close(done)
	}()
	<-done
	logger.Info("shutdown complete")
}

// runAgent contains the core agent logic — called from both interactive and service mode.
// Returns error instead of calling os.Exit so the service handler can shut down gracefully.
func runAgent(ctx context.Context, logger *slog.Logger) error {
	cfg, err := config.LoadFromPathOrDefault("")
	if err != nil {
		return fmt.Errorf("load config failed: %w", err)
	}

	telemetryURL := cfg.TelemetryURL
	if telemetryURL == "" {
		telemetryURL = cfg.BackendURL
	}
	if telemetryURL == "" {
		return fmt.Errorf("telemetry_url or backend_url required")
	}
	if cfg.APIKey == "" {
		return fmt.Errorf("api_key required in config (or set in agent.yaml)")
	}

	agentID := os.Getenv("CORRELIC_AGENT_ID")
	if agentID == "" {
		agentID, err = identity.LoadOrCreate()
		if err != nil {
			return fmt.Errorf("agent identity failed: %w", err)
		}
	}
	logger.Info("agent starting", "agent_id", agentID, "telemetry_url", telemetryURL)

	t, err := transport.NewHTTPTransportWithTelemetryURLAndTLS(
		cfg.APIKey,
		cfg.BackendURL,
		telemetryURL,
		cfg.TLSCAFile,
		cfg.TLSClientCertFile,
		cfg.TLSClientKeyFile,
	)
	if err != nil {
		return fmt.Errorf("transport failed: %w", err)
	}

	// Optional remote key server (correlic_api_url). Off unless configured.
	if cfg.CorrelicAPIURL != "" {
		t.SetCorrelicAPIURL(cfg.CorrelicAPIURL)

		logger.Info("validating API key against key server", "url", cfg.CorrelicAPIURL)
		keyResult, err := t.ValidateKey(context.Background())
		if err != nil {
			logger.Warn("key server unreachable — continuing without remote validation", "error", err)
		} else if !keyResult.Valid {
			return fmt.Errorf("API key is invalid or expired: %s (code: %s)", keyResult.Error, keyResult.Code)
		} else {
			logger.Info("API key validated", "expiresAt", keyResult.ExpiresAt)
		}
	}

	// Fetch AI patterns from backend for lineage tracking.
	// Retry with backoff — the backend may still be starting.
	{
		delays := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second}
		var patterns []string
		var fetchErr error
		for attempt, delay := range delays {
			patterns, fetchErr = t.GetAIPatterns(context.Background())
			if fetchErr == nil {
				break
			}
			logger.Warn("failed to fetch AI patterns, retrying...",
				"attempt", attempt+1,
				"maxAttempts", len(delays),
				"retryIn", delay,
				"error", fetchErr,
			)
			time.Sleep(delay)
		}
		if fetchErr != nil {
			logger.Warn("failed to fetch AI patterns after retries - AI detection will be disabled until restart", "error", fetchErr)
		} else {
			lineage.GetLineageTracker().UpdatePatterns(patterns)
			logger.Info("loaded AI patterns from backend", "count", len(patterns))
		}
	}

	hostID, err := hostid.GetOrCreate()
	if err != nil {
		logger.Error("failed to get host id", "error", err)
		hostID = "unknown"
	}

	b := telemetry.NewBatcher(agentID, t)
	go b.Start(ctx)

	var disp dispatch.Dispatcher

	if cfg.ProcessExecEnabled {
		var sink dispatch.DispatcherSink
		if cfg.TelemetryURL != "" {
			s := dispatch.NewHTTPSink(t, 100)
			go s.Start(ctx)
			sink = s
			logger.Info("live ingestion enabled", "target", cfg.TelemetryURL+"/ingest/events")
		} else {
			sink = dispatch.NopSink{}
			logger.Info("live ingestion disabled (telemetry_url not set); canonical events logged only")
		}
		d := dispatch.NewBufferedDispatcher(sink, 50000)
		d.Start(ctx)
		disp = d
	}

	emit := func(eventType string, payload any) bool {
		ok := b.Enqueue(eventType, payload)

		// Convert scanner process_exec events to canonical events for graph dispatch.
		if disp != nil && eventType == "process_exec" {
			if m, ok := payload.(map[string]any); ok {
				pid, _ := m["pid"].(int)
				ppid, _ := m["ppid"].(int)
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

	// Platform-specific startup: eBPF runners on Linux, kqueue/FSEvents/lsof on macOS.
	startPlatformCollectors(ctx, cfg, logger, hostID, emit, disp)

	return nil
}

func safeString(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func safeStringSlice(m map[string]any, key string) []string {
	v, _ := m[key].([]string)
	return v
}

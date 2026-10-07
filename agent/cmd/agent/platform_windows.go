//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/config"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/enforcer"
	windows "github.com/correlic/correlic-agent/internal/windows"
)

// startPlatformCollectors wires Windows ETW-based runners and starts them.
func startPlatformCollectors(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	hostID string,
	emit collect.EventSink,
	disp dispatch.Dispatcher,
) {
	if !cfg.ETWEnabled {
		logger.Warn("ETW disabled in config — no Windows collectors started")
		return
	}

	// Create runners (no session arg — they create their own collectors).
	execRunner := windows.NewExecRunner(emit, logger, hostID, disp)
	fileRunner := windows.NewFileRunner(emit, logger, hostID, disp)
	netRunner := windows.NewNetworkRunner(emit, logger, hostID, disp)
	dnsRunner := windows.NewDNSRunner(emit, logger, hostID, disp)

	// Soft-block enforcer
	if cfg.BlockEnabled && !cfg.BlockEmergencyBypass {
		enf := enforcer.New(logger, true)
		// Protect the agent's own PID
		enf.AddProtectedPID(uint32(os.Getpid()))

		// Build TLS config with client certs for mTLS
		var syncTLS *tls.Config
		if cfg.TLSClientCertFile != "" && cfg.TLSClientKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.TLSClientCertFile, cfg.TLSClientKeyFile)
			if err != nil {
				logger.Error("failed to load client cert for block rule sync", "error", err)
			} else {
				syncTLS = &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				}
				if cfg.TLSCAFile != "" {
					pem, err := os.ReadFile(cfg.TLSCAFile)
					if err == nil {
						pool := x509.NewCertPool()
						pool.AppendCertsFromPEM(pem)
						syncTLS.RootCAs = pool
					}
				}
			}
		}

		// Start rule sync from backend
		ruleSync := enforcer.NewRuleSync(enf, cfg.TelemetryURL, cfg.APIKey, cfg.BlockSyncInterval, logger, syncTLS)
		go ruleSync.Start(ctx)

		execRunner.SetEnforcer(enf)
		netRunner.SetEnforcer(enf)
		fileRunner.SetEnforcer(enf)
		logger.Info("soft-block enforcer enabled", "sync_interval", cfg.BlockSyncInterval)
	} else if cfg.BlockEmergencyBypass {
		logger.Warn("soft-block EMERGENCY BYPASS active — all blocking disabled")
	}

	// Create a single ETW session that dispatches events to all collectors.
	session := windows.NewSession(logger, func(rec *windows.EventRecord) {
		execRunner.Collector().Handle(rec)
		if cfg.FileMonitorEnabled {
			fileRunner.Collector().Handle(rec)
		}
		if cfg.NetworkMonitorEnabled {
			netRunner.Collector().Handle(rec)
		}
		if cfg.DNSMonitorEnabled {
			dnsRunner.Collector().Handle(rec)
		}
	})

	// Enable Windows Security Audit policies (requires admin)
	if err := windows.EnableRequiredAuditPolicies(logger); err != nil {
		logger.Warn("some audit policies could not be enabled", "error", err)
	}

	// Create cmdline cache for merging Event 4688 data into ETW process events
	cmdlineCache := windows.NewCmdlineCache(10 * time.Second)
	execRunner.SetCmdlineCache(cmdlineCache)

	// Start Security Event Log subscriber (Event 4688 for cmdline, 4657 for registry, etc.)
	auditSub := windows.NewAuditSubscriber(logger, cmdlineCache, []uint16{
		4688, // Process Creation (cmdline)
		4689, // Process Termination
		4656, // Handle Request (read vs write)
		4657, // Registry Value Modified
		4672, // Special Privileges Assigned
		4698, // Scheduled Task Created
	})
	go auditSub.Start()

	// Audit runner for registry, privilege, and scheduled task events
	auditRunner := windows.NewAuditRunner(auditSub, logger, hostID, disp)
	go auditRunner.Start(ctx)

	// Scan running processes and register AI agents with lineage tracker.
	scanner := windows.NewProcScanner(logger, disp, hostID)
	_ = scanner.Scan(func(eventType string, payload any) bool {
		if emit != nil {
			return emit(eventType, payload)
		}
		return true
	})

	// Start all runners.
	go execRunner.Start(ctx)
	if cfg.FileMonitorEnabled {
		go fileRunner.Start(ctx)
		logger.Info("ETW file monitor started")
	}
	if cfg.NetworkMonitorEnabled {
		go netRunner.Start(ctx)
		logger.Info("ETW network monitor started")
	}
	if cfg.DNSMonitorEnabled {
		go dnsRunner.Start(ctx)
		logger.Info("ETW DNS monitor started")
	}

	// Start ETW session (blocks until context cancelled).
	go session.Start(ctx)

	logger.Info("Windows ETW collectors started",
		"file_monitor", cfg.FileMonitorEnabled,
		"network_monitor", cfg.NetworkMonitorEnabled,
		"dns_monitor", cfg.DNSMonitorEnabled,
	)
}

//go:build windows

package main

import (
	"context"
	"time"

	windows "github.com/correlic/correlic-agent/internal/windows"
)

// startPlatformCollectors wires Windows ETW-based runners and starts them.
func startPlatformCollectors(ctx context.Context, d platformDeps) {
	cfg, logger := d.cfg, d.logger
	if !cfg.ETWEnabled {
		logger.Warn("ETW disabled in config — no Windows collectors started")
		return
	}

	// Create runners (no session arg — they create their own collectors).
	execRunner := windows.NewExecRunner(d.emit, logger, d.hostID, d.disp)
	fileRunner := windows.NewFileRunner(d.emit, logger, d.hostID, d.disp)
	netRunner := windows.NewNetworkRunner(d.emit, logger, d.hostID, d.disp)
	dnsRunner := windows.NewDNSRunner(d.emit, logger, d.hostID, d.disp)

	// Soft-block enforcer (built and synced by runAgent when block_enabled).
	if d.enf != nil {
		execRunner.SetEnforcer(d.enf)
		netRunner.SetEnforcer(d.enf)
		fileRunner.SetEnforcer(d.enf)
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

	// Enable Windows Security Audit policies (requires admin). The prior
	// state is recorded in the state dir and restored on "service uninstall".
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
	auditRunner := windows.NewAuditRunner(auditSub, logger, d.hostID, d.disp)
	d.rt.spawn("etw_audit", func() { auditRunner.Start(ctx) })

	// Scan running processes and register AI agents with lineage tracker once
	// the AI pattern list is known.
	procScanner := windows.NewProcScanner(logger, d.disp, d.hostID)
	d.rt.spawn("proc_scanner", func() {
		d.waitPatterns(ctx)
		if ctx.Err() != nil {
			return
		}
		_ = procScanner.Scan(func(eventType string, payload any) bool {
			if d.emit != nil {
				return d.emit(eventType, payload)
			}
			return true
		})
	})

	// Start all runners.
	d.rt.spawn("etw_exec", func() { execRunner.Start(ctx) })
	if cfg.FileMonitorEnabled {
		d.rt.spawn("etw_file", func() { fileRunner.Start(ctx) })
		logger.Info("ETW file monitor started")
	}
	if cfg.NetworkMonitorEnabled {
		d.rt.spawn("etw_network", func() { netRunner.Start(ctx) })
		logger.Info("ETW network monitor started")
	}
	if cfg.DNSMonitorEnabled {
		d.rt.spawn("etw_dns", func() { dnsRunner.Start(ctx) })
		logger.Info("ETW DNS monitor started")
	}

	// Start ETW session (blocks until context cancelled).
	d.rt.spawn("etw_session", func() { session.Start(ctx) })

	logger.Info("Windows ETW collectors started",
		"file_monitor", cfg.FileMonitorEnabled,
		"network_monitor", cfg.NetworkMonitorEnabled,
		"dns_monitor", cfg.DNSMonitorEnabled,
		"block_rules", d.enf != nil,
	)
}

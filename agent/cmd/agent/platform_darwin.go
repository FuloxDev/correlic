//go:build darwin

package main

import (
	"context"
	"time"

	"github.com/correlic/correlic-agent/internal/darwin"
	"github.com/correlic/correlic-agent/internal/darwin/esevents"
	"github.com/correlic/correlic-agent/internal/darwin/eslogger"
)

// startPlatformCollectors starts the macOS collectors, trying the sources
// with real PIDs first:
//
//  1. Native Endpoint Security (esf-tagged builds signed with the
//     com.apple.developer.endpoint-security.client entitlement, root, Full
//     Disk Access): process, file and DNS events; see platform_darwin_esf.go.
//  2. /usr/bin/eslogger (macOS 13+, root, Full Disk Access, eslogger_enabled):
//     Apple's entitled Endpoint Security CLI, giving the same exec/exit/open
//     events without an Apple Developer account.
//  3. The kqueue, FSEvents and lsof pollers.
//
// Outbound connections always come from lsof: Endpoint Security has no
// network events. The soft-block enforcer (d.enf) is not wired into the
// darwin runners yet.
func startPlatformCollectors(ctx context.Context, d platformDeps) {
	cfg, logger := d.cfg, d.logger

	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = 2 * time.Second
	}

	if startESF(ctx, d) {
		startProcScan(ctx, d)
		startLsofNetwork(ctx, d, pollInterval)
		return
	}

	if startEslogger(ctx, d) {
		startProcScan(ctx, d)
		startLsofNetwork(ctx, d, pollInterval)
		return
	}

	// Process exec/exit monitoring via kqueue EVFILT_PROC.
	execRunner, err := darwin.NewExecRunner(d.emit, logger.With("component", "kqueue_exec"), d.hostID, d.disp)
	if err != nil {
		logger.Error("darwin exec runner init failed", "error", err)
		return
	}
	d.rt.spawn("kqueue_exec", func() { execRunner.Start(ctx) })
	logger.Info("darwin exec runner started (kqueue)")

	// Scan already-running processes and register them with kqueue once the
	// AI pattern list is known.
	scannerLogger := logger.With("component", "proc_scanner")
	procScanner := darwin.NewProcScanner(scannerLogger)
	d.rt.spawn("proc_scanner", func() {
		d.waitPatterns(ctx)
		if ctx.Err() != nil {
			return
		}
		if err := procScanner.RegisterAndWatch(d.emit, execRunner.Collector()); err != nil {
			scannerLogger.Error("initial proc scan failed", "error", err)
		}
	})

	// File monitoring via FSEvents polling.
	if cfg.FileMonitorEnabled {
		watchPaths := cfg.FSEventsWatchPaths
		if len(watchPaths) == 0 {
			// Default credential-rich directories.
			watchPaths = []string{
				"/Users",
				"/private/etc",
			}
		}
		fileRunner := darwin.NewFileRunner(d.emit, logger.With("component", "fsevents_file"), d.hostID, d.disp, watchPaths, pollInterval)
		d.rt.spawn("fsevents_file", func() { fileRunner.Start(ctx) })
		logger.Info("darwin file runner started (FSEvents)", "watch_paths", watchPaths)
	}

	startLsofNetwork(ctx, d, pollInterval)
}

// startProcScan registers already-running AI trees with the lineage tracker
// through a one-shot process scan. Used with the Endpoint Security sources,
// which report everything that happens after they start.
func startProcScan(ctx context.Context, d platformDeps) {
	scannerLogger := d.logger.With("component", "proc_scanner")
	procScanner := darwin.NewProcScanner(scannerLogger)
	d.rt.spawn("proc_scanner", func() {
		d.waitPatterns(ctx)
		if ctx.Err() != nil {
			return
		}
		if err := procScanner.Scan(d.emit); err != nil {
			scannerLogger.Error("initial proc scan failed", "error", err)
		}
	})
}

// startEslogger runs /usr/bin/eslogger for exec, exit, fork and (with file
// monitoring) open events and starts the shared Endpoint Security runners on
// its output. It returns false, after one WARN with the remediation, when
// eslogger is disabled, unavailable (not root, not macOS 13+) or exits at
// startup (typically Full Disk Access missing); the caller then falls back
// to the kqueue/FSEvents/lsof pollers.
func startEslogger(ctx context.Context, d platformDeps) bool {
	if !d.cfg.EsloggerEnabled {
		d.logger.Info("eslogger disabled (eslogger_enabled: false); using kqueue/FSEvents/lsof collectors")
		return false
	}
	logger := d.logger.With("component", "eslogger")

	if err := eslogger.Available(logger); err != nil {
		logger.Warn("eslogger unavailable; using kqueue/FSEvents/lsof collectors",
			"error", err, "remediation", eslogger.Remediation)
		return false
	}

	names := []string{"exec", "exit", "fork"}
	if d.cfg.FileMonitorEnabled {
		names = append(names, "open")
	}
	col := eslogger.New(logger, names)
	if err := col.Start(ctx); err != nil {
		logger.Warn("eslogger failed to start; using kqueue/FSEvents/lsof collectors",
			"error", err, "remediation", eslogger.Remediation)
		return false
	}
	d.rt.spawn("eslogger", col.Wait)

	// One stdout stream; the fanout splits it per runner.
	fan := esevents.NewFanout(col, logger)
	d.rt.spawn("eslogger_fanout", func() { fan.Start(ctx) })

	execRunner := esevents.NewExecRunner(fan.Process(), "eslogger", d.emit, logger.With("runner", "exec"), d.hostID, d.disp)
	d.rt.spawn("eslogger_exec", func() { execRunner.Start(ctx) })

	if d.cfg.FileMonitorEnabled {
		fileRunner := esevents.NewFileRunner(fan.Open(), "eslogger", d.emit, logger.With("runner", "file"), d.hostID, d.disp)
		d.rt.spawn("eslogger_file", func() { fileRunner.Start(ctx) })
	}
	if d.cfg.DNSMonitorEnabled {
		logger.Info("dns_monitor_enabled has no effect with eslogger: Endpoint Security has no DNS events")
	}

	logger.Info("Endpoint Security events via eslogger started",
		"events", names, "file_monitor", d.cfg.FileMonitorEnabled, "network", "lsof")
	return true
}

// startLsofNetwork starts the lsof-based connection poller when network
// monitoring is enabled. It is used by every configuration: Endpoint
// Security has no network events.
func startLsofNetwork(ctx context.Context, d platformDeps, pollInterval time.Duration) {
	if !d.cfg.NetworkMonitorEnabled {
		return
	}
	netRunner := darwin.NewNetworkRunner(d.emit, d.logger.With("component", "lsof_network"), d.hostID, d.disp, pollInterval)
	d.rt.spawn("lsof_network", func() { netRunner.Start(ctx) })
	d.logger.Info("darwin network runner started (lsof)")
}

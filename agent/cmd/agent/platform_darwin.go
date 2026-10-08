//go:build darwin

package main

import (
	"context"
	"time"

	"github.com/correlic/correlic-agent/internal/darwin"
)

// startPlatformCollectors starts the macOS collectors.
//
// When the binary was built with the esf tag, is signed with the
// com.apple.developer.endpoint-security.client entitlement and may open an
// Endpoint Security client (root, Full Disk Access), process, file and DNS
// events come from Endpoint Security with real PIDs; see
// platform_darwin_esf.go. Otherwise the kqueue, FSEvents and lsof collectors
// run. Outbound connections always come from lsof: Endpoint Security has no
// network events. The soft-block enforcer (d.enf) is not wired into the
// darwin runners yet.
func startPlatformCollectors(ctx context.Context, d platformDeps) {
	cfg, logger := d.cfg, d.logger

	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = 2 * time.Second
	}

	if startESF(ctx, d) {
		// Already-running AI trees are registered with the lineage tracker
		// by a one-shot process scan; Endpoint Security reports everything
		// that happens after it.
		scannerLogger := logger.With("component", "proc_scanner")
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

// startLsofNetwork starts the lsof-based connection poller when network
// monitoring is enabled. It is used by both the kqueue and the Endpoint
// Security configurations.
func startLsofNetwork(ctx context.Context, d platformDeps, pollInterval time.Duration) {
	if !d.cfg.NetworkMonitorEnabled {
		return
	}
	netRunner := darwin.NewNetworkRunner(d.emit, d.logger.With("component", "lsof_network"), d.hostID, d.disp, pollInterval)
	d.rt.spawn("lsof_network", func() { netRunner.Start(ctx) })
	d.logger.Info("darwin network runner started (lsof)")
}

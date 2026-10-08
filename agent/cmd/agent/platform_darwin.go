//go:build darwin

package main

import (
	"context"
	"time"

	"github.com/correlic/correlic-agent/internal/darwin"
)

// startPlatformCollectors starts kqueue/FSEvents/lsof-based collectors on macOS.
// The soft-block enforcer (d.enf) is not wired into the darwin runners yet.
func startPlatformCollectors(ctx context.Context, d platformDeps) {
	cfg, logger := d.cfg, d.logger

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

	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = 2 * time.Second
	}

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

	// Network monitoring via lsof polling.
	if cfg.NetworkMonitorEnabled {
		netRunner := darwin.NewNetworkRunner(d.emit, logger.With("component", "lsof_network"), d.hostID, d.disp, pollInterval)
		d.rt.spawn("lsof_network", func() { netRunner.Start(ctx) })
		logger.Info("darwin network runner started (lsof)")
	}
}

//go:build darwin

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/config"
	"github.com/correlic/correlic-agent/internal/darwin"
	"github.com/correlic/correlic-agent/internal/dispatch"
)

// startPlatformCollectors starts kqueue/FSEvents/lsof-based collectors on macOS.
func startPlatformCollectors(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	hostID string,
	emit collect.EventSink,
	disp dispatch.Dispatcher,
) {
	// Process exec/exit monitoring via kqueue EVFILT_PROC.
	execRunner, err := darwin.NewExecRunner(emit, logger.With("component", "kqueue_exec"), hostID, disp)
	if err != nil {
		logger.Error("darwin exec runner init failed", "error", err)
		return
	}
	go execRunner.Start(ctx)
	logger.Info("darwin exec runner started (kqueue)")

	// Scan already-running processes and register them with kqueue.
	scannerLogger := logger.With("component", "proc_scanner")
	procScanner := darwin.NewProcScanner(scannerLogger)
	go func() {
		if err := procScanner.RegisterAndWatch(emit, execRunner.Collector()); err != nil {
			scannerLogger.Error("initial proc scan failed", "error", err)
		}
	}()

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
		fileRunner := darwin.NewFileRunner(emit, logger.With("component", "fsevents_file"), hostID, disp, watchPaths, pollInterval)
		go fileRunner.Start(ctx)
		logger.Info("darwin file runner started (FSEvents)", "watch_paths", watchPaths)
	}

	// Network monitoring via lsof polling.
	if cfg.NetworkMonitorEnabled {
		netRunner := darwin.NewNetworkRunner(emit, logger.With("component", "lsof_network"), hostID, disp, pollInterval)
		go netRunner.Start(ctx)
		logger.Info("darwin network runner started (lsof)")
	}
}

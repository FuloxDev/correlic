//go:build linux

package main

import (
	"context"
	"log/slog"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/config"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/ebpf"
	"github.com/correlic/correlic-agent/internal/scanner"
)

// startPlatformCollectors starts eBPF-based collectors on Linux.
func startPlatformCollectors(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	hostID string,
	emit collect.EventSink,
	disp dispatch.Dispatcher,
) {
	dockerResolver := ebpf.NewDockerResolver(logger)

	// Scan already-running AI processes.
	if cfg.ProcessExecEnabled {
		procScanner := scanner.NewProcScanner(logger.With("component", "proc_scanner"), dockerResolver)
		go func() {
			if err := procScanner.Scan(emit); err != nil {
				logger.Warn("initial /proc scan failed", "error", err)
			}
		}()
	}

	if !cfg.EBPFEnabled {
		logger.Info("eBPF disabled — using /proc polling only")
		return
	}

	runner, err := ebpf.NewRunner(emit, logger.With("component", "ebpf_exec"), hostID, disp, dockerResolver)
	if err != nil {
		logger.Error("eBPF exec runner init failed", "error", err)
		return
	}
	go runner.Start(ctx)

	if cfg.FileMonitorEnabled {
		if fileRunner, err := ebpf.NewFileRunner(emit, logger.With("component", "ebpf_file"), hostID, disp); err != nil {
			logger.Warn("eBPF file runner init failed", "error", err)
		} else {
			go fileRunner.Start(ctx)
		}
	}

	if cfg.NetworkMonitorEnabled {
		if netRunner, err := ebpf.NewNetworkRunner(emit, logger.With("component", "ebpf_network"), hostID, disp); err != nil {
			logger.Warn("eBPF network runner init failed", "error", err)
		} else {
			go netRunner.Start(ctx)
		}
	}

	if cfg.DNSMonitorEnabled {
		if dnsRunner, err := ebpf.NewDNSRunner(emit, logger.With("component", "ebpf_dns"), hostID, disp); err != nil {
			logger.Warn("eBPF DNS runner init failed", "error", err)
		} else {
			go dnsRunner.Start(ctx)
		}
	}
}

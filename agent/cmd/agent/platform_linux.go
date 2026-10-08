//go:build linux

package main

import (
	"context"

	"github.com/correlic/correlic-agent/internal/ebpf"
	"github.com/correlic/correlic-agent/internal/scanner"
)

// startPlatformCollectors starts eBPF-based collectors on Linux.
func startPlatformCollectors(ctx context.Context, d platformDeps) {
	cfg, logger := d.cfg, d.logger
	dockerResolver := ebpf.NewDockerResolver(logger)

	// Scan already-running AI processes once the pattern list is known.
	if cfg.ProcessExecEnabled {
		procScanner := scanner.NewProcScanner(logger.With("component", "proc_scanner"), dockerResolver)
		d.rt.spawn("proc_scanner", func() {
			d.waitPatterns(ctx)
			if ctx.Err() != nil {
				return
			}
			if err := procScanner.Scan(d.emit); err != nil {
				logger.Warn("initial /proc scan failed", "error", err)
			}
		})
	}

	if !cfg.EBPFEnabled {
		logger.Info("eBPF disabled — using /proc polling only")
		return
	}
	if d.disp == nil {
		logger.Warn("process_exec_enabled is false — eBPF runners need the dispatcher; no collectors started")
		return
	}

	runner, err := ebpf.NewRunner(d.emit, logger.With("component", "ebpf_exec"), d.hostID, d.disp, dockerResolver)
	if err != nil {
		logger.Error("eBPF exec runner init failed", "error", err)
		return
	}
	runner.SetEnforcer(d.enf)
	d.rt.spawn("ebpf_exec", func() { runner.Start(ctx) })

	// Process exit is what releases PIDs from the lineage tracker; without it
	// the tracker only grows and recycled PIDs keep their old AI label.
	if exitRunner, err := ebpf.NewExitRunner(logger.With("component", "ebpf_exit"), d.hostID, d.disp); err != nil {
		logger.Warn("eBPF exit runner init failed", "error", err)
	} else {
		d.rt.spawn("ebpf_exit", func() { exitRunner.Start(ctx) })
	}

	if cfg.ForkMonitorEnabled {
		if forkRunner, err := ebpf.NewForkRunner(d.emit, logger.With("component", "ebpf_fork"), d.hostID, d.disp); err != nil {
			logger.Warn("eBPF fork runner init failed", "error", err)
		} else {
			d.rt.spawn("ebpf_fork", func() { forkRunner.Start(ctx) })
		}
	}

	if cfg.BindMonitorEnabled {
		if bindRunner, err := ebpf.NewBindRunner(d.emit, logger.With("component", "ebpf_bind"), d.hostID, d.disp); err != nil {
			logger.Warn("eBPF bind runner init failed", "error", err)
		} else {
			d.rt.spawn("ebpf_bind", func() { bindRunner.Start(ctx) })
		}
	}

	if cfg.UnlinkMonitorEnabled {
		if unlinkRunner, err := ebpf.NewUnlinkRunner(d.emit, logger.With("component", "ebpf_unlink")); err != nil {
			logger.Warn("eBPF unlink runner init failed", "error", err)
		} else {
			d.rt.spawn("ebpf_unlink", func() { unlinkRunner.Start(ctx) })
		}
	}

	if cfg.SetuidMonitorEnabled {
		if setuidRunner, err := ebpf.NewSetuidRunner(d.emit, logger.With("component", "ebpf_setuid")); err != nil {
			logger.Warn("eBPF setuid runner init failed", "error", err)
		} else {
			d.rt.spawn("ebpf_setuid", func() { setuidRunner.Start(ctx) })
		}
	}

	if cfg.FileMonitorEnabled {
		if fileRunner, err := ebpf.NewFileRunner(d.emit, logger.With("component", "ebpf_file"), d.hostID, d.disp); err != nil {
			logger.Warn("eBPF file runner init failed", "error", err)
		} else {
			fileRunner.SetEnforcer(d.enf)
			d.rt.spawn("ebpf_file", func() { fileRunner.Start(ctx) })
		}
	}

	if cfg.NetworkMonitorEnabled {
		if netRunner, err := ebpf.NewNetworkRunner(d.emit, logger.With("component", "ebpf_network"), d.hostID, d.disp); err != nil {
			logger.Warn("eBPF network runner init failed", "error", err)
		} else {
			netRunner.SetEnforcer(d.enf)
			d.rt.spawn("ebpf_network", func() { netRunner.Start(ctx) })
		}
	}

	if cfg.DNSMonitorEnabled {
		if dnsRunner, err := ebpf.NewDNSRunner(d.emit, logger.With("component", "ebpf_dns"), d.hostID, d.disp); err != nil {
			logger.Warn("eBPF DNS runner init failed", "error", err)
		} else {
			d.rt.spawn("ebpf_dns", func() { dnsRunner.Start(ctx) })
		}
	}
}

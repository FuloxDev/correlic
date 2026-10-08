//go:build darwin && esf

package main

import (
	"context"

	"github.com/correlic/correlic-agent/internal/darwin/esf"
)

// startESF opens an Endpoint Security client and starts the ESF runners for
// process exec/exit, file opens and (on a macOS 12+ SDK) DNS lookups. It
// returns false, after logging why, when the client cannot be opened: the
// binary is not signed with com.apple.developer.endpoint-security.client,
// the agent is not root, or Full Disk Access was not granted. The caller then
// falls back to the kqueue/FSEvents collectors, so an esf-tagged binary is
// safe to run on any Mac.
func startESF(ctx context.Context, d platformDeps) bool {
	logger := d.logger.With("component", "esf")

	client, err := esf.NewClient()
	if err != nil {
		logger.Warn("Endpoint Security unavailable; using kqueue/FSEvents collectors", "error", err)
		return false
	}
	collector := esf.NewCollector(client, logger)
	if err := collector.Subscribe(); err != nil {
		logger.Warn("Endpoint Security subscribe failed; using kqueue/FSEvents collectors", "error", err)
		client.Close()
		return false
	}

	d.rt.spawn("esf_collector", func() { collector.Start(ctx) })
	// Release the ES client when the agent stops; macOS limits how many
	// clients may be open and the collector's channels close with it.
	d.rt.spawn("esf_client", func() {
		<-ctx.Done()
		client.Close()
	})

	execRunner := esf.NewExecRunner(collector, d.emit, logger.With("runner", "exec"), d.hostID, d.disp)
	d.rt.spawn("esf_exec", func() { execRunner.Start(ctx) })

	if d.cfg.FileMonitorEnabled {
		fileRunner := esf.NewFileRunner(collector, d.emit, logger.With("runner", "file"), d.hostID, d.disp)
		d.rt.spawn("esf_file", func() { fileRunner.Start(ctx) })
	}
	if d.cfg.DNSMonitorEnabled {
		if esf.LookupAvailable() {
			dnsRunner := esf.NewDNSRunner(collector, d.emit, logger.With("runner", "dns"), d.hostID, d.disp)
			d.rt.spawn("esf_dns", func() { dnsRunner.Start(ctx) })
		} else {
			logger.Warn("dns_monitor_enabled, but this build's SDK has no ES_EVENT_TYPE_NOTIFY_LOOKUP (macOS 12 SDK or newer required)")
		}
	}

	logger.Info("Endpoint Security collectors started",
		"file_monitor", d.cfg.FileMonitorEnabled, "dns_monitor", d.cfg.DNSMonitorEnabled)
	return true
}

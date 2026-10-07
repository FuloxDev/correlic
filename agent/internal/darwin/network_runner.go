//go:build darwin

package darwin

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/procinfo"
)

// NetworkRunner monitors network connections via lsof and dispatches canonical events.
type NetworkRunner struct {
	collector  *NetworkCollector
	emit       collect.EventSink
	logger     *slog.Logger
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// NewNetworkRunner creates a new lsof-based network runner.
func NewNetworkRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher, interval time.Duration) *NetworkRunner {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}

	collector := NewNetworkCollector(
		logger.With("component", "lsof_network"),
		interval,
	)

	return &NetworkRunner{
		collector:  collector,
		emit:       emit,
		logger:     logger,
		HostID:     hostID,
		Dispatcher: disp,
	}
}

// Start implements the collect.Collector interface.
func (r *NetworkRunner) Start(ctx context.Context) {
	go r.collector.Start(ctx)

	r.logger.Info("darwin network runner started (lsof)")

	tracker := lineage.GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("darwin network runner stopping")
			return
		case ev, ok := <-r.collector.Events():
			if !ok {
				return
			}

			// Skip port-0 events.
			if ev.DstPort == 0 {
				continue
			}

			// Lineage filter. Look up PPID so inheritance works for
			// child processes of AI roots (e.g. node spawned by cursor).
			if !tracker.IsAI(ev.PID) {
				ppid := procinfo.LookupPPID(ev.PID)
				if !tracker.RegisterProcess(ev.PID, ppid, ev.Comm) {
					continue
				}
			}

			category := categorizeConnection(ev.DstPort, ev.DstIP)

			// Flat telemetry.
			payload := map[string]any{
				"pid":      ev.PID,
				"dst_ip":   ev.DstIP,
				"dst_port": ev.DstPort,
				"family":   ev.Protocol,
				"comm":     ev.Comm,
				"source":   "lsof",
				"category": category,
				"is_ai":    true,
			}
			if r.emit != nil {
				r.emit("net_connect", payload)
			}

			// Canonical event.
			if r.Dispatcher != nil {
				ts := time.Now()
				sessionID := procinfo.DetectSessionID(ev.PID)
				canonEvt := event.Event{
					SchemaVersion: 1,
					Type:          "net_connect",
					Timestamp:     ts,
					HostID:        r.HostID,
					Source:        "lsof",
					Actor: &event.Actor{
						PID:       int(ev.PID),
						Comm:      ev.Comm,
						SessionID: strconv.FormatUint(uint64(sessionID), 10),
					},
					Target: &event.Target{
						IP:       ev.DstIP,
						Port:     int(ev.DstPort),
						Protocol: ev.Protocol,
					},
					Context: map[string]any{
						"category": category,
					},
				}
				canonEvt.ID = event.GenerateID(
					r.HostID,
					ts.UnixNano(),
					canonEvt.Source,
					canonEvt.Type,
					canonEvt.Actor.PID,
					ev.DstIP,
				)
				r.Dispatcher.Enqueue(canonEvt)
			}
		}
	}
}

// categorizeConnection returns a category based on port/destination.
// Shared logic with Linux network runner.
func categorizeConnection(port uint16, ip string) string {
	switch port {
	case 22:
		return "ssh"
	case 80, 8080:
		return "http"
	case 443, 8443:
		return "https"
	case 53:
		return "dns"
	case 25, 465, 587:
		return "smtp"
	case 21:
		return "ftp"
	case 23:
		return "telnet"
	case 3389:
		return "rdp"
	case 5900, 5901:
		return "vnc"
	case 6666, 6667:
		return "irc"
	case 4444:
		return "msf"
	}
	if port > 10000 && port != 0 {
		return "high_port"
	}
	return "other"
}

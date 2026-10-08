//go:build linux

package ebpf

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/enforcer"
	"github.com/correlic/correlic-agent/internal/event"
)

// NetworkRunner wraps the NetworkCollector to implement the collect.Collector interface.
type NetworkRunner struct {
	collector  *NetworkCollector
	emit       collect.EventSink
	logger     *slog.Logger
	HostID     string
	Dispatcher dispatch.Dispatcher
	enforcer   *enforcer.Enforcer
}

// NewNetworkRunner creates a new network monitoring runner.
func NewNetworkRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) (*NetworkRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}

	collector, err := NewNetworkCollector(logger)
	if err != nil {
		return nil, err
	}

	return &NetworkRunner{
		collector:  collector,
		emit:       emit,
		logger:     logger,
		HostID:     hostID,
		Dispatcher: disp,
	}, nil
}

// SetEnforcer attaches the soft-block enforcer to the network runner.
func (r *NetworkRunner) SetEnforcer(e *enforcer.Enforcer) {
	r.enforcer = e
}

// Start implements the collect.Collector interface.
func (r *NetworkRunner) Start(ctx context.Context) {
	// Start the underlying collector
	go r.collector.Start(ctx)

	r.logger.Info("eBPF network runner started, forwarding connection events")

	tracker := GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("eBPF network runner stopping")
			r.collector.Close()
			return
		case ev := <-r.collector.Events():
			// FILTER: Skip port-0 events — these are UDP routing queries (e.g. Chromium
			// calling connect() with just an IP to determine the outbound interface).
			// They are not real connections and produce useless findings with dst_port=0.
			if ev.DPort == 0 {
				continue
			}

			// FILTER: Only proceed if this is an AI process or descendant
			if !tracker.IsAI(ev.PID) {
				// Race condition check: try to register via inheritance or pattern
				if !tracker.RegisterProcess(ev.PID, ev.PPID, ev.Comm) {
					continue
				}
			}

			dstIP := ev.DstIP()
			category := categorizeConnection(ev.DPort, dstIP)

			// Soft-block check — kill process if the destination matches a block rule.
			target := net.JoinHostPort(dstIP, strconv.Itoa(int(ev.DPort)))
			blocked := applyBlockRule(r.enforcer, r.emit, r.logger, "net_connect", ev.PID, target,
				map[string]any{"target": target})

			// Convert ConnectEvent to telemetry format
			payload := map[string]any{
				"pid":      ev.PID,
				"ppid":     ev.PPID,
				"uid":      ev.UID,
				"gid":      ev.GID,
				"dst_ip":   dstIP,
				"dst_port": ev.DPort,
				"family":   familyToString(ev.Family),
				"comm":     ev.Comm,
				"pcomm":    ev.ParentComm,
				"source":   "ebpf",
				"category": category,
			}
			tracker.Annotate(payload, ev.PID)
			if blocked {
				payload["action"] = "blocked"
			}

			// Send to batcher for aggregation
			ok := r.emit("net_connect", payload)
			if !ok {
				r.logger.Debug("network event dropped by sink")
			}

			// Also dispatch to live ingestion so it appears in Neo4j
			if r.Dispatcher != nil {
				ts := time.Now()
				canonicalEvent := event.Event{
					SchemaVersion: 1,
					Type:          "net_connect",
					Timestamp:     ts,
					HostID:        r.HostID,
					Source:        "ebpf",
					Actor: &event.Actor{
						PID:       int(ev.PID),
						PPID:      int(ev.PPID),
						Comm:      ev.Comm,
						SessionID: strconv.FormatUint(uint64(detectSessionID(ev.PID)), 10),
					},
					Target: &event.Target{
						IP:       dstIP,
						Port:     int(ev.DPort),
						Protocol: familyToString(ev.Family),
					},
					Context: map[string]any{
						"category": category,
					},
				}
				tracker.Annotate(canonicalEvent.Context, ev.PID)
				if blocked {
					canonicalEvent.Context["action"] = "blocked"
				}
				canonicalEvent.ID = event.GenerateID(
					r.HostID,
					ts.UnixNano(),
					canonicalEvent.Source,
					canonicalEvent.Type,
					canonicalEvent.Actor.PID,
					dstIP,
				)
				r.Dispatcher.Enqueue(canonicalEvent)
			}
		}
	}
}

// familyToString converts address family to string.
func familyToString(family uint16) string {
	switch family {
	case 2:
		return "ipv4"
	case 10:
		return "ipv6"
	default:
		return "unknown"
	}
}

// categorizeConnection returns a category based on port/destination.
func categorizeConnection(port uint16, ip string) string {
	// Check for common suspicious ports
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
		return "irc" // Often used for C2
	case 4444:
		return "msf" // Metasploit default
	}

	// High ports are often suspicious
	if port > 10000 && port != 0 {
		return "high_port"
	}

	return "other"
}

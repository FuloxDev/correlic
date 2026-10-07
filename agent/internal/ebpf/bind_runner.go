//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
)

// BindRunner wraps the BindCollector to implement the collect.Collector interface.
// AI-focused: dispatches to Neo4j only for AI agent bind events (listening ports).
type BindRunner struct {
	collector  *BindCollector
	emit       collect.EventSink
	logger     *slog.Logger
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// NewBindRunner creates a new bind monitoring runner.
// AI-focused: only AI-related bind events are dispatched to Neo4j graph.
func NewBindRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) (*BindRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}

	collector, err := NewBindCollector(logger)
	if err != nil {
		return nil, err
	}

	return &BindRunner{
		collector:  collector,
		emit:       emit,
		logger:     logger,
		HostID:     hostID,
		Dispatcher: disp,
	}, nil
}

// Start implements the collect.Collector interface.
func (r *BindRunner) Start(ctx context.Context) {
	// Start the underlying collector
	go r.collector.Start(ctx)

	r.logger.Info("eBPF bind runner started, forwarding bind events")

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("eBPF bind runner stopping")
			r.collector.Close()
			return
		case bindEvt := <-r.collector.Events():
			// 1. Always emit telemetry (net_bind) for ALL processes system-wide
			category := categorizeBind(bindEvt)

			// Check if this is an AI process or descendant
			tracker := GetLineageTracker()
			isAI := tracker.IsAI(bindEvt.PID)

			payload := map[string]any{
				"pid":        bindEvt.PID,
				"ppid":       bindEvt.PPID,
				"uid":        bindEvt.UID,
				"bind_addr":  bindEvt.BindAddr(),
				"bind_port":  bindEvt.Port,
				"family":     familyToString(bindEvt.Family),
				"comm":       bindEvt.Comm,
				"pcomm":      bindEvt.ParentComm,
				"source":     "ebpf",
				"is_exposed": bindEvt.IsWildcard(),
				"risk":       category,
				"is_ai":      isAI,
			}

			ok := r.emit("net_bind", payload)
			if !ok {
				r.logger.Debug("bind event dropped by sink")
			}

			// 2. Dispatch to Neo4j (Graph) - ONLY for AI processes
			if r.Dispatcher != nil && isAI {
				ts := time.Now()
				canonicalEvent := event.Event{
					SchemaVersion: 1,
					Type:          "net_listen", // Canonical type for bind/listen
					Timestamp:     ts,
					HostID:        r.HostID,
					Source:        "ebpf",
					Actor: &event.Actor{
						PID:       int(bindEvt.PID),
						PPID:      int(bindEvt.PPID),
						Comm:      bindEvt.Comm,
						SessionID: strconv.FormatUint(uint64(detectSessionID(bindEvt.PID)), 10),
					},
					Target: &event.Target{
						IP:   bindEvt.BindAddr(),
						Port: int(bindEvt.Port),
						// Protocol derived from family? Defaulting for now
					},
					Context: map[string]any{
						"risk":       category,
						"is_exposed": bindEvt.IsWildcard(),
					},
				}
				canonicalEvent.ID = event.GenerateID(
					r.HostID,
					ts.UnixNano(),
					canonicalEvent.Source,
					canonicalEvent.Type,
					canonicalEvent.Actor.PID,
					fmt.Sprintf("%s:%d", bindEvt.BindAddr(), bindEvt.Port),
				)
				r.Dispatcher.Enqueue(canonicalEvent)
			}
		}
	}
}

// Close releases eBPF resources.
func (r *BindRunner) Close() error {
	if r.collector != nil {
		return r.collector.Close()
	}
	return nil
}

// categorizeBind returns a risk category based on the bind event.
func categorizeBind(event BindEvent) string {
	addr := event.BindAddr()

	// Wildcard (0.0.0.0 or ::) = exposed to ALL interfaces
	if event.IsWildcard() {
		return categorizeByProcess(event.Comm, "critical", "high")
	}

	// Multicast binds (mDNS, SSDP, etc.) are normal background traffic; don't treat as exposed.
	if isMulticastIP(addr) {
		return "low"
	}

	// Localhost = generally safe
	if addr == "127.0.0.1" || addr == "::1" || addr == "localhost" {
		return "low"
	}

	// Private network = medium risk (network may be compromised)
	if isPrivateIP(addr) {
		return categorizeByProcess(event.Comm, "medium", "info")
	}

	// Public IP bind = high risk
	return "high"
}

func isMulticastIP(addr string) bool {
	// IPv6 multicast: ff00::/8
	if len(addr) >= 2 && (addr[0:2] == "ff" || addr[0:2] == "FF") {
		return true
	}
	// IPv4 multicast: 224.0.0.0/4
	// We avoid net.ParseIP here; simple prefix checks are enough for our UI use.
	prefixes := []string{
		"224.", "225.", "226.", "227.", "228.", "229.",
		"230.", "231.", "232.", "233.", "234.", "235.",
		"236.", "237.", "238.", "239.",
	}
	for _, p := range prefixes {
		if len(addr) >= len(p) && addr[0:len(p)] == p {
			return true
		}
	}
	return false
}

// categorizeByProcess assigns risk based on the command
func categorizeByProcess(comm, riskyLevel, normalLevel string) string {
	riskyCommands := map[string]bool{
		"code": true, "node": true, "python": true, "python3": true,
		"nc": true, "socat": true, "ncat": true,
		"ruby": true, "perl": true, "php": true,
		"npm": true, "yarn": true, "pnpm": true,
	}
	if riskyCommands[comm] {
		return riskyLevel
	}

	// Server processes are expected to bind
	serverCommands := map[string]bool{
		"nginx": true, "apache": true, "httpd": true,
		"sshd": true, "postgres": true, "mysql": true,
		"docker": true, "containerd": true,
	}
	if serverCommands[comm] {
		return "expected"
	}

	return normalLevel
}

// isPrivateIP checks if an IP is in private/local ranges
func isPrivateIP(addr string) bool {
	// RFC 1918 and other private ranges
	privateRanges := []string{
		"10.",     // 10.0.0.0/8
		"172.16.", // 172.16.0.0/12 (partial check)
		"172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.",
		"172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.", // 192.168.0.0/16
		"169.254.", // Link-local
		"fc",       // IPv6 unique local
		"fd",       // IPv6 unique local
		"fe80:",    // IPv6 link-local
	}

	for _, prefix := range privateRanges {
		if len(addr) >= len(prefix) && addr[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

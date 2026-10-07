//go:build windows

package windows

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/enforcer"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/procinfo"
)

// NetworkRunner consumes NetworkCollector events and emits canonical net_connect events.
type NetworkRunner struct {
	collector  *NetworkCollector
	emit       collect.EventSink
	logger     *slog.Logger
	hostID     string
	dispatcher dispatch.Dispatcher
	enforcer   *enforcer.Enforcer
}

// SetEnforcer attaches the soft-block enforcer to the network runner.
func (r *NetworkRunner) SetEnforcer(e *enforcer.Enforcer) {
	r.enforcer = e
}

// NewNetworkRunner creates an ETW-based network runner.
func NewNetworkRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) *NetworkRunner {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}
	return &NetworkRunner{
		collector:  NewNetworkCollector(),
		emit:       emit,
		logger:     logger,
		hostID:     hostID,
		dispatcher: disp,
	}
}

// Collector returns the underlying NetworkCollector.
func (r *NetworkRunner) Collector() *NetworkCollector {
	return r.collector
}

// Start processes network events until ctx is cancelled.
func (r *NetworkRunner) Start(ctx context.Context) {
	r.logger.Info("windows network runner started (ETW Kernel-Network)")
	tracker := lineage.GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("windows network runner stopping")
			return
		case ev, ok := <-r.collector.Events():
			if !ok {
				return
			}

			if ev.DstPort == 0 {
				continue
			}

			if !tracker.IsAI(ev.PID) {
				ppid := procinfo.LookupPPID(ev.PID)
				cmdline := procinfo.ReadProcCmdline(ev.PID)
				comm := ""
				if len(cmdline) > 0 {
					comm = cmdline[0]
				}
				if !tracker.RegisterProcess(ev.PID, ppid, comm) {
					continue
				}
			}

			category := categorizePort(ev.DstPort, ev.DstIP)

			if r.enforcer != nil && r.enforcer.IsEnabled() {
				target := fmt.Sprintf("%s:%d", ev.DstIP, ev.DstPort)
				if blocked, rule := r.enforcer.ShouldBlock("net_connect", target); blocked {
					start := time.Now()
					success, killErr := r.enforcer.Kill(ev.PID, rule.KillTree)
					latency := time.Since(start)
					r.logger.Warn("BLOCKED network connection",
						"pid", ev.PID, "target", target, "rule_id", rule.ID,
						"success", success, "latency", latency)
					if r.emit != nil {
						r.emit("block_event", map[string]any{
							"rule_id":     rule.ID,
							"signal_type": "net_connect",
							"pid":         int(ev.PID),
							"target":      target,
							"success":     success,
							"error_msg":   errStr(killErr),
							"latency_us":  latency.Microseconds(),
						})
					}
					// Don't return — still dispatch the event with blocked flag for visibility
				}
			}

			if r.emit != nil {
				r.emit("net_connect", map[string]any{
					"pid":      ev.PID,
					"dst_ip":   ev.DstIP,
					"dst_port": ev.DstPort,
					"src_ip":   ev.SrcIP,
					"src_port": ev.SrcPort,
					"family":   ev.Protocol,
					"source":   "etw_kernel_network",
					"category": category,
					"is_ai":    true,
				})
			}

			if r.dispatcher != nil {
				ts := time.Now()
				sessionID := procinfo.DetectSessionID(ev.PID)
				canonEvt := event.Event{
					SchemaVersion: 1,
					Type:          "net_connect",
					Timestamp:     ts,
					HostID:        r.hostID,
					Source:        "etw_kernel_network",
					Actor: &event.Actor{
						PID:       int(ev.PID),
						SessionID: strconv.FormatUint(uint64(sessionID), 10),
					},
					Target: &event.Target{
						IP:       ev.DstIP,
						Port:     int(ev.DstPort),
						Protocol: ev.Protocol,
					},
					Context: map[string]any{"category": category},
				}
				if aiSess := tracker.GetSessionID(ev.PID); aiSess != "" {
					canonEvt.Context["ai_session_id"] = aiSess
				}
				if aiType := tracker.GetAIType(ev.PID); aiType != "" {
					canonEvt.Context["ai_type"] = aiType
				}
				canonEvt.ID = event.GenerateID(
					r.hostID, ts.UnixNano(),
					canonEvt.Source, canonEvt.Type,
					canonEvt.Actor.PID, ev.DstIP,
				)
				r.dispatcher.Enqueue(canonEvt)
			}
		}
	}
}

// categorizePort returns a label for well-known ports.
func categorizePort(port uint16, _ string) string {
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
	case 3389:
		return "rdp"
	case 5985, 5986:
		return "winrm"
	case 445:
		return "smb"
	}
	if port > 10000 {
		return "high_port"
	}
	return "other"
}

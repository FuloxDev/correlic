//go:build linux

package ebpf

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
)

// DNSRunner wraps the DNSCollector to implement the collect.Collector interface.
// AI-focused: dispatches to Neo4j only for AI agent DNS queries.
type DNSRunner struct {
	collector  *DNSCollector
	emit       collect.EventSink
	logger     *slog.Logger
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// NewDNSRunner creates a new DNS monitoring runner.
// AI-focused: only AI-related DNS events are dispatched to Neo4j graph.
func NewDNSRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) (*DNSRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}

	collector, err := NewDNSCollector(logger)
	if err != nil {
		return nil, err
	}

	return &DNSRunner{
		collector:  collector,
		emit:       emit,
		logger:     logger,
		HostID:     hostID,
		Dispatcher: disp,
	}, nil
}

// Start implements the collect.Collector interface.
func (r *DNSRunner) Start(ctx context.Context) {
	// Start the underlying collector
	go r.collector.Start(ctx)

	r.logger.Info("eBPF DNS runner started, forwarding DNS query events")

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("eBPF DNS runner stopping")
			r.collector.Close()
			return
		case dnsEvt := <-r.collector.Events():
			// FILTER: Only proceed if this is an AI process or descendant
			tracker := GetLineageTracker()
			if !tracker.IsAI(dnsEvt.PID) {
				// Race condition check: try to register via inheritance or pattern
				if !tracker.RegisterProcess(dnsEvt.PID, dnsEvt.PPID, dnsEvt.Comm) {
					continue
				}
			}

			// Convert DNSEvent to telemetry format
			category := categorizeDNS(dnsEvt.Domain)
			payload := map[string]any{
				"pid":        dnsEvt.PID,
				"ppid":       dnsEvt.PPID,
				"uid":        dnsEvt.UID,
				"domain":     dnsEvt.Domain,
				"qtype":      dnsEvt.QTypeString(),
				"dns_server": dnsEvt.DNSServerIP(),
				"comm":       dnsEvt.Comm,
				"source":     "ebpf",
				"category":   category,
				"suspicious": isSuspiciousDNS(dnsEvt.Domain),
				"is_ai":      true, // Explicit flag
			}

			ok := r.emit("dns_query", payload)
			if !ok {
				r.logger.Debug("DNS event dropped by sink")
			}

			// Dispatch to Neo4j (Graph) - Always for AI processes now
			if r.Dispatcher != nil {
				ts := time.Now()
				canonicalEvent := event.Event{
					SchemaVersion: 1,
					Type:          "net_dns",
					Timestamp:     ts,
					HostID:        r.HostID,
					Source:        "ebpf",
					Actor: &event.Actor{
						PID:       int(dnsEvt.PID),
						PPID:      int(dnsEvt.PPID),
						Comm:      dnsEvt.Comm,
						SessionID: strconv.FormatUint(uint64(detectSessionID(dnsEvt.PID)), 10),
					},
					Target: &event.Target{
						Domain: dnsEvt.Domain,
						IP:     dnsEvt.DNSServerIP(),
					},
					Context: map[string]any{
						"domain":     dnsEvt.Domain,
						"qtype":      dnsEvt.QTypeString(),
						"dns_server": dnsEvt.DNSServerIP(),
						"category":   category,
					},
				}
				canonicalEvent.ID = event.GenerateID(
					r.HostID,
					ts.UnixNano(),
					canonicalEvent.Source,
					canonicalEvent.Type,
					canonicalEvent.Actor.PID,
					dnsEvt.Domain,
				)
				r.Dispatcher.Enqueue(canonicalEvent)
			}
		}
	}
}

// Close releases eBPF resources.
func (r *DNSRunner) Close() error {
	if r.collector != nil {
		return r.collector.Close()
	}
	return nil
}

// categorizeDNS returns a category based on the domain.
func categorizeDNS(domain string) string {
	domain = strings.ToLower(domain)

	// Known cloud providers
	if strings.Contains(domain, "amazonaws.com") || strings.Contains(domain, "aws.amazon.com") {
		return "aws"
	}
	if strings.Contains(domain, "azure.com") || strings.Contains(domain, "microsoft.com") {
		return "azure"
	}
	if strings.Contains(domain, "googleapis.com") || strings.Contains(domain, "google.com") {
		return "gcp"
	}

	// Known suspicious TLDs
	suspiciousTLDs := []string{".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click"}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(domain, tld) {
			return "suspicious_tld"
		}
	}

	// File sharing / paste services
	if strings.Contains(domain, "pastebin.com") || strings.Contains(domain, "paste.") {
		return "paste_service"
	}
	if strings.Contains(domain, "transfer.sh") || strings.Contains(domain, "file.io") {
		return "file_share"
	}

	// VPN/Proxy/Tor
	if strings.Contains(domain, "tor") || strings.Contains(domain, "onion") {
		return "tor"
	}

	// Default
	return "other"
}

// isSuspiciousDNS checks for patterns that may indicate DGA or tunneling.
func isSuspiciousDNS(domain string) bool {
	domain = strings.ToLower(domain)

	// Very long subdomains (potential DNS tunneling)
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) > 30 {
			return true
		}
	}

	// High entropy check (simplified - lots of consonants in a row)
	consonants := "bcdfghjklmnpqrstvwxz"
	consonantCount := 0
	for _, c := range domain {
		if strings.ContainsRune(consonants, c) {
			consonantCount++
		} else {
			consonantCount = 0
		}
		if consonantCount > 5 {
			return true // Many consonants in a row = possible random/DGA
		}
	}

	// Too many digits (potential DGA)
	digitCount := 0
	for _, c := range domain {
		if c >= '0' && c <= '9' {
			digitCount++
		}
	}
	if digitCount > 6 {
		return true
	}

	return false
}

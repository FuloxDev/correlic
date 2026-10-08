package esevents

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/procinfo"
)

// DNSRunner converts lookup events into canonical net_dns events. Only the
// native ESF client delivers them (ES_EVENT_TYPE_NOTIFY_LOOKUP, macOS 12+
// SDK); eslogger's "lookup" is a path lookup and is never mapped here.
type DNSRunner struct {
	src    EventSource
	source string
	emit   collect.EventSink
	logger *slog.Logger
	hostID string
	disp   dispatch.Dispatcher
}

// NewDNSRunner creates a DNS lookup runner over src. source names the
// collector in the emitted events.
func NewDNSRunner(src EventSource, source string, emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) *DNSRunner {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}
	if source == "" {
		source = "esf"
	}
	return &DNSRunner{
		src:    src,
		source: source,
		emit:   emit,
		logger: logger,
		hostID: hostID,
		disp:   disp,
	}
}

// Start processes DNS lookup events until ctx is cancelled or the source closes.
func (r *DNSRunner) Start(ctx context.Context) {
	r.logger.Info("dns runner started", "source", r.source)
	tracker := lineage.GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("dns runner stopping", "source", r.source)
			return

		case ev, ok := <-r.src.Events():
			if !ok {
				return
			}

			domain := ev.Domain
			if domain == "" {
				continue
			}

			// Lineage filter.
			if !tracker.IsAI(ev.PID) {
				ppid := ev.PPID
				if ppid == 0 {
					ppid = lookupPPID(ev.PID)
				}
				if !tracker.RegisterProcess(ev.PID, ppid, ev.Comm) {
					continue
				}
			}

			category := categorizeDNS(domain)
			suspicious := isSuspiciousDNS(domain)

			// Flat telemetry.
			if r.emit != nil {
				r.emit("dns_query", map[string]any{
					"pid":        ev.PID,
					"ppid":       ev.PPID,
					"comm":       ev.Comm,
					"domain":     domain,
					"category":   category,
					"suspicious": suspicious,
					"source":     r.source,
					"is_ai":      true,
				})
			}

			// Canonical event.
			if r.disp != nil {
				ts := time.Now()
				sessionID := procinfo.DetectSessionID(ev.PID)

				canonEvt := event.Event{
					SchemaVersion: 1,
					Type:          "net_dns",
					Timestamp:     ts,
					HostID:        r.hostID,
					Source:        r.source,
					Actor: &event.Actor{
						PID:       int(ev.PID),
						PPID:      int(ev.PPID),
						Comm:      ev.Comm,
						SessionID: strconv.FormatUint(uint64(sessionID), 10),
					},
					Target: &event.Target{
						Domain: domain,
					},
					Context: map[string]any{
						"domain":     domain,
						"category":   category,
						"suspicious": suspicious,
					},
				}
				tracker.Annotate(canonEvt.Context, ev.PID)
				canonEvt.ID = event.GenerateID(r.hostID, ts.UnixNano(), r.source, "net_dns", int(ev.PID), domain)
				r.disp.Enqueue(canonEvt)
			}
		}
	}
}

// categorizeDNS returns a category based on the domain.
// Mirrors the logic in internal/ebpf/dns_runner.go for Linux parity.
func categorizeDNS(domain string) string {
	domain = strings.ToLower(domain)

	if strings.Contains(domain, "amazonaws.com") || strings.Contains(domain, "aws.amazon.com") {
		return "aws"
	}
	if strings.Contains(domain, "azure.com") || strings.Contains(domain, "microsoft.com") {
		return "azure"
	}
	if strings.Contains(domain, "googleapis.com") || strings.Contains(domain, "google.com") {
		return "gcp"
	}

	suspiciousTLDs := []string{".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click"}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(domain, tld) {
			return "suspicious_tld"
		}
	}

	if strings.Contains(domain, "pastebin.com") || strings.Contains(domain, "paste.") {
		return "paste_service"
	}
	if strings.Contains(domain, "transfer.sh") || strings.Contains(domain, "file.io") {
		return "file_share"
	}
	if strings.Contains(domain, "tor") || strings.Contains(domain, "onion") {
		return "tor"
	}

	return "other"
}

// isSuspiciousDNS checks for patterns indicating DGA or DNS tunneling.
// Mirrors the logic in internal/ebpf/dns_runner.go for Linux parity.
func isSuspiciousDNS(domain string) bool {
	domain = strings.ToLower(domain)

	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) > 30 {
			return true
		}
	}

	consonants := "bcdfghjklmnpqrstvwxz"
	consonantRun := 0
	for _, c := range domain {
		if strings.ContainsRune(consonants, c) {
			consonantRun++
		} else {
			consonantRun = 0
		}
		if consonantRun > 5 {
			return true
		}
	}

	digitCount := 0
	for _, c := range domain {
		if c >= '0' && c <= '9' {
			digitCount++
		}
	}
	return digitCount > 6
}

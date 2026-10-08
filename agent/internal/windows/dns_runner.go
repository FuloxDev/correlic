//go:build windows

package windows

import (
	"context"
	"log/slog"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/lineage"
)

// DNSRunner consumes DNSCollector events and emits canonical net_dns events.
type DNSRunner struct {
	collector  *DNSCollector
	emit       collect.EventSink
	logger     *slog.Logger
	hostID     string
	dispatcher dispatch.Dispatcher
}

// NewDNSRunner creates an ETW-based DNS runner.
func NewDNSRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) *DNSRunner {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}
	return &DNSRunner{
		collector:  NewDNSCollector(),
		emit:       emit,
		logger:     logger,
		hostID:     hostID,
		dispatcher: disp,
	}
}

// Collector returns the underlying DNSCollector.
func (r *DNSRunner) Collector() *DNSCollector {
	return r.collector
}

// Start processes DNS events until ctx is cancelled.
func (r *DNSRunner) Start(ctx context.Context) {
	r.logger.Info("windows DNS runner started (ETW DNS-Client)")
	tracker := lineage.GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("windows DNS runner stopping")
			return
		case ev, ok := <-r.collector.Events():
			if !ok {
				return
			}

			if ev.QueryName == "" {
				continue
			}

			if !tracker.IsAI(ev.PID) && !tracker.HasAnyAI() {
				continue
			}

			if r.emit != nil {
				r.emit("net_dns", map[string]any{
					"pid":        ev.PID,
					"query_name": ev.QueryName,
					"source":     "etw_dns_client",
					"is_ai":      true,
				})
			}

			if r.dispatcher != nil {
				ts := time.Now()
				canonEvt := event.Event{
					SchemaVersion: 1,
					Type:          "net_dns",
					Timestamp:     ts,
					HostID:        r.hostID,
					Source:        "etw_dns_client",
					Actor:         &event.Actor{PID: int(ev.PID)},
					Target:        &event.Target{IP: ev.QueryName},
					Context: map[string]any{
						"query_name": ev.QueryName,
					},
				}
				tracker.Annotate(canonEvt.Context, ev.PID)
				canonEvt.ID = event.GenerateID(
					r.hostID, ts.UnixNano(),
					canonEvt.Source, canonEvt.Type,
					canonEvt.Actor.PID, ev.QueryName,
				)
				r.dispatcher.Enqueue(canonEvt)
			}
		}
	}
}

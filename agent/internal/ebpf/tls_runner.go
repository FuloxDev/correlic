//go:build linux

package ebpf

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
)

// TLSRunner orchestrates the TLSCollector and dispatches events.
type TLSRunner struct {
	collector  *TLSCollector
	emit       collect.EventSink
	logger     *slog.Logger
	HostID     string
	Dispatcher dispatch.Dispatcher
}

// NewTLSRunner creates a new TLS monitoring runner.
func NewTLSRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) (*TLSRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}

	collector, err := NewTLSCollector(logger)
	if err != nil {
		return nil, err
	}

	runner := &TLSRunner{
		collector:  collector,
		emit:       emit,
		logger:     logger,
		HostID:     hostID,
		Dispatcher: disp,
	}

	// Register listener to push AI PIDs to the kernel map
	GetLineageTracker().AddListener(func(pid uint32) {
		if err := collector.UpdateAIProcess(pid); err != nil {
			logger.Error("failed to update AI process in TLS filter", "pid", pid, "error", err)
		}
	})

	// Register removal listener to clean up exited PIDs from the kernel map
	GetLineageTracker().AddRemoveListener(func(pid uint32) {
		if err := collector.RemoveAIProcess(pid); err != nil {
			logger.Warn("failed to remove AI process from TLS filter", "pid", pid, "error", err)
		}
	})

	return runner, nil
}

// Start implements the collect.Collector interface.
func (r *TLSRunner) Start(ctx context.Context) {
	// Start the underlying collector
	go r.collector.Start(ctx)

	r.logger.Info("eBPF TLS runner started, tracing plaintext AI traffic")

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("eBPF TLS runner stopping")
			r.collector.Close()
			return
		case evt := <-r.collector.Events():
			payload := map[string]any{
				"pid":          evt.PID,
				"tgid":         evt.TGID,
				"uid":          evt.UID,
				"len":          evt.Len,
				"direction":    evt.Direction, // 0=Write (Prompt), 1=Read (Response)
				"comm":         evt.Comm,
				"data":         string(evt.Data), // Send as string for now (JSON-safe?)
				"source":       "ebpf_uprobe",
				"timestamp_ns": evt.TimestampNs,
				"is_ai":        true,
			}

			// 1. Emit to local file/log sink (optional)
			r.emit("net_tls", payload)

			// 2. Dispatch to Backend
			if r.Dispatcher != nil {
				ts := time.Now()
				// Use "net_tls" type. Ensure backend schema supports it.
				canonicalEvent := event.Event{
					SchemaVersion: 1,
					Type:          "net_tls",
					Timestamp:     ts,
					HostID:        r.HostID,
					Source:        "ebpf_uprobe",
					Actor: &event.Actor{
						PID:       int(evt.PID),
						Comm:      evt.Comm,
						SessionID: strconv.FormatUint(uint64(detectSessionID(evt.PID)), 10),
					},
					Context: map[string]any{
						"direction": func() string {
							if evt.Direction == 0 {
								return "write"
							}
							return "read"
						}(),
						"length": int(evt.Len),
						// In real world, we might want to buffer/reassemble here if data is fragmented.
						// For MVP, we send raw chunks.
						"payload": string(evt.Data),
					},
				}
				canonicalEvent.ID = event.GenerateID(
					r.HostID,
					ts.UnixNano(),
					canonicalEvent.Source,
					canonicalEvent.Type,
					canonicalEvent.Actor.PID,
					evt.Comm, // Unique ID per chunk (using Comm as proxy for now, ideally hash of payload or sequence)
				)
				r.Dispatcher.Enqueue(canonicalEvent)
			}
		}
	}
}

// Close cleans up resources.
func (r *TLSRunner) Close() error {
	return r.collector.Close()
}

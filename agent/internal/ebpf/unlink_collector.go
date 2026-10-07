//go:build linux

// Package ebpf provides eBPF-based file deletion monitoring.
package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// UnlinkEvent represents a file deletion captured by eBPF.
type UnlinkEvent struct {
	PID         uint32
	PPID        uint32
	UID         uint32
	TimestampNs uint64
	DFD         int32  // Directory file descriptor
	Flags       uint32 // unlinkat flags
	Comm        string // Command name
	ParentComm  string // Parent command name
	Path        string // File path being deleted
}

// UnlinkCollector manages the unlink eBPF program lifecycle.
type UnlinkCollector struct {
	objs         *unlinkObjects
	linkUnlink   link.Link
	linkUnlinkAt link.Link
	reader       *ringbuf.Reader
	events       chan UnlinkEvent
	logger       *slog.Logger
}

// NewUnlinkCollector creates a new eBPF-based file deletion collector.
func NewUnlinkCollector(logger *slog.Logger) (*UnlinkCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Remove memory lock limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	// Load the eBPF objects
	objs := &unlinkObjects{}
	if err := loadUnlinkObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading unlink eBPF objects: %w", err)
	}

	// Attach to unlink tracepoint
	lUnlink, err := link.Tracepoint("syscalls", "sys_enter_unlink", objs.TraceUnlink, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching unlink tracepoint: %w", err)
	}

	// Attach to unlinkat tracepoint
	lUnlinkAt, err := link.Tracepoint("syscalls", "sys_enter_unlinkat", objs.TraceUnlinkat, nil)
	if err != nil {
		lUnlink.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching unlinkat tracepoint: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.UnlinkEvents)
	if err != nil {
		lUnlinkAt.Close()
		lUnlink.Close()
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return &UnlinkCollector{
		objs:         objs,
		linkUnlink:   lUnlink,
		linkUnlinkAt: lUnlinkAt,
		reader:       reader,
		events:       make(chan UnlinkEvent, 1000),
		logger:       logger,
	}, nil
}

// Events returns a channel of unlink events.
func (c *UnlinkCollector) Events() <-chan UnlinkEvent {
	return c.events
}

// Start begins reading events from the eBPF program.
func (c *UnlinkCollector) Start(ctx context.Context) {
	c.logger.Info("eBPF unlink collector started (monitoring file deletions)")

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("eBPF unlink collector stopping")
			return
		default:
		}

		// Read the next event
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				c.logger.Info("unlink events ring buffer closed, stopping")
				return
			}
			c.logger.Warn("reading from unlink events ring buffer", "error", err)
			continue
		}

		// Parse the event
		event, err := parseUnlinkEvent(record.RawSample)
		if err != nil {
			c.logger.Warn("parsing unlink event", "error", err)
			continue
		}

		// Send to channel
		select {
		case c.events <- event:
		default:
			c.logger.Warn("unlink event channel full, dropping event")
		}
	}
}

// Close releases eBPF resources.
func (c *UnlinkCollector) Close() error {
	c.reader.Close()
	c.linkUnlinkAt.Close()
	c.linkUnlink.Close()
	return c.objs.Close()
}

// parseUnlinkEvent converts raw bytes from the ring buffer to UnlinkEvent.
// Layout: pid(4) + ppid(4) + uid(4) + pad(4) + timestamp_ns @16 + dfd @24 + flags @28 + comm @32 + pcomm @48 + path @64 = 320 bytes
func parseUnlinkEvent(data []byte) (UnlinkEvent, error) {
	if len(data) < 320 {
		return UnlinkEvent{}, fmt.Errorf("unlink event too short: %d bytes (expected 320)", len(data))
	}

	event := UnlinkEvent{
		PID:         binary.LittleEndian.Uint32(data[0:4]),
		PPID:        binary.LittleEndian.Uint32(data[4:8]),
		UID:         binary.LittleEndian.Uint32(data[8:12]),
		TimestampNs: binary.LittleEndian.Uint64(data[16:24]),
		DFD:         int32(binary.LittleEndian.Uint32(data[24:28])),
		Flags:       binary.LittleEndian.Uint32(data[28:32]),
		Comm:        nullTerminatedString(data[32:48]),
		ParentComm:  nullTerminatedString(data[48:64]),
		Path:        nullTerminatedString(data[64:320]),
	}

	return event, nil
}

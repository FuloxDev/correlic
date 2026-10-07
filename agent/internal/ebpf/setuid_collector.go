//go:build linux

// Package ebpf provides eBPF-based privilege escalation monitoring.
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

// SetuidEvent represents a privilege change captured by eBPF.
type SetuidEvent struct {
	PID         uint32
	PPID        uint32
	OldUID      uint32 // Original UID
	OldEUID     uint32 // Original effective UID
	NewUID      uint32 // Target real UID
	NewEUID     uint32 // Target effective UID
	NewSUID     uint32 // Target saved UID
	TimestampNs uint64
	SyscallType uint8 // 0=setuid, 1=setgid, 2=setresuid, 3=setresgid
	Comm        string
	ParentComm  string
}

// SyscallName returns the human-readable syscall name.
func (e *SetuidEvent) SyscallName() string {
	switch e.SyscallType {
	case 0:
		return "setuid"
	case 1:
		return "setgid"
	case 2:
		return "setresuid"
	case 3:
		return "setresgid"
	default:
		return "unknown"
	}
}

// IsEscalation returns true if this is a privilege escalation (non-root -> root).
func (e *SetuidEvent) IsEscalation() bool {
	// UID 0 = root
	return e.OldUID != 0 && (e.NewUID == 0 || e.NewEUID == 0)
}

// IsDropping returns true if this is a privilege drop (root -> non-root).
func (e *SetuidEvent) IsDropping() bool {
	return e.OldUID == 0 && e.NewUID != 0
}

// SetuidCollector manages the setuid eBPF program lifecycle.
type SetuidCollector struct {
	objs          *setuidObjects
	linkSetuid    link.Link
	linkSetgid    link.Link
	linkSetresuid link.Link
	linkSetresgid link.Link
	reader        *ringbuf.Reader
	events        chan SetuidEvent
	logger        *slog.Logger
}

// NewSetuidCollector creates a new eBPF-based privilege escalation collector.
func NewSetuidCollector(logger *slog.Logger) (*SetuidCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Remove memory lock limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	// Load the eBPF objects
	objs := &setuidObjects{}
	if err := loadSetuidObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading setuid eBPF objects: %w", err)
	}

	// Attach to setuid tracepoint
	lSetuid, err := link.Tracepoint("syscalls", "sys_enter_setuid", objs.TraceSetuid, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching setuid tracepoint: %w", err)
	}

	// Attach to setgid tracepoint
	lSetgid, err := link.Tracepoint("syscalls", "sys_enter_setgid", objs.TraceSetgid, nil)
	if err != nil {
		lSetuid.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching setgid tracepoint: %w", err)
	}

	// Attach to setresuid tracepoint
	lSetresuid, err := link.Tracepoint("syscalls", "sys_enter_setresuid", objs.TraceSetresuid, nil)
	if err != nil {
		lSetgid.Close()
		lSetuid.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching setresuid tracepoint: %w", err)
	}

	// Attach to setresgid tracepoint
	lSetresgid, err := link.Tracepoint("syscalls", "sys_enter_setresgid", objs.TraceSetresgid, nil)
	if err != nil {
		lSetresuid.Close()
		lSetgid.Close()
		lSetuid.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching setresgid tracepoint: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.SetuidEvents)
	if err != nil {
		lSetresgid.Close()
		lSetresuid.Close()
		lSetgid.Close()
		lSetuid.Close()
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return &SetuidCollector{
		objs:          objs,
		linkSetuid:    lSetuid,
		linkSetgid:    lSetgid,
		linkSetresuid: lSetresuid,
		linkSetresgid: lSetresgid,
		reader:        reader,
		events:        make(chan SetuidEvent, 1000),
		logger:        logger,
	}, nil
}

// Events returns a channel of setuid events.
func (c *SetuidCollector) Events() <-chan SetuidEvent {
	return c.events
}

// Start begins reading events from the eBPF program.
func (c *SetuidCollector) Start(ctx context.Context) {
	c.logger.Info("eBPF setuid collector started (monitoring privilege changes)")

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("eBPF setuid collector stopping")
			return
		default:
		}

		// Read the next event
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				c.logger.Info("setuid events ring buffer closed, stopping")
				return
			}
			c.logger.Warn("reading from setuid events ring buffer", "error", err)
			continue
		}

		// Parse the event
		event, err := parseSetuidEvent(record.RawSample)
		if err != nil {
			c.logger.Warn("parsing setuid event", "error", err)
			continue
		}

		// Send to channel
		select {
		case c.events <- event:
		default:
			c.logger.Warn("setuid event channel full, dropping event")
		}
	}
}

// Close releases eBPF resources.
func (c *SetuidCollector) Close() error {
	c.reader.Close()
	c.linkSetresgid.Close()
	c.linkSetresuid.Close()
	c.linkSetgid.Close()
	c.linkSetuid.Close()
	return c.objs.Close()
}

// parseSetuidEvent converts raw bytes from the ring buffer to SetuidEvent.
// Layout: pid(4) + ppid(4) + old_uid(4) + old_euid(4) + new_uid(4) + new_euid(4) + new_suid(4) + timestamp(8) + syscall_type(1) + pad(3) + comm(16) + pcomm(16) = 72 bytes
func parseSetuidEvent(data []byte) (SetuidEvent, error) {
	if len(data) < 72 {
		return SetuidEvent{}, fmt.Errorf("setuid event too short: %d bytes (expected 72)", len(data))
	}

	event := SetuidEvent{
		PID:         binary.LittleEndian.Uint32(data[0:4]),
		PPID:        binary.LittleEndian.Uint32(data[4:8]),
		OldUID:      binary.LittleEndian.Uint32(data[8:12]),
		OldEUID:     binary.LittleEndian.Uint32(data[12:16]),
		NewUID:      binary.LittleEndian.Uint32(data[16:20]),
		NewEUID:     binary.LittleEndian.Uint32(data[20:24]),
		NewSUID:     binary.LittleEndian.Uint32(data[24:28]),
		TimestampNs: binary.LittleEndian.Uint64(data[28:36]),
		SyscallType: data[36],
		Comm:        nullTerminatedString(data[40:56]),
		ParentComm:  nullTerminatedString(data[56:72]),
	}

	return event, nil
}

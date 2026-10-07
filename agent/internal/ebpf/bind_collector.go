//go:build linux

// Package ebpf provides eBPF-based socket bind monitoring.
package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// BindEvent represents a socket bind operation captured by eBPF.
type BindEvent struct {
	PID         uint32
	PPID        uint32
	UID         uint32
	TimestampNs uint64
	Port        uint16   // Port being bound
	Family      uint16   // AF_INET or AF_INET6
	AddrV4      uint32   // IPv4 address (network byte order)
	AddrV6      [16]byte // IPv6 address
	Comm        string   // Command name
	ParentComm  string   // Parent command name
}

// BindAddr returns the bind address as a string.
func (e *BindEvent) BindAddr() string {
	if e.Family == 2 { // AF_INET
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, e.AddrV4)
		return ip.String()
	}
	// AF_INET6
	return net.IP(e.AddrV6[:]).String()
}

// IsWildcard returns true if binding to all interfaces (0.0.0.0 or ::).
func (e *BindEvent) IsWildcard() bool {
	if e.Family == 2 { // AF_INET
		return e.AddrV4 == 0
	}
	// AF_INET6: check if all zeros
	for _, b := range e.AddrV6 {
		if b != 0 {
			return false
		}
	}
	return true
}

// BindCollector manages the bind eBPF program lifecycle.
type BindCollector struct {
	objs   *bindObjects
	link   link.Link
	reader *ringbuf.Reader
	events chan BindEvent
	logger *slog.Logger
}

// NewBindCollector creates a new eBPF-based bind collector.
func NewBindCollector(logger *slog.Logger) (*BindCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Remove memory lock limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	// Load the eBPF objects
	objs := &bindObjects{}
	if err := loadBindObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading bind eBPF objects: %w", err)
	}

	// Attach to the inet_listen kprobe (captures port AFTER assignment)
	l, err := link.Kprobe("inet_listen", objs.TraceListen, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching inet_listen kprobe: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.BindEvents)
	if err != nil {
		l.Close()
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return &BindCollector{
		objs:   objs,
		link:   l,
		reader: reader,
		events: make(chan BindEvent, 1000),
		logger: logger,
	}, nil
}

// Events returns a channel of bind events.
func (c *BindCollector) Events() <-chan BindEvent {
	return c.events
}

// Start begins reading events from the eBPF program.
func (c *BindCollector) Start(ctx context.Context) {
	c.logger.Info("eBPF bind collector started (monitoring socket binds)")

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("eBPF bind collector stopping")
			return
		default:
		}

		// Read the next event
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				c.logger.Info("bind events ring buffer closed, stopping")
				return
			}
			c.logger.Warn("reading from bind events ring buffer", "error", err)
			continue
		}

		// Parse the event
		event, err := parseBindEvent(record.RawSample)
		if err != nil {
			c.logger.Warn("parsing bind event", "error", err)
			continue
		}

		// Send to channel
		select {
		case c.events <- event:
		default:
			c.logger.Warn("bind event channel full, dropping event")
		}
	}
}

// Close releases eBPF resources.
func (c *BindCollector) Close() error {
	c.reader.Close()
	c.link.Close()
	return c.objs.Close()
}

// parseBindEvent converts raw bytes from the ring buffer to BindEvent.
//
// IMPORTANT: The C struct is naturally aligned, so there is padding after the
// third u32 to align the following u64:
//
//	pid(4) + ppid(4) + uid(4) + pad(4) + timestamp(8) + port(2) + family(2) + addr_v4(4) + addr_v6(16) + comm(16) + pcomm(16)
//
// = 80 bytes
func parseBindEvent(data []byte) (BindEvent, error) {
	if len(data) < 80 {
		return BindEvent{}, fmt.Errorf("bind event too short: %d bytes (expected 80)", len(data))
	}

	event := BindEvent{
		PID:         binary.LittleEndian.Uint32(data[0:4]),
		PPID:        binary.LittleEndian.Uint32(data[4:8]),
		UID:         binary.LittleEndian.Uint32(data[8:12]),
		TimestampNs: binary.LittleEndian.Uint64(data[16:24]),
		Port:        binary.LittleEndian.Uint16(data[24:26]),
		Family:      binary.LittleEndian.Uint16(data[26:28]),
		// IPv4 addresses are stored in network byte order; decode accordingly so
		// BindAddr() renders correct dotted-quad output.
		AddrV4:     binary.BigEndian.Uint32(data[28:32]),
		Comm:       nullTerminatedString(data[48:64]), // 16 bytes
		ParentComm: nullTerminatedString(data[64:80]), // 16 bytes
	}

	// Copy IPv6 address
	copy(event.AddrV6[:], data[32:48])

	return event, nil
}

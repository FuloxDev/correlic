//go:build linux

// Package ebpf provides eBPF-based network connection monitoring.
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

// ConnectEvent represents a network connection captured by eBPF.
type ConnectEvent struct {
	PID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	TimestampNs uint64
	DPort       uint16   // Destination port
	Family      uint16   // AF_INET or AF_INET6
	DAddrV4     uint32   // IPv4 address (network byte order)
	DAddrV6     [16]byte // IPv6 address
	Comm        string   // Command name
	ParentComm  string   // Parent command name
}

// DstIP returns the destination IP address as a string.
func (e *ConnectEvent) DstIP() string {
	if e.Family == 2 { // AF_INET
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, e.DAddrV4)
		return ip.String()
	}
	// AF_INET6
	return net.IP(e.DAddrV6[:]).String()
}

// NetworkCollector manages the network eBPF program lifecycle.
type NetworkCollector struct {
	objs   *connectObjects
	link   link.Link
	reader *ringbuf.Reader
	events chan ConnectEvent
	logger *slog.Logger
}

// NewNetworkCollector creates a new eBPF-based network connection collector.
func NewNetworkCollector(logger *slog.Logger) (*NetworkCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Remove memory lock limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	// Load the eBPF objects
	objs := &connectObjects{}
	if err := loadConnectObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading connect eBPF objects: %w", err)
	}

	// Attach to the connect tracepoint
	l, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching connect tracepoint: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.ConnectEvents)
	if err != nil {
		l.Close()
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return &NetworkCollector{
		objs:   objs,
		link:   l,
		reader: reader,
		events: make(chan ConnectEvent, 1000),
		logger: logger,
	}, nil
}

// Events returns a channel of connect events.
func (c *NetworkCollector) Events() <-chan ConnectEvent {
	return c.events
}

// Start begins reading events from the eBPF program.
func (c *NetworkCollector) Start(ctx context.Context) {
	c.logger.Info("eBPF network collector started (monitoring outbound connections)")

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("eBPF network collector stopping")
			return
		default:
		}

		// Read the next event
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				c.logger.Info("connect events ring buffer closed, stopping")
				return
			}
			c.logger.Warn("reading from connect events ring buffer", "error", err)
			continue
		}

		// Parse the event
		event, err := parseConnectEvent(record.RawSample)
		if err != nil {
			c.logger.Warn("parsing connect event", "error", err)
			continue
		}

		// Send to channel
		select {
		case c.events <- event:
		default:
			c.logger.Warn("connect event channel full, dropping event")
		}
	}
}

// Close releases eBPF resources.
func (c *NetworkCollector) Close() error {
	c.reader.Close()
	c.link.Close()
	return c.objs.Close()
}

// parseConnectEvent converts raw bytes from the ring buffer to ConnectEvent.
// Layout: pid(4) + ppid(4) + uid(4) + gid(4) + timestamp(8) + dport(2) + family(2) + daddr_v4(4) + daddr_v6(16) + comm(16) + pcomm(16) = 80 bytes
// Note: 4x __u32 = 16 bytes before __u64, already 8-byte aligned — no padding inserted.
func parseConnectEvent(data []byte) (ConnectEvent, error) {
	if len(data) < 80 {
		return ConnectEvent{}, fmt.Errorf("connect event too short: %d bytes (expected 80)", len(data))
	}

	event := ConnectEvent{
		PID:         binary.LittleEndian.Uint32(data[0:4]),
		PPID:        binary.LittleEndian.Uint32(data[4:8]),
		UID:         binary.LittleEndian.Uint32(data[8:12]),
		GID:         binary.LittleEndian.Uint32(data[12:16]),
		TimestampNs: binary.LittleEndian.Uint64(data[16:24]),
		DPort:       binary.LittleEndian.Uint16(data[24:26]),
		Family:      binary.LittleEndian.Uint16(data[26:28]),
		// IPv4 addresses are stored in network byte order; decode accordingly so
		// DstIP() renders correct dotted-quad output.
		DAddrV4:    binary.BigEndian.Uint32(data[28:32]),
		Comm:       nullTerminatedString(data[48:64]), // 16 bytes
		ParentComm: nullTerminatedString(data[64:80]), // 16 bytes
	}

	// Copy IPv6 address
	copy(event.DAddrV6[:], data[32:48])

	return event, nil
}

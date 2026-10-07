//go:build linux

// Package ebpf provides eBPF-based inbound connection (accept/accept4) monitoring.
package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// AcceptEvent represents an inbound connection captured at accept/accept4.
type AcceptEvent struct {
	PID          uint32
	PPID         uint32
	UID          uint32
	GID          uint32
	TimestampNs  uint64
	Family       uint16
	ClientPort   uint16
	ClientAddrV4 uint32
	ClientAddrV6 [16]byte
	Comm         string
	ParentComm   string
}

// ClientIP returns the client IP address as a string.
func (e *AcceptEvent) ClientIP() string {
	if e.Family == 2 { // AF_INET
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, e.ClientAddrV4)
		return ip.String()
	}
	return net.IP(e.ClientAddrV6[:]).String()
}

// AcceptCollector manages the accept eBPF program lifecycle.
type AcceptCollector struct {
	objs   *acceptObjects
	links  []link.Link
	reader *ringbuf.Reader
	events chan AcceptEvent
	logger *slog.Logger
}

// NewAcceptCollector creates a new accept eBPF collector.
func NewAcceptCollector(logger *slog.Logger) (*AcceptCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	objs := &acceptObjects{}
	if err := loadAcceptObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading accept eBPF objects: %w", err)
	}

	tracepoints := []struct {
		cat, name string
		prog      *ebpf.Program
	}{
		{"syscalls", "sys_enter_accept", objs.TraceAcceptEnter},
		{"syscalls", "sys_exit_accept", objs.TraceAcceptExit},
		{"syscalls", "sys_enter_accept4", objs.TraceAccept4Enter},
		{"syscalls", "sys_exit_accept4", objs.TraceAccept4Exit},
	}

	var links []link.Link
	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.cat, tp.name, tp.prog, nil)
		if err != nil {
			for _, lnk := range links {
				lnk.Close()
			}
			objs.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", tp.cat, tp.name, err)
		}
		links = append(links, l)
	}

	reader, err := ringbuf.NewReader(objs.AcceptEvents)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return &AcceptCollector{
		objs:   objs,
		links:  links,
		reader: reader,
		events: make(chan AcceptEvent, 1000),
		logger: logger,
	}, nil
}

// Events returns the channel of accept events.
func (c *AcceptCollector) Events() <-chan AcceptEvent {
	return c.events
}

// Start reads events from the ring buffer.
func (c *AcceptCollector) Start(ctx context.Context) {
	c.logger.Info("eBPF accept collector started (monitoring inbound connections)")

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("eBPF accept collector stopping")
			return
		default:
		}

		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			c.logger.Warn("reading from accept events ring buffer", "error", err)
			continue
		}

		event, err := parseAcceptEvent(record.RawSample)
		if err != nil {
			c.logger.Warn("parsing accept event", "error", err)
			continue
		}

		select {
		case c.events <- event:
		default:
			c.logger.Warn("accept event channel full, dropping event")
		}
	}
}

// Close releases eBPF resources.
func (c *AcceptCollector) Close() error {
	c.reader.Close()
	for _, l := range c.links {
		l.Close()
	}
	return c.objs.Close()
}

// parseAcceptEvent converts raw ring buffer bytes to AcceptEvent.
// Layout: pid(4)+ppid(4)+uid(4)+gid(4)+timestamp_ns(8)+family(2)+client_port(2)+client_addr_v4(4)+client_addr_v6(16)+comm(16)+pcomm(16) = 80 bytes
func parseAcceptEvent(data []byte) (AcceptEvent, error) {
	if len(data) < 80 {
		return AcceptEvent{}, fmt.Errorf("accept event too short: %d bytes", len(data))
	}
	event := AcceptEvent{
		PID:          binary.LittleEndian.Uint32(data[0:4]),
		PPID:         binary.LittleEndian.Uint32(data[4:8]),
		UID:          binary.LittleEndian.Uint32(data[8:12]),
		GID:          binary.LittleEndian.Uint32(data[12:16]),
		TimestampNs:  binary.LittleEndian.Uint64(data[16:24]),
		Family:       binary.LittleEndian.Uint16(data[24:26]),
		ClientPort:   binary.LittleEndian.Uint16(data[26:28]),
		ClientAddrV4: binary.BigEndian.Uint32(data[28:32]),
		Comm:         nullTerminatedString(data[48:64]),
		ParentComm:   nullTerminatedString(data[64:80]),
	}
	copy(event.ClientAddrV6[:], data[32:48])
	return event, nil
}

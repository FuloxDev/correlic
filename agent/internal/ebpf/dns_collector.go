//go:build linux

// Package ebpf provides eBPF-based DNS query monitoring.
package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const MaxDNSName = 128

// DNSEvent represents a DNS query captured by eBPF.
type DNSEvent struct {
	PID         uint32
	PPID        uint32
	UID         uint32
	TimestampNs uint64
	QType       uint16 // Query type (A=1, AAAA=28, CNAME=5, MX=15, TXT=16)
	QClass      uint16 // Query class (IN=1)
	DstIP       uint32 // DNS server IP
	Comm        string // Command name
	Domain      string // Domain being queried
}

// DNSServerIP returns the DNS server IP as a string.
func (e *DNSEvent) DNSServerIP() string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, e.DstIP)
	return ip.String()
}

// QTypeString returns the query type as a string.
func (e *DNSEvent) QTypeString() string {
	switch e.QType {
	case 1:
		return "A"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	default:
		return fmt.Sprintf("TYPE%d", e.QType)
	}
}

// DNSCollector manages the DNS eBPF program lifecycle.
type DNSCollector struct {
	objs   *dnsObjects
	link   link.Link
	reader *ringbuf.Reader
	events chan DNSEvent
	logger *slog.Logger
}

// NewDNSCollector creates a new eBPF-based DNS query collector.
func NewDNSCollector(logger *slog.Logger) (*DNSCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Remove memory lock limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	// Load the eBPF objects
	objs := &dnsObjects{}
	if err := loadDnsObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading dns eBPF objects: %w", err)
	}

	// Attach kprobe to udp_sendmsg — catches ALL UDP sends (sendto, send,
	// sendmsg, write) regardless of whether the socket is connected or not.
	// The previous sys_enter_sendto hook missed send() on connected sockets
	// because addr was NULL, which is the path glibc's DNS resolver uses.
	l, err := link.Kprobe("udp_sendmsg", objs.TraceDnsUdpSendmsg, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching udp_sendmsg kprobe: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.DnsEvents)
	if err != nil {
		l.Close()
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return &DNSCollector{
		objs:   objs,
		link:   l,
		reader: reader,
		events: make(chan DNSEvent, 1000),
		logger: logger,
	}, nil
}

// Events returns a channel of DNS events.
func (c *DNSCollector) Events() <-chan DNSEvent {
	return c.events
}

// Start begins reading events from the eBPF program.
func (c *DNSCollector) Start(ctx context.Context) {
	c.logger.Info("eBPF DNS collector started (monitoring DNS queries)")

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("eBPF DNS collector stopping")
			return
		default:
		}

		// Read the next event
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				c.logger.Info("DNS events ring buffer closed, stopping")
				return
			}
			c.logger.Warn("reading from DNS events ring buffer", "error", err)
			continue
		}

		// Parse the event
		event, err := parseDNSEvent(record.RawSample)
		if err != nil {
			c.logger.Warn("parsing DNS event", "error", err)
			continue
		}

		// Send to channel
		select {
		case c.events <- event:
		default:
			c.logger.Warn("DNS event channel full, dropping event")
		}
	}
}

// Close releases eBPF resources.
func (c *DNSCollector) Close() error {
	c.reader.Close()
	c.link.Close()
	return c.objs.Close()
}

// parseDNSEvent converts raw bytes from the ring buffer to DNSEvent.
//
// IMPORTANT: The C struct is naturally aligned, so there is padding after the
// third u32 to align the following u64:
//
//	pid(4) + ppid(4) + uid(4) + pad(4) + timestamp(8) + qtype(2) + qclass(2) + dst_ip(4) + comm(16) + domain(128)
//
// = 176 bytes
func parseDNSEvent(data []byte) (DNSEvent, error) {
	if len(data) < 176 {
		return DNSEvent{}, fmt.Errorf("DNS event too short: %d bytes (expected 176)", len(data))
	}

	event := DNSEvent{
		PID:         binary.LittleEndian.Uint32(data[0:4]),
		PPID:        binary.LittleEndian.Uint32(data[4:8]),
		UID:         binary.LittleEndian.Uint32(data[8:12]),
		TimestampNs: binary.LittleEndian.Uint64(data[16:24]),
		QType:       binary.LittleEndian.Uint16(data[24:26]),
		QClass:      binary.LittleEndian.Uint16(data[26:28]),
		// IPv4 addresses are stored in network byte order; decode accordingly so
		// DNSServerIP() renders correct dotted-quad output.
		DstIP:  binary.BigEndian.Uint32(data[28:32]),
		Comm:   nullTerminatedString(data[32:48]),  // 16 bytes
		Domain: nullTerminatedString(data[48:176]), // 128 bytes (raw question bytes)
	}

	if domain, qtype, qclass, ok := parseDNSQuestion(data[48:176]); ok {
		event.Domain = domain
		if qtype != 0 {
			event.QType = qtype
		}
		if qclass != 0 {
			event.QClass = qclass
		}
	}

	return event, nil
}

// parseDNSQuestion parses a DNS question section (QNAME + QTYPE + QCLASS).
// Returns the domain, qtype, qclass, and ok=false if parsing fails.
func parseDNSQuestion(raw []byte) (string, uint16, uint16, bool) {
	if len(raw) == 0 {
		return "", 0, 0, false
	}

	var labels []string
	i := 0
	for i < len(raw) {
		l := int(raw[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 {
			// Compression pointer not supported with partial buffers.
			return "", 0, 0, false
		}
		i++
		if i+l > len(raw) {
			return "", 0, 0, false
		}
		labels = append(labels, string(raw[i:i+l]))
		i += l
	}

	if len(labels) == 0 {
		return "", 0, 0, false
	}

	domain := strings.Join(labels, ".")

	// Try to parse QTYPE and QCLASS if present
	if i+4 <= len(raw) {
		qtype := binary.BigEndian.Uint16(raw[i : i+2])
		qclass := binary.BigEndian.Uint16(raw[i+2 : i+4])
		return domain, qtype, qclass, true
	}

	return domain, 0, 0, true
}

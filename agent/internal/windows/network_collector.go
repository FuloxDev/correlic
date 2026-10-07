//go:build windows

package windows

import (
	"fmt"
	"sync/atomic"
	"unsafe"
)

var netEventCount atomic.Int64

// NetEvent is emitted when a TCP connection is established.
type NetEvent struct {
	PID      uint32
	DstIP    string
	DstPort  uint16
	SrcIP    string
	SrcPort  uint16
	Protocol string // "tcp" or "udp"
}

// NetworkCollector subscribes to Microsoft-Windows-Kernel-Network ETW events.
type NetworkCollector struct {
	events chan NetEvent
}

// NewNetworkCollector returns a collector for kernel network events.
func NewNetworkCollector() *NetworkCollector {
	return &NetworkCollector{
		events: make(chan NetEvent, 4096),
	}
}

// Events returns the receive-only channel of network events.
func (c *NetworkCollector) Events() <-chan NetEvent {
	return c.events
}

// Handle is called for every ETW event; it filters for Kernel-Network.
func (c *NetworkCollector) Handle(rec *EventRecord) {
	if !GUIDEquals(rec.ProviderID, GUIDKernelNetwork()) {
		return
	}

	// Kernel-Network event IDs:
	//  12 = TcpIpConnect (IPv4 connect)
	//  26 = TcpIpConnectIPV6
	// We also catch accept and send/recv as secondary indicators.
	switch rec.EventID {
	case 12, 26, 15, 29: // TcpConnect IPv4/IPv6, TcpAccept IPv4/IPv6
	default:
		return
	}

	if rec.UserDataLen < 16 || rec.UserData == 0 {
		return
	}

	ud := unsafe.Pointer(rec.UserData)

	// The actual application PID is in UserData at offset 0, NOT in
	// rec.ProcessID. For Kernel-Network events, rec.ProcessID is often 0
	// or 4 (SYSTEM), while the real process that owns the socket is in
	// the event payload.
	pid := *(*uint32)(unsafe.Pointer(uintptr(ud)))

	ev := NetEvent{
		PID:      pid,
		Protocol: "tcp",
	}

	if rec.EventID == 12 || rec.EventID == 15 {
		// IPv4: [PID u32][size u32][daddr u32][saddr u32][dport u16][sport u16]
		if rec.UserDataLen >= 20 {
			dAddr := *(*uint32)(unsafe.Pointer(uintptr(ud) + 8))
			sAddr := *(*uint32)(unsafe.Pointer(uintptr(ud) + 12))
			dPort := *(*uint16)(unsafe.Pointer(uintptr(ud) + 16))
			sPort := *(*uint16)(unsafe.Pointer(uintptr(ud) + 18))
			ev.DstIP = ipv4String(dAddr)
			ev.SrcIP = ipv4String(sAddr)
			ev.DstPort = swapPort(dPort)
			ev.SrcPort = swapPort(sPort)
		}
	} else if rec.EventID == 26 || rec.EventID == 29 {
		// IPv6: [PID u32][size u32][daddr 16B][saddr 16B][dport u16][sport u16]
		// Total: 44 bytes. Ports at offsets 40 and 42.
		ev.Protocol = "tcp6"
		if rec.UserDataLen >= 44 {
			dPort := *(*uint16)(unsafe.Pointer(uintptr(ud) + 40))
			sPort := *(*uint16)(unsafe.Pointer(uintptr(ud) + 42))
			ev.DstPort = swapPort(dPort)
			ev.SrcPort = swapPort(sPort)
			ev.DstIP = ipv6String(ud, 8)
			ev.SrcIP = ipv6String(ud, 24)
		}
	}

	if ev.DstIP == "" || ev.DstPort == 0 {
		return
	}

	netEventCount.Add(1)

	select {
	case c.events <- ev:
	default:
	}
}

// Close drains and closes the events channel.
func (c *NetworkCollector) Close() {
	close(c.events)
}

// ipv4String converts a network-byte-order uint32 to a dotted-decimal string.
func ipv4String(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		addr&0xFF,
		(addr>>8)&0xFF,
		(addr>>16)&0xFF,
		(addr>>24)&0xFF,
	)
}

// swapPort converts big-endian port to host byte order.
func swapPort(p uint16) uint16 {
	return (p>>8)&0xFF | (p&0xFF)<<8
}

// ipv6String reads a 16-byte IPv6 address at the given offset and returns it
// as a colon-hex string. Returns "::1" for loopback, abbreviated form otherwise.
func ipv6String(base unsafe.Pointer, offset uintptr) string {
	addr := (*[16]byte)(unsafe.Pointer(uintptr(base) + offset))
	// Check for ::1 (loopback)
	isLoopback := true
	for i := 0; i < 15; i++ {
		if addr[i] != 0 {
			isLoopback = false
			break
		}
	}
	if isLoopback && addr[15] == 1 {
		return "::1"
	}
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		uint16(addr[0])<<8|uint16(addr[1]),
		uint16(addr[2])<<8|uint16(addr[3]),
		uint16(addr[4])<<8|uint16(addr[5]),
		uint16(addr[6])<<8|uint16(addr[7]),
		uint16(addr[8])<<8|uint16(addr[9]),
		uint16(addr[10])<<8|uint16(addr[11]),
		uint16(addr[12])<<8|uint16(addr[13]),
		uint16(addr[14])<<8|uint16(addr[15]),
	)
}

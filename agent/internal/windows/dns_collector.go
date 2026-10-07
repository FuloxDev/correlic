//go:build windows

package windows

import (
	"unsafe"
)

// DNSEvent is emitted when a DNS query is made.
type DNSEvent struct {
	PID        uint32
	QueryName  string
	QueryType  uint16
	StatusCode uint32
}

// DNSCollector subscribes to Microsoft-Windows-DNS-Client ETW events.
type DNSCollector struct {
	events chan DNSEvent
}

// NewDNSCollector returns a collector for DNS query events.
func NewDNSCollector() *DNSCollector {
	return &DNSCollector{
		events: make(chan DNSEvent, 4096),
	}
}

// Events returns the receive-only channel of DNS events.
func (c *DNSCollector) Events() <-chan DNSEvent {
	return c.events
}

// Handle is called for every ETW event; it filters for DNS-Client.
func (c *DNSCollector) Handle(rec *EventRecord) {
	if !GUIDEquals(rec.ProviderID, GUIDDNSClient()) {
		return
	}

	// DNS Client event IDs: 3008 = Query request, 3009 = Query completed.
	if rec.EventID != 3008 && rec.EventID != 3009 {
		return
	}

	if rec.UserDataLen < 4 || rec.UserData == 0 {
		return
	}

	// QueryName is the first UTF-16 null-terminated string in UserData.
	namePtr := (*uint16)(unsafe.Pointer(rec.UserData))
	queryName := readWCHAR(namePtr, int(rec.UserDataLen))

	ev := DNSEvent{
		PID:       rec.ProcessID,
		QueryName: queryName,
	}

	select {
	case c.events <- ev:
	default:
	}
}

// Close drains and closes the events channel.
func (c *DNSCollector) Close() {
	close(c.events)
}

//go:build windows

package windows

import (
	"encoding/xml"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wevtapi.dll function pointers
var (
	wevtapi                  = syscall.NewLazyDLL("wevtapi.dll")
	procEvtSubscribe         = wevtapi.NewProc("EvtSubscribe")
	procEvtRender            = wevtapi.NewProc("EvtRender")
	procEvtClose             = wevtapi.NewProc("EvtClose")
	procEvtCreateRenderCtx   = wevtapi.NewProc("EvtCreateRenderContext")
)

// EvtSubscribe flags
const (
	evtSubscribeToFutureEvents = 1
	evtRenderEventXml          = 1
)

// AuditEvent represents a parsed Windows Security event.
type AuditEvent struct {
	EventID    uint16
	PID        uint32
	PPID       uint32
	Cmdline    string
	User       string
	ExePath    string
	Timestamp  time.Time
	// Registry (4657)
	RegKey     string
	RegValue   string
	RegOldVal  string
	RegNewVal  string
	// Access (4656)
	AccessMask uint32
	ObjectPath string
	ObjectType string
	// Privilege (4672)
	Privileges []string
	// Scheduled task (4698)
	TaskName   string
	TaskXML    string
}

// AuditSubscriber subscribes to the Windows Security event log and emits
// parsed AuditEvent structs for consumption by the audit runner and cmdline cache.
type AuditSubscriber struct {
	logger       *slog.Logger
	events       chan AuditEvent
	cmdlineCache *CmdlineCache
	eventFilter  map[uint16]bool
	subscription uintptr
	signalEvent  windows.Handle // manual-reset event for EvtSubscribe pull mode
	stopOnce     sync.Once
	stopped      chan struct{}
}

// NewAuditSubscriber creates a subscriber for the given event IDs.
// eventIDs: which Security event IDs to capture (e.g., 4688, 4689, 4656, 4657, 4672, 4698)
func NewAuditSubscriber(logger *slog.Logger, cmdlineCache *CmdlineCache, eventIDs []uint16) *AuditSubscriber {
	filter := make(map[uint16]bool, len(eventIDs))
	for _, id := range eventIDs {
		filter[id] = true
	}
	return &AuditSubscriber{
		logger:       logger,
		events:       make(chan AuditEvent, 4096),
		cmdlineCache: cmdlineCache,
		eventFilter:  filter,
		stopped:      make(chan struct{}),
	}
}

// Events returns the channel of parsed audit events.
func (s *AuditSubscriber) Events() <-chan AuditEvent {
	return s.events
}

// Start begins subscribing to the Security event log.
// This function blocks until Stop() is called or an error occurs.
func (s *AuditSubscriber) Start() error {
	// Build XML query to filter for specific event IDs
	query := s.buildQuery()

	queryUTF16, err := syscall.UTF16PtrFromString(query)
	if err != nil {
		return fmt.Errorf("failed to encode query: %w", err)
	}
	channelUTF16, err := syscall.UTF16PtrFromString("Security")
	if err != nil {
		return fmt.Errorf("failed to encode channel: %w", err)
	}

	// Create a MANUAL-RESET event, INITIALLY SIGNALED for EvtSubscribe pull mode.
	// Manual-reset: stays signaled until we explicitly ResetEvent after draining.
	// Initially signaled: immediately check for existing events on first iteration.
	// See: https://learn.microsoft.com/en-us/windows/win32/wes/subscribing-to-events
	signalEvent, err := windows.CreateEvent(nil, 1, 1, nil) // bManualReset=TRUE, bInitialState=TRUE
	if err != nil {
		return fmt.Errorf("failed to create signal event: %w", err)
	}
	s.signalEvent = signalEvent
	defer windows.CloseHandle(signalEvent)

	// Subscribe to future events using signal mode (not callback mode)
	// EvtSubscribe(Session, SignalEvent, ChannelPath, Query, Bookmark, Context, Callback, Flags)
	r, _, callErr := procEvtSubscribe.Call(
		0,                                     // Session (NULL = local)
		uintptr(signalEvent), // SignalEvent
		uintptr(unsafe.Pointer(channelUTF16)), // ChannelPath
		uintptr(unsafe.Pointer(queryUTF16)),   // Query
		0,                                     // Bookmark (NULL)
		0,                                     // Context
		0,                                     // Callback (NULL — using signal mode)
		evtSubscribeToFutureEvents,            // Flags
	)
	if r == 0 {
		return fmt.Errorf("EvtSubscribe failed: %v", callErr)
	}
	s.subscription = r

	s.logger.Info("Security Event Log subscriber started",
		"events", fmt.Sprintf("%v", s.filterIDs()),
		"channel", "Security",
	)

	// Event processing loop (pull model per Microsoft docs)
	for {
		select {
		case <-s.stopped:
			return nil
		default:
		}

		// Wait for events (1 second timeout to check stop signal)
		ret, _ := windows.WaitForSingleObject(signalEvent, 1000)
		if ret == windows.WAIT_OBJECT_0 {
			s.processEvents()
			// Reset the manual-reset event after draining all available events.
			// WaitForSingleObject will block until the service signals again.
			windows.ResetEvent(signalEvent)
		}
	}
}

// Stop terminates the subscription.
func (s *AuditSubscriber) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopped)
		if s.subscription != 0 {
			procEvtClose.Call(s.subscription)
			s.subscription = 0
		}
	})
}

// buildQuery creates an XML query for the specific event IDs.
func (s *AuditSubscriber) buildQuery() string {
	ids := s.filterIDs()
	if len(ids) == 0 {
		return "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*</Select></Query></QueryList>"
	}

	var parts []string
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("EventID=%d", id))
	}
	selector := strings.Join(parts, " or ")
	return fmt.Sprintf(
		"<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[(%s)]]</Select></Query></QueryList>",
		selector,
	)
}

func (s *AuditSubscriber) filterIDs() []uint16 {
	ids := make([]uint16, 0, len(s.eventFilter))
	for id := range s.eventFilter {
		ids = append(ids, id)
	}
	return ids
}

// processEvents reads all available events from the subscription.
func (s *AuditSubscriber) processEvents() {
	var evtNextProc = wevtapi.NewProc("EvtNext")

	// Use small array (max 10) — larger arrays produce corrupt handles on some Windows versions
	const arraySize = 10
	handles := make([]uintptr, arraySize)
	var returned uint32
	totalProcessed := 0

	for {
		// Timeout=0: non-blocking drain of available events (we know signal fired)
		r, _, _ := evtNextProc.Call(
			s.subscription,
			uintptr(arraySize),
			uintptr(unsafe.Pointer(&handles[0])),
			0, // timeout=0: return immediately if no more events
			0, // flags
			uintptr(unsafe.Pointer(&returned)),
		)
		if r == 0 || returned == 0 {
			break // ERROR_NO_MORE_ITEMS — all events drained
		}

		for i := uint32(0); i < returned; i++ {
			evt := s.renderEvent(handles[i])
			if evt != nil && s.eventFilter[evt.EventID] {
				totalProcessed++

				// For Event 4688, immediately cache the redacted cmdline
				if evt.EventID == 4688 && s.cmdlineCache != nil && evt.Cmdline != "" {
					s.cmdlineCache.Put(evt.PID, redactCmdlineStr(evt.Cmdline), evt.User)
				}

				// Send to channel (non-blocking)
				select {
				case s.events <- *evt:
				default:
					// Channel full — drop event
				}
			}
			procEvtClose.Call(handles[i])
		}
	}

	if totalProcessed > 0 {
		s.logger.Info("audit events processed", "count", totalProcessed)
	}
}

// renderEvent renders an event handle to XML and parses it.
func (s *AuditSubscriber) renderEvent(handle uintptr) *AuditEvent {
	// First call to get buffer size
	var bufferSize uint32
	var propertyCount uint32
	procEvtRender.Call(
		0,                // Context
		handle,           // Event
		evtRenderEventXml, // Flags
		0,                // BufferSize
		0,                // Buffer
		uintptr(unsafe.Pointer(&bufferSize)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if bufferSize == 0 {
		return nil
	}

	buf := make([]uint16, bufferSize/2+1)
	r, _, _ := procEvtRender.Call(
		0,
		handle,
		evtRenderEventXml,
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufferSize)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if r == 0 {
		return nil
	}

	xmlStr := syscall.UTF16ToString(buf)
	return s.parseEventXML(xmlStr)
}

// XML structures for parsing Windows Security events
type eventXML struct {
	XMLName xml.Name    `xml:"Event"`
	System  systemXML   `xml:"System"`
	Data    []dataField `xml:"EventData>Data"`
}

type systemXML struct {
	EventID     uint16 `xml:"EventID"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
}

type dataField struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// parseEventXML parses rendered XML into an AuditEvent.
func (s *AuditSubscriber) parseEventXML(xmlStr string) *AuditEvent {
	var evt eventXML
	if err := xml.Unmarshal([]byte(xmlStr), &evt); err != nil {
		return nil
	}

	audit := &AuditEvent{
		EventID: evt.System.EventID,
	}

	// Parse timestamp
	if ts, err := time.Parse(time.RFC3339Nano, evt.System.TimeCreated.SystemTime); err == nil {
		audit.Timestamp = ts
	} else {
		audit.Timestamp = time.Now()
	}

	// Build data map for easy access
	data := make(map[string]string, len(evt.Data))
	for _, d := range evt.Data {
		data[d.Name] = d.Value
	}

	switch evt.System.EventID {
	case 4688: // Process Creation
		audit.PID = parseUint32(data["NewProcessId"])
		audit.PPID = parseUint32(data["ProcessId"]) // Parent PID
		audit.Cmdline = data["CommandLine"]
		audit.ExePath = data["NewProcessName"]
		audit.User = data["SubjectUserName"]

	case 4689: // Process Termination
		audit.PID = parseUint32(data["ProcessId"])
		audit.ExePath = data["ProcessName"]

	case 4656: // Handle Request (read vs write)
		audit.PID = parseUint32(data["ProcessId"])
		audit.ObjectPath = data["ObjectName"]
		audit.ObjectType = data["ObjectType"]
		audit.AccessMask = parseHex32(data["AccessMask"])
		audit.ExePath = data["ProcessName"]

	case 4657: // Registry Value Modified
		audit.PID = parseUint32(data["ProcessId"])
		audit.RegKey = data["ObjectName"]
		audit.RegValue = data["ObjectValueName"]
		audit.RegOldVal = data["OldValue"]
		audit.RegNewVal = data["NewValue"]
		audit.ExePath = data["ProcessName"]

	case 4672: // Special Privileges Assigned
		audit.PID = parseUint32(data["ProcessId"])
		audit.User = data["SubjectUserName"]
		privStr := data["PrivilegeList"]
		if privStr != "" {
			for _, p := range strings.Split(privStr, "\n") {
				p = strings.TrimSpace(p)
				if p != "" {
					audit.Privileges = append(audit.Privileges, p)
				}
			}
		}

	case 4698: // Scheduled Task Created
		audit.TaskName = data["TaskName"]
		audit.TaskXML = data["TaskContent"]
		audit.User = data["SubjectUserName"]
	}

	return audit
}

func parseUint32(s string) uint32 {
	// Handle hex format (0x1234) common in Windows events
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, _ := strconv.ParseUint(s[2:], 16, 32)
		return uint32(val)
	}
	val, _ := strconv.ParseUint(s, 10, 32)
	return uint32(val)
}

func parseHex32(s string) uint32 {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.TrimPrefix(s, "%%")
	val, _ := strconv.ParseUint(s, 16, 32)
	return uint32(val)
}

//go:build windows

// Package windows provides ETW-based telemetry collectors for the Correlic agent on Windows.
// It is the Windows equivalent of the internal/ebpf package on Linux and internal/darwin on macOS.
//
// Architecture: one shared ETW trace session with four providers:
//   - Microsoft-Windows-Kernel-Process  → process exec/exit
//   - Microsoft-Windows-Kernel-File     → file open
//   - Microsoft-Windows-Kernel-Network  → TCP connect/accept
//   - Microsoft-Windows-DNS-Client      → DNS queries
//
// All paths are normalised from backslashes to forward slashes before dispatch.
package windows

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── ETW GUIDs ────────────────────────────────────────────────────────────────

var (
	// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
	guidKernelProcess = windows.GUID{
		Data1: 0x22fb2cd6, Data2: 0x0e7b, Data3: 0x422b,
		Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16},
	}
	// {EDD08927-9CC4-4E65-B970-C2560FB5C289}
	guidKernelFile = windows.GUID{
		Data1: 0xedd08927, Data2: 0x9cc4, Data3: 0x4e65,
		Data4: [8]byte{0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89},
	}
	// {7DD42A49-5329-4832-8DFD-43D979153A88}
	guidKernelNetwork = windows.GUID{
		Data1: 0x7dd42a49, Data2: 0x5329, Data3: 0x4832,
		Data4: [8]byte{0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88},
	}
	// {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
	guidDNSClient = windows.GUID{
		Data1: 0x1c95126e, Data2: 0x7eea, Data3: 0x49a9,
		Data4: [8]byte{0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d},
	}
)

// ─── ETW constants ────────────────────────────────────────────────────────────

const (
	eventTraceRealTimeMode       = 0x00000100
	wNodeFlagTracedGUID          = 0x00020000
	processTraceModeRealTime     = 0x00000100
	processTraceModeEventRecord  = 0x10000000
	eventControlCodeEnableProvider = 1

	etwLevelInformational = 4
	etwSessionName        = "CorrelicAgent"
)

// ─── Windows API lazy-load ────────────────────────────────────────────────────

var (
	modAdvapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW   = modAdvapi32.NewProc("StartTraceW")
	procControlTraceW = modAdvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = modAdvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW    = modAdvapi32.NewProc("OpenTraceW")
	procProcessTrace  = modAdvapi32.NewProc("ProcessTrace")
	procCloseTrace    = modAdvapi32.NewProc("CloseTrace")
)

// ─── Structures (64-bit layout) ───────────────────────────────────────────────

// wnodeHeader mirrors the Windows WNODE_HEADER (48 bytes on 64-bit).
type wnodeHeader struct {
	BufferSize    uint32
	ProviderId    uint32
	Version       uint32   // low dword of HistoricalContext union
	Linkage       uint32   // high dword of HistoricalContext union
	_             [8]byte  // KernelHandle/CountLost/TimeStamp union (pointer-sized)
	Guid          windows.GUID
	ClientContext uint32
	Flags         uint32
}

// etwTraceProperties mirrors EVENT_TRACE_PROPERTIES (120 bytes fixed on 64-bit).
type etwTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadId      uintptr // HANDLE — 8 bytes on 64-bit
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// etwTracePropsBuffer is the full allocation: fixed header + name buffer.
type etwTracePropsBuffer struct {
	props etwTraceProperties
	names [2048]byte // space for session name + log file name (UTF-16)
}

// etwTraceLogfile mirrors the offsets we care about in EVENT_TRACE_LOGFILE (64-bit).
// We access it as a byte buffer to avoid struct-padding guesswork for the
// middle fields (CurrentEvent + LogfileHeader) that we don't read.
//
// Offsets verified against Windows SDK evntrace.h (x64):
//   0   LogFileName       *uint16  (LPWSTR)
//   8   LoggerName        *uint16  (LPWSTR)
//  16   CurrentTime       int64
//  24   BuffersRead       uint32
//  28   ProcessTraceMode  uint32   (union with LogFileMode)
//  32   CurrentEvent      [88]byte (EVENT_TRACE)
// 120   LogfileHeader     [280]byte
// 400   BufferCallback    uintptr
// 408   BufferSize        uint32
// 412   Filled            uint32
// 416   EventsLost        uint32
// 420   _pad              [4]byte
// 424   EventRecordCallback uintptr  (union with EventCallback)
// 432   IsKernelTrace     uint32
// 436   _pad              [4]byte
// 440   Context           uintptr
const etwLogfileSize = 448

type etwTraceLogfileBuffer [etwLogfileSize]byte

func (b *etwTraceLogfileBuffer) setLoggerName(p *uint16) {
	*(*uintptr)(unsafe.Pointer(&b[8])) = uintptr(unsafe.Pointer(p))
}
func (b *etwTraceLogfileBuffer) setProcessTraceMode(v uint32) {
	*(*uint32)(unsafe.Pointer(&b[28])) = v
}
func (b *etwTraceLogfileBuffer) setEventRecordCallback(fn uintptr) {
	*(*uintptr)(unsafe.Pointer(&b[424])) = fn
}
func (b *etwTraceLogfileBuffer) setContext(v uintptr) {
	*(*uintptr)(unsafe.Pointer(&b[440])) = v
}

// EventRecord mirrors EVENT_RECORD (112 bytes on 64-bit).
// Fields are laid out to match the Windows SDK exactly.
type EventRecord struct {
	// EVENT_HEADER (80 bytes)
	Size          uint16
	HeaderType    uint16
	Flags         uint16
	EventProperty uint16
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	ProviderID    windows.GUID // 16 bytes
	// EVENT_DESCRIPTOR (starts at offset 40)
	EventID       uint16
	Version       uint8
	Channel       uint8
	Level         uint8
	Opcode        uint8
	Task          uint16
	Keyword       uint64 // 8-aligned → offset 48
	// Processor time union (offset 56)
	KernelTime    uint32
	UserTime      uint32
	// ActivityId (offset 64)
	ActivityID    windows.GUID // 16 bytes → ends at 80
	// ETW_BUFFER_CONTEXT (offset 80)
	ProcNumber    uint8
	Alignment     uint8
	LoggerID      uint16
	// counts (offset 84)
	ExtDataCount  uint16
	UserDataLen   uint16
	// pointers (offset 88, 8-aligned)
	ExtData       uintptr
	UserData      uintptr
	UserCtx       uintptr
}

// ─── Global callback dispatch ─────────────────────────────────────────────────

var (
	globalCBPtr  uintptr
	globalCBOnce sync.Once

	cbMu    sync.Mutex
	cbMap   = make(map[uintptr]func(*EventRecord))
	cbNextID uintptr = 1
)

func initGlobalCallback() {
	globalCBOnce.Do(func() {
		// NewCallback creates a C-callable function pointer.
		// The signature must be stdcall: func(record *EventRecord) uintptr.
		globalCBPtr = syscall.NewCallback(func(record *EventRecord) uintptr {
			if record == nil {
				return 0
			}
			id := record.UserCtx
			cbMu.Lock()
			fn := cbMap[id]
			cbMu.Unlock()
			if fn != nil {
				fn(record)
			}
			return 0
		})
	})
}

func registerDispatch(fn func(*EventRecord)) uintptr {
	cbMu.Lock()
	defer cbMu.Unlock()
	id := atomic.AddUintptr(&cbNextID, 1)
	cbMap[id] = fn
	return id
}

func unregisterDispatch(id uintptr) {
	cbMu.Lock()
	delete(cbMap, id)
	cbMu.Unlock()
}

// ─── Session ──────────────────────────────────────────────────────────────────

// ProviderID identifies a known ETW provider.
type ProviderID int

const (
	ProviderProcess ProviderID = iota
	ProviderFile
	ProviderNetwork
	ProviderDNS
)

// Session wraps an ETW real-time trace session with multiple kernel providers.
type Session struct {
	logger     *slog.Logger
	handle     uint64 // SESSION_HANDLE (TRACEHANDLE, uint64 even on 32-bit)
	traceHandle uint64
	dispatchID uintptr
	dispatch   func(*EventRecord)
}

// NewSession creates an ETW session that calls dispatch for every received event.
// The caller is responsible for filtering by ProviderID / EventID.
func NewSession(logger *slog.Logger, dispatch func(*EventRecord)) *Session {
	if logger == nil {
		logger = slog.Default()
	}
	initGlobalCallback()
	return &Session{
		logger:   logger,
		dispatch: dispatch,
	}
}

// Start opens the ETW session, enables all providers, and begins processing events.
// It blocks until ctx is cancelled.
func (s *Session) Start(ctx context.Context) error {
	// Stop any lingering session with the same name.
	s.stopExisting()

	buf := &etwTracePropsBuffer{}
	totalSize := uint32(unsafe.Sizeof(*buf))

	buf.props.Wnode.BufferSize = totalSize
	buf.props.Wnode.Flags = wNodeFlagTracedGUID
	buf.props.LogFileMode = eventTraceRealTimeMode
	buf.props.MinimumBuffers = 4
	buf.props.MaximumBuffers = 32
	buf.props.BufferSize = 64 // 64 KB per buffer
	buf.props.LoggerNameOffset = uint32(unsafe.Sizeof(buf.props))

	// Write session name at LoggerNameOffset.
	sessionNameW, _ := windows.UTF16FromString(etwSessionName)
	nameBytes := (*[1024]byte)(unsafe.Pointer(&buf.names[0]))
	for i, c := range sessionNameW {
		if i*2+1 >= len(buf.names) {
			break
		}
		nameBytes[i*2] = byte(c)
		nameBytes[i*2+1] = byte(c >> 8)
	}

	var sessionHandle uint64
	ret, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&sessionHandle)),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(etwSessionName))),
		uintptr(unsafe.Pointer(buf)),
	)
	if ret != 0 {
		return fmt.Errorf("StartTraceW failed: 0x%08x", ret)
	}
	s.handle = sessionHandle
	s.logger.Info("ETW session started", "session", etwSessionName, "handle", sessionHandle)

	// Enable providers with two layers of kernel-level filtering:
	//
	// 1. Keyword filtering: restricts which EVENT CATEGORIES are delivered
	//    (e.g., process events only, not threads/images for Kernel-Process)
	//
	// 2. EventID filtering: restricts which SPECIFIC EVENT IDs are delivered
	//    (e.g., only EventID 1,2 for Kernel-Process — exactly what collectors process)
	//
	// Together these eliminate >99% of kernel events before they reach userspace.
	// This is the Windows equivalent of eBPF's targeted tracepoint attachment.

	// ENABLE_TRACE_PARAMETERS structure (Windows 8.1+)
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
	type enableTraceParams struct {
		Version          uint32
		EnableProperty   uint32
		ControlFlags     uint32
		SourceId         windows.GUID
		EnableFilterDesc uintptr // pointer to EVENT_FILTER_DESCRIPTOR array
		FilterDescCount  uint32
		_                uint32 // padding
	}

	// EVENT_FILTER_DESCRIPTOR for EventID filtering
	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
	type eventFilterDescriptor struct {
		Ptr  uint64 // pointer to filter data
		Size uint32
		Type uint32
	}

	// EVENT_FILTER_EVENT_ID structure: boolean + count + array of uint16 event IDs
	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_event_id
	type eventFilterEventID struct {
		FilterIn uint8 // 1 = include listed IDs, 0 = exclude listed IDs
		Reserved uint8
		Count    uint16
		// Followed by Count × uint16 EventIDs (variable length)
	}

	const eventFilterTypeEventID = 0x80000200 // EVENT_FILTER_TYPE_EVENT_ID

	type providerCfg struct {
		guid     windows.GUID
		keyword  uint64
		eventIDs []uint16
	}
	providers := []providerCfg{
		{guidKernelProcess, 0x10, []uint16{1, 2}},             // ProcessStart, ProcessStop
		{guidKernelFile, 0x10B0, []uint16{10, 11, 12, 30}},    // NameCreate, NameDelete, Create, CreateNewFile
		{guidKernelNetwork, 0x30, []uint16{12, 15, 26, 29}},   // TcpConnect/Accept IPv4/IPv6
		{guidDNSClient, 0x8000000000000000, []uint16{3008, 3009}}, // QueryRequest, QueryCompleted
	}

	for _, p := range providers {
		// Build EVENT_FILTER_EVENT_ID: header (4 bytes) + eventIDs (2 bytes each)
		filterBuf := make([]byte, 4+len(p.eventIDs)*2)
		filterBuf[0] = 1 // FilterIn = TRUE (include these IDs)
		filterBuf[1] = 0 // Reserved
		filterBuf[2] = byte(len(p.eventIDs))
		filterBuf[3] = byte(len(p.eventIDs) >> 8)
		for i, id := range p.eventIDs {
			filterBuf[4+i*2] = byte(id)
			filterBuf[4+i*2+1] = byte(id >> 8)
		}

		filterDesc := eventFilterDescriptor{
			Ptr:  uint64(uintptr(unsafe.Pointer(&filterBuf[0]))),
			Size: uint32(len(filterBuf)),
			Type: eventFilterTypeEventID,
		}

		params := enableTraceParams{
			Version:          2, // ENABLE_TRACE_PARAMETERS_VERSION_2
			EnableFilterDesc: uintptr(unsafe.Pointer(&filterDesc)),
			FilterDescCount:  1,
		}

		ret, _, _ = procEnableTraceEx2.Call(
			uintptr(sessionHandle),
			uintptr(unsafe.Pointer(&p.guid)),
			eventControlCodeEnableProvider,
			etwLevelInformational,
			uintptr(p.keyword),
			0, // matchAllKeyword
			0, // timeout
			uintptr(unsafe.Pointer(&params)),
		)
		if ret != 0 {
			// If EventID filtering fails (older Windows), fall back to keyword-only
			s.logger.Warn("EnableTraceEx2 with EventID filter failed, retrying keyword-only",
				"guid", fmt.Sprintf("%v", p.guid), "error", fmt.Sprintf("0x%08x", ret))
			ret, _, _ = procEnableTraceEx2.Call(
				uintptr(sessionHandle),
				uintptr(unsafe.Pointer(&p.guid)),
				eventControlCodeEnableProvider,
				etwLevelInformational,
				uintptr(p.keyword),
				0, 0, 0,
			)
			if ret != 0 {
				s.logger.Warn("EnableTraceEx2 keyword-only also failed",
					"guid", fmt.Sprintf("%v", p.guid), "error", fmt.Sprintf("0x%08x", ret))
			}
		}
	}

	// Open trace for real-time consumption.
	s.dispatchID = registerDispatch(s.dispatch)

	var logfile etwTraceLogfileBuffer
	logfile.setLoggerName(windows.StringToUTF16Ptr(etwSessionName))
	logfile.setProcessTraceMode(processTraceModeRealTime | processTraceModeEventRecord)
	logfile.setEventRecordCallback(globalCBPtr)
	logfile.setContext(s.dispatchID)

	traceHandle, _, _ := procOpenTraceW.Call(uintptr(unsafe.Pointer(&logfile)))
	// INVALID_PROCESSTRACE_HANDLE is 0xFFFFFFFFFFFFFFFF on 64-bit
	if traceHandle == 0xFFFFFFFFFFFFFFFF {
		unregisterDispatch(s.dispatchID)
		s.stopSession()
		return fmt.Errorf("OpenTraceW failed")
	}
	s.traceHandle = uint64(traceHandle)

	// ProcessTrace blocks until CloseTrace is called.
	processDone := make(chan error, 1)
	go func() {
		ret, _, _ := procProcessTrace.Call(
			uintptr(unsafe.Pointer(&s.traceHandle)),
			1,
			0,
			0,
		)
		if ret != 0 {
			processDone <- fmt.Errorf("ProcessTrace exited: 0x%08x", ret)
		} else {
			processDone <- nil
		}
	}()

	// Periodic ETW loss stats — logs every 30s so we can detect event drops.
	statsTicker := time.NewTicker(30 * time.Second)
	defer statsTicker.Stop()

	// Wait for context cancellation.
	for {
		select {
		case <-ctx.Done():
			s.logStats()
			s.Close()
			return nil
		case err := <-processDone:
			if err != nil {
				s.logger.Error("ProcessTrace error", "error", err)
			}
			s.logStats()
			s.Close()
			return nil
		case <-statsTicker.C:
			s.logStats()
		}
	}
}

// Close stops the ETW session and releases resources.
func (s *Session) Close() {
	if s.traceHandle != 0 {
		procCloseTrace.Call(uintptr(s.traceHandle))
		s.traceHandle = 0
	}
	unregisterDispatch(s.dispatchID)
	s.stopSession()
}

// logStats queries the ETW session for event/buffer loss counters and logs them.
func (s *Session) logStats() {
	if s.handle == 0 {
		return
	}
	buf := &etwTracePropsBuffer{}
	buf.props.Wnode.BufferSize = uint32(unsafe.Sizeof(*buf))
	buf.props.Wnode.Flags = wNodeFlagTracedGUID
	buf.props.LoggerNameOffset = uint32(unsafe.Sizeof(buf.props))

	const eventTraceControlQuery = 0
	ret, _, _ := procControlTraceW.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(etwSessionName))),
		uintptr(unsafe.Pointer(buf)),
		eventTraceControlQuery,
	)
	if ret != 0 {
		return // query failed, skip
	}
	p := &buf.props
	s.logger.Info("ETW session stats",
		"events_lost", p.EventsLost,
		"buffers_written", p.BuffersWritten,
		"log_buffers_lost", p.LogBuffersLost,
		"realtime_buffers_lost", p.RealTimeBuffersLost,
		"free_buffers", p.FreeBuffers,
		"number_of_buffers", p.NumberOfBuffers,
	)
}

func (s *Session) stopSession() {
	if s.handle == 0 {
		return
	}
	buf := &etwTracePropsBuffer{}
	buf.props.Wnode.BufferSize = uint32(unsafe.Sizeof(*buf))
	buf.props.Wnode.Flags = wNodeFlagTracedGUID
	buf.props.LoggerNameOffset = uint32(unsafe.Sizeof(buf.props))

	const eventTraceControlStop = 1
	procControlTraceW.Call(
		uintptr(s.handle),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(etwSessionName))),
		uintptr(unsafe.Pointer(buf)),
		eventTraceControlStop,
	)
	s.handle = 0
}

func (s *Session) stopExisting() {
	buf := &etwTracePropsBuffer{}
	buf.props.Wnode.BufferSize = uint32(unsafe.Sizeof(*buf))
	buf.props.Wnode.Flags = wNodeFlagTracedGUID
	buf.props.LoggerNameOffset = uint32(unsafe.Sizeof(buf.props))

	const eventTraceControlStop = 1
	procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(etwSessionName))),
		uintptr(unsafe.Pointer(buf)),
		eventTraceControlStop,
	)
}

// GUIDEquals compares two GUIDs for equality.
func GUIDEquals(a, b windows.GUID) bool {
	return a.Data1 == b.Data1 && a.Data2 == b.Data2 && a.Data3 == b.Data3 && a.Data4 == b.Data4
}

// GUIDKernelProcess is the GUID for Microsoft-Windows-Kernel-Process.
func GUIDKernelProcess() windows.GUID { return guidKernelProcess }

// GUIDKernelFile is the GUID for Microsoft-Windows-Kernel-File.
func GUIDKernelFile() windows.GUID { return guidKernelFile }

// GUIDKernelNetwork is the GUID for Microsoft-Windows-Kernel-Network.
func GUIDKernelNetwork() windows.GUID { return guidKernelNetwork }

// GUIDDNSClient is the GUID for Microsoft-Windows-DNS-Client.
func GUIDDNSClient() windows.GUID { return guidDNSClient }

//go:build windows

package windows

import (
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procCallbackCount atomic.Int64
var procStartCount atomic.Int64
var procStopCount atomic.Int64
var procDropCount atomic.Int64

// ProcEventType distinguishes process start vs stop.
type ProcEventType int

const (
	ProcStart ProcEventType = iota
	ProcStop
)

// ProcEvent is emitted when a process starts or exits.
type ProcEvent struct {
	Type      ProcEventType
	PID       uint32
	Cmdline   []string // captured in callback for short-lived processes
	PPID      uint32 // populated via snapshot for start events
	ImagePath string  // normalised forward-slash path
	ExitCode  uint32  // only valid for ProcStop
}

// ProcCollector subscribes to Microsoft-Windows-Kernel-Process ETW events.
type ProcCollector struct {
	events chan ProcEvent
}

// NewProcCollector returns a collector that emits ProcEvents on its channel.
func NewProcCollector() *ProcCollector {
	return &ProcCollector{
		events: make(chan ProcEvent, 4096),
	}
}

// Events returns the receive-only channel of process events.
func (c *ProcCollector) Events() <-chan ProcEvent {
	return c.events
}

// Handle is called by the ETW session for every event; it filters for Kernel-Process.
func (c *ProcCollector) Handle(rec *EventRecord) {
	// Recover from panics in unsafe pointer arithmetic — a crash here
	// kills the entire ETW callback and takes down all 4 providers.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("proc_collector panic recovered", "error", r)
		}
	}()
	if !GUIDEquals(rec.ProviderID, GUIDKernelProcess()) {
		return
	}

	// Only handle ProcessStart (1) and ProcessStop (2).
	// Skip all other event IDs (3=ThreadStart, 5=ImageLoad, 21=ThreadWorkOnBehalf, etc.)
	// which fire thousands of times per second and waste CPU in the shared ETW callback.
	if rec.EventID != 1 && rec.EventID != 2 {
		return
	}

	n := procCallbackCount.Add(1)
	if n <= 10 || n%200 == 0 {
		slog.Info("proc_collector callback", "event_id", rec.EventID, "total", n,
			"starts", procStartCount.Load(), "stops", procStopCount.Load(),
			"drops", procDropCount.Load(), "chan_len", len(c.events))
	}

	switch rec.EventID {
	case 1: // ProcessStart
		ev := ProcEvent{
			Type: ProcStart,
			PID:  rec.ProcessID,
		}

		// UserData layout for Microsoft-Windows-Kernel-Process Event 1 (ProcessStart)
		// Version 4 (Windows 11 24H2, Build 26200):
		//   Offset 0:  ProcessID               (u32)
		//   Offset 4:  ProcessSequenceNumber    (u64, 8 bytes)
		//   Offset 12: CreateTime               (FILETIME, u64, 8 bytes)
		//   Offset 20: ParentProcessID          (u32)
		//   Offset 24: ParentProcessSequenceNum (u64, 8 bytes)
		//   Offset 32: SessionID                (u32)
		//   Offset 36: Flags                    (u32)
		//   Offset 40+: variable-length null-terminated UTF-16 strings:
		//               ImageName, then CommandLine
		//
		// Verified via hex dump on Windows 11 Build 26200.
		if rec.UserDataLen >= 24 && rec.UserData != 0 {
			ud := unsafe.Pointer(rec.UserData)
			dataLen := int(rec.UserDataLen)

			ev.PID = *(*uint32)(ud)
			ev.PPID = *(*uint32)(unsafe.Pointer(uintptr(ud) + 20))

			// Scan for ImageName in UserData, then extract CommandLine after it.
			if dataLen > 44 {
				scanEnd := dataLen - 4
				imageOff := -1
				for off := 40; off < scanEnd; off += 2 {
					w := *(*uint16)(unsafe.Pointer(uintptr(ud) + uintptr(off)))
					if w == 0x005C { // '\'
						next := *(*uint16)(unsafe.Pointer(uintptr(ud) + uintptr(off+2)))
						if next == 0x0044 || next == 0x003F { // 'D' or '?'
							namePtr := (*uint16)(unsafe.Pointer(uintptr(ud) + uintptr(off)))
							ev.ImagePath = normalisePath(readWCHAR(namePtr, dataLen-off))
							imageOff = off
							break
						}
					}
					if w == 0x0043 { // 'C'
						next := *(*uint16)(unsafe.Pointer(uintptr(ud) + uintptr(off+2)))
						if next == 0x003A { // ':'
							namePtr := (*uint16)(unsafe.Pointer(uintptr(ud) + uintptr(off)))
							ev.ImagePath = normalisePath(readWCHAR(namePtr, dataLen-off))
							imageOff = off
							break
						}
					}
				}

				// CommandLine follows ImageName as the next null-terminated UTF-16 string.
				// This is the only reliable way to capture cmdline for short-lived processes
				// (which.exe, hostname.exe, etc. exit in <1ms — PEB read always loses the race).
				if imageOff >= 0 {
					// Skip past ImageName to its null terminator.
					cmdOff := imageOff
					for cmdOff < dataLen-1 {
						w := *(*uint16)(unsafe.Pointer(uintptr(ud) + uintptr(cmdOff)))
						if w == 0 {
							cmdOff += 2 // skip null terminator
							break
						}
						cmdOff += 2
					}
					// DWORD-align: ETW strings may be padded to 4-byte boundaries.
					// Without this, an odd-aligned offset reads padding bytes as
					// part of the first wchar, producing garbled UTF-16 (e.g. Korean).
					if cmdOff%4 != 0 {
						cmdOff += 4 - (cmdOff % 4)
					}
					// Read CommandLine if data remains after ImageName.
					if cmdOff+2 <= dataLen {
						cmdPtr := (*uint16)(unsafe.Pointer(uintptr(ud) + uintptr(cmdOff)))
						cmdRaw := readWCHAR(cmdPtr, dataLen-cmdOff)
						if cmdRaw != "" {
							ev.Cmdline = splitArgs(normalisePath(cmdRaw))
						}
					}
				}
			}
		}

		// Fallback: if CommandLine wasn't in ETW UserData, try PEB read.
		// This handles older Windows versions where UserData may not include CommandLine.
		if len(ev.Cmdline) == 0 {
			ev.Cmdline = readProcCmdlineInCallback(ev.PID)
		}

		procStartCount.Add(1)
		select {
		case c.events <- ev:
		default:
			procDropCount.Add(1)
		}

	case 2: // ProcessStop
		ev := ProcEvent{
			Type: ProcStop,
			PID:  rec.ProcessID,
		}
		// UserData: [ProcessID u32][ExitCode u32]...
		if rec.UserDataLen >= 8 && rec.UserData != 0 {
			ud := unsafe.Pointer(rec.UserData)
			ev.PID = *(*uint32)(ud)
			ev.ExitCode = *(*uint32)(unsafe.Pointer(uintptr(ud) + 4))
		}
		procStopCount.Add(1)
		select {
		case c.events <- ev:
		default:
			procDropCount.Add(1)
		}
	}
}

// Close drains and closes the events channel.
func (c *ProcCollector) Close() {
	close(c.events)
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// lookupPPID uses CreateToolhelp32Snapshot to find the parent PID.
func lookupPPID(pid uint32) uint32 {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return 0
	}
	for {
		if entry.ProcessID == pid {
			return entry.ParentProcessID
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return 0
}

// queryImagePath resolves the full exe path for a PID.
func queryImagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return normalisePath(windows.UTF16ToString(buf[:size]))
}

// readWCHAR reads a null-terminated UTF-16 string from a pointer with a byte limit.
func readWCHAR(p *uint16, maxBytes int) string {
	if p == nil || maxBytes <= 0 {
		return ""
	}
	maxWChars := maxBytes / 2
	buf := make([]uint16, 0, 64)
	for i := 0; i < maxWChars; i++ {
		c := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i*2)))
		if c == 0 {
			break
		}
		buf = append(buf, c)
	}
	return windows.UTF16ToString(buf)
}

// normalisePath converts backslash paths to forward slashes.
// "C:\Users\..." → "C:/Users/..."
func normalisePath(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}

// ─── NT device path → DOS path conversion ───────────────────────────────────

var (
	volumeMapOnce sync.Once
	volumeMap     map[string]string // "/Device/HarddiskVolume3" → "C:"
)

// buildVolumeMap queries all drive letters (A:-Z:) and maps their NT device
// names to drive letters using QueryDosDevice.
func buildVolumeMap() {
	volumeMapOnce.Do(func() {
		volumeMap = make(map[string]string)
		buf := make([]uint16, 260)
		for c := 'A'; c <= 'Z'; c++ {
			drive := string(c) + ":"
			driveW, _ := windows.UTF16PtrFromString(drive)
			n, err := queryDosDevice(driveW, &buf[0], uint32(len(buf)))
			if err != nil || n == 0 {
				continue
			}
			// QueryDosDevice returns null-terminated string(s).
			ntPath := windows.UTF16ToString(buf[:n])
			// Normalise to forward slashes for consistent matching.
			ntPath = strings.ReplaceAll(ntPath, `\`, "/")
			volumeMap[ntPath] = drive
		}
	})
}

// ntPathToDOS converts an NT device path like "/Device/HarddiskVolume3/Users/..."
// to a DOS path like "C:/Users/...". Returns the original path if no mapping found.
func ntPathToDOS(path string) string {
	if !strings.HasPrefix(path, "/Device/") {
		// Normalise drive letter to uppercase (ETW may give "c:\..." or "c:/...").
		if len(path) >= 2 && path[1] == ':' && path[0] >= 'a' && path[0] <= 'z' {
			path = string(path[0]-32) + path[1:]
		}
		// Handle bare drive-letter paths without colon (e.g. "c/Users/..." from ETW).
		// ETW sometimes strips the colon from device paths, producing "c/Users/..." instead
		// of "C:/Users/...". Without this fix, paths appear as separate "c/", "Users/" entries
		// in the baselines directory tree.
		if len(path) >= 2 && path[1] == '/' && ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) {
			path = strings.ToUpper(string(path[0])) + ":/" + path[2:]
		}
		return path
	}
	buildVolumeMap()
	for ntPrefix, drive := range volumeMap {
		if strings.HasPrefix(path, ntPrefix) {
			rest := path[len(ntPrefix):]
			return stripMSYSDriveMirror(drive + rest)
		}
	}
	return path
}

// stripMSYSDriveMirror fixes MSYS/Git-for-Windows path artifacts.
// Git Bash maps C:\ as /c/, so ETW sometimes reports paths like:
//   \Device\HarddiskVolume3\c\Users\alice\... → C:/c/Users/alice/...
// The "c" after the drive letter is a MSYS mount point, not a real directory.
// This strips it when the inner letter matches the drive: C:/c/... → C:/...
func stripMSYSDriveMirror(path string) string {
	// Need at least "X:/x/" (5 chars)
	if len(path) < 5 || path[1] != ':' || path[2] != '/' {
		return path
	}
	// Check: path[3] is a single letter, path[4] is '/', and it matches the drive letter
	if path[4] == '/' && strings.ToLower(string(path[0])) == strings.ToLower(string(path[3])) {
		return path[:3] + path[5:] // "C:/" + everything after "C:/c/"
	}
	return path
}

var (
	modKernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procQueryDosDevice = modKernel32.NewProc("QueryDosDeviceW")
)

func queryDosDevice(deviceName *uint16, targetPath *uint16, maxLen uint32) (uint32, error) {
	r, _, err := procQueryDosDevice.Call(
		uintptr(unsafe.Pointer(deviceName)),
		uintptr(unsafe.Pointer(targetPath)),
		uintptr(maxLen),
	)
	if r == 0 {
		return 0, err
	}
	return uint32(r), nil
}

// splitArgs splits a Windows command line into arguments, respecting quotes.
func splitArgs(cmdline string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	for _, c := range cmdline {
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

// readProcCmdlineInCallback reads the command line from a process's PEB.
// Used inside the ETW callback where speed is critical (~0.1ms).
// Returns nil if the process has already exited or access is denied.
func readProcCmdlineInCallback(pid uint32) []string {
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ,
		false, pid,
	)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)

	// Guard: skip PEB read if process has already exited.
	// ReadProcessMemory on a dead process can return stale/garbage pages,
	// which decode as garbled UTF-16 (e.g. Korean characters).
	var exitCode uint32
	if err := windows.GetExitCodeProcess(h, &exitCode); err == nil && exitCode != 259 { // 259 = STILL_ACTIVE
		return nil
	}

	// NtQueryInformationProcess(ProcessBasicInformation) → PEB address
	type pbi struct {
		ExitStatus                   uintptr
		PebBaseAddress               uintptr
		AffinityMask                 uintptr
		BasePriority                 int32
		_                            [4]byte
		UniqueProcessId              uintptr
		InheritedFromUniqueProcessId uintptr
	}
	var info pbi
	var retLen uint32
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQuery := ntdll.NewProc("NtQueryInformationProcess")
	r1, _, _ := ntQuery.Call(
		uintptr(h), 0,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r1 != 0 {
		return nil
	}

	// Read ProcessParameters pointer from PEB (offset 0x20 on 64-bit)
	var paramsPtr uintptr
	if err := windows.ReadProcessMemory(h, info.PebBaseAddress+0x20,
		(*byte)(unsafe.Pointer(&paramsPtr)), unsafe.Sizeof(paramsPtr), nil); err != nil {
		return nil
	}

	// Read CommandLine UNICODE_STRING from ProcessParameters (offset 0x70)
	type uniStr struct {
		Length    uint16
		MaxLen   uint16
		_        [4]byte
		Buffer   uintptr
	}
	var cmdUS uniStr
	if err := windows.ReadProcessMemory(h, paramsPtr+0x70,
		(*byte)(unsafe.Pointer(&cmdUS)), unsafe.Sizeof(cmdUS), nil); err != nil {
		return nil
	}
	if cmdUS.Length == 0 || cmdUS.Buffer == 0 {
		return nil
	}


	// Read the actual string
	buf := make([]uint16, cmdUS.Length/2)
	if err := windows.ReadProcessMemory(h, cmdUS.Buffer,
		(*byte)(unsafe.Pointer(&buf[0])), uintptr(cmdUS.Length), nil); err != nil {
		return nil
	}

	cmdline := windows.UTF16ToString(buf)
	cmdline = strings.ReplaceAll(cmdline, `\`, "/")
	if cmdline == "" {
		return nil
	}

	// Simple split on spaces (respecting quotes)
	var args []string
	var current strings.Builder
	inQuote := false
	for _, c := range cmdline {
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

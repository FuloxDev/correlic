//go:build windows

package procinfo

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DetectContainerID returns "" on Windows — containers are detected via image name, not cgroups.
func DetectContainerID(_ uint32) string {
	return ""
}

// DetectSessionID returns the Windows session ID for a process.
// Uses ProcessIdToSessionId from kernel32.dll.
func DetectSessionID(pid uint32) uint32 {
	var sessionID uint32
	err := windows.ProcessIdToSessionId(pid, &sessionID)
	if err != nil {
		return 0
	}
	return sessionID
}

// LookupPPID returns the parent PID of a process using CreateToolhelp32Snapshot.
func LookupPPID(pid uint32) uint32 {
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

// LookupChildPIDs returns the immediate child PIDs of a process using CreateToolhelp32Snapshot.
func LookupChildPIDs(pid uint32) []uint32 {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var children []uint32
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil
	}
	for {
		if entry.ParentProcessID == pid && entry.ProcessID != pid {
			children = append(children, entry.ProcessID)
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return children
}

// ReadProcCmdline returns the full command-line arguments for a process.
// Uses NtQueryInformationProcess to read the command line directly from
// the process PEB — microseconds fast, works even for short-lived processes
// unlike WMIC which takes hundreds of milliseconds.
func ReadProcCmdline(pid uint32) []string {
	// Need PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ to read PEB
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ,
		false,
		pid,
	)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)

	// Guard: skip PEB read if process has already exited.
	// ReadProcessMemory on a dead process returns stale pages → garbled UTF-16.
	var exitCode uint32
	if err := windows.GetExitCodeProcess(h, &exitCode); err == nil && exitCode != 259 { // STILL_ACTIVE
		return readCmdlineFallback(h)
	}

	// Get the PEB address via NtQueryInformationProcess(ProcessBasicInformation)
	var pbi processBasicInformation
	var retLen uint32
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQuery := ntdll.NewProc("NtQueryInformationProcess")
	r1, _, _ := ntQuery.Call(
		uintptr(h),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r1 != 0 { // NTSTATUS != STATUS_SUCCESS
		return readCmdlineFallback(h)
	}

	// Read RTL_USER_PROCESS_PARAMETERS pointer from PEB
	// PEB.ProcessParameters is at offset 0x20 on 64-bit
	var paramsPtr uintptr
	err = windows.ReadProcessMemory(h,
		pbi.PebBaseAddress+0x20,
		(*byte)(unsafe.Pointer(&paramsPtr)),
		unsafe.Sizeof(paramsPtr),
		nil,
	)
	if err != nil {
		return readCmdlineFallback(h)
	}

	// Read UNICODE_STRING CommandLine from RTL_USER_PROCESS_PARAMETERS
	// CommandLine is at offset 0x70 on 64-bit (after ImagePathName at 0x60)
	var cmdlineUS unicodeString
	err = windows.ReadProcessMemory(h,
		paramsPtr+0x70,
		(*byte)(unsafe.Pointer(&cmdlineUS)),
		unsafe.Sizeof(cmdlineUS),
		nil,
	)
	if err != nil || cmdlineUS.Length == 0 || cmdlineUS.Buffer == 0 {
		return readCmdlineFallback(h)
	}

	// Read the actual command line string
	cmdBuf := make([]uint16, cmdlineUS.Length/2)
	err = windows.ReadProcessMemory(h,
		cmdlineUS.Buffer,
		(*byte)(unsafe.Pointer(&cmdBuf[0])),
		uintptr(cmdlineUS.Length),
		nil,
	)
	if err != nil {
		return readCmdlineFallback(h)
	}

	cmdline := windows.UTF16ToString(cmdBuf)
	cmdline = strings.ReplaceAll(cmdline, `\`, "/")
	if cmdline == "" {
		return readCmdlineFallback(h)
	}
	return splitCmdline(cmdline)
}

// processBasicInformation matches the PROCESS_BASIC_INFORMATION struct (64-bit).
type processBasicInformation struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	_                            [4]byte // padding
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

// unicodeString matches the UNICODE_STRING struct (64-bit).
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte // padding on 64-bit
	Buffer        uintptr
}

// readCmdlineFallback gets just the exe path when PEB reading fails.
func readCmdlineFallback(h windows.Handle) []string {
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return nil
	}
	exePath := windows.UTF16ToString(buf[:size])
	exePath = strings.ReplaceAll(exePath, `\`, "/")
	return []string{exePath}
}

// splitCmdline splits a Windows command line into arguments.
func splitCmdline(cmdline string) []string {
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

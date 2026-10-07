//go:build windows

package windows

import (
	"strings"
	"unsafe"
)

// FileEvent is emitted when a file is opened/accessed.
type FileEvent struct {
	PID      uint32
	FilePath string // normalised forward-slash path
}

// FileCollector subscribes to Microsoft-Windows-Kernel-File ETW events.
type FileCollector struct {
	events chan FileEvent
}

// NewFileCollector returns a collector for kernel file events.
func NewFileCollector() *FileCollector {
	return &FileCollector{
		events: make(chan FileEvent, 8192),
	}
}

// Events returns the receive-only channel of file events.
func (c *FileCollector) Events() <-chan FileEvent {
	return c.events
}

// Handle is called for every ETW event; it filters for Kernel-File.
func (c *FileCollector) Handle(rec *EventRecord) {
	if !GUIDEquals(rec.ProviderID, GUIDKernelFile()) {
		return
	}

	// Determine the byte offset where FileName begins in UserData.
	// Each event ID (and version) has a different binary header before the
	// null-terminated UTF-16 file name string.
	//
	// Layouts confirmed via ETW manifest:
	//   https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-18990/Microsoft-Windows-Kernel-File.xml
	//
	// Event 10/11 (NameCreate/NameDelete) — template NameCreateArgs:
	//   FileKey  win:Pointer (8)  →  FileName at offset 8
	//
	// Event 12 (Create) v0 — template CreateArgs:
	//   Irp(8) + ThreadId(ptr 8) + FileObject(8) + CreateOptions(4) +
	//   CreateAttributes(4) + ShareAccess(4)  →  FileName at offset 36
	//
	// Event 12 (Create) v1 — template CreateArgs_V1:
	//   Irp(8) + FileObject(8) + IssuingThreadId(4) + CreateOptions(4) +
	//   CreateAttributes(4) + ShareAccess(4)  →  FileName at offset 32
	//
	// Event 30 (CreateNewFile) uses the same templates as event 12.

	var offset int
	switch rec.EventID {
	case 10, 11: // NameCreate, NameDelete
		offset = 8
	case 12, 30: // Create, CreateNewFile
		if rec.Version == 0 {
			offset = 36 // v0: ThreadId is a Pointer (8 bytes)
		} else {
			offset = 32 // v1+: IssuingThreadId is UInt32 (4 bytes)
		}
	default:
		return
	}

	if rec.UserData == 0 || int(rec.UserDataLen) <= offset {
		return
	}

	ud := unsafe.Pointer(rec.UserData)
	namePtr := (*uint16)(unsafe.Pointer(uintptr(ud) + uintptr(offset)))
	raw := readWCHAR(namePtr, int(rec.UserDataLen)-offset)
	if raw == "" {
		return
	}

	path := ntPathToDOS(normalisePath(raw))
	if !isValidFilePath(path) {
		return
	}

	ev := FileEvent{
		PID:      rec.ProcessID,
		FilePath: path,
	}
	select {
	case c.events <- ev:
	default:
	}
}

// isValidFilePath rejects decoded strings that are clearly not file paths.
// Checks for:
// 1. Mojibake (non-ASCII > 25%)
// 2. Shell command operators (&&, ||, |, ;) indicating a command line was parsed
// 3. Unreasonable length (real paths are under 4096 chars)
func isValidFilePath(path string) bool {
	if len(path) < 2 {
		return false
	}
	// Reject command-line strings misinterpreted as file paths.
	// Shell operators never appear in legitimate Windows/POSIX file paths.
	// "source " is the bash builtin captured when ETW sees the shell resolving
	// the command name as a file (e.g. "source /c/Users/.../file.sh 2>/dev/null").
	if strings.Contains(path, " && ") ||
		strings.Contains(path, " || ") ||
		strings.Contains(path, " | ") ||
		strings.Contains(path, "eval '") ||
		strings.Contains(path, "eval \"") ||
		strings.Contains(path, "shopt ") ||
		strings.HasPrefix(path, "source ") {
		return false
	}
	// Real file paths are under MAX_PATH (260) on Windows or 4096 on Linux.
	// Anything longer is almost certainly corrupted data or a command line.
	if len(path) > 4096 {
		return false
	}
	nonASCII := 0
	total := 0
	for _, r := range path {
		total++
		if r > 127 {
			nonASCII++
		}
	}
	return total > 0 && nonASCII*4 < total
}

// Close drains and closes the events channel.
func (c *FileCollector) Close() {
	close(c.events)
}

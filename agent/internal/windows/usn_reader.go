//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── USN Journal constants ──────────────────────────────────────────────────

const (
	fsctlQueryUSNJournal = 0x000900f4
	fsctlReadUSNJournal  = 0x000900bb

	fileAttrDirectory = 0x10 // FILE_ATTRIBUTE_DIRECTORY

	// USN_REASON_* flags we care about.
	usnReasonDataOverwrite = 0x00000001
	usnReasonDataExtend    = 0x00000002
	usnReasonFileCreate    = 0x00000100
	usnReasonFileDelete    = 0x00000200
	usnReasonRenameNewName = 0x00002000
	usnReasonClose         = 0x80000000

	// Reasons worth reporting.
	interestingReasons = usnReasonDataOverwrite | usnReasonDataExtend |
		usnReasonFileCreate | usnReasonFileDelete | usnReasonRenameNewName
)

// USNEvent is a parsed USN Journal record.
type USNEvent struct {
	FilePath  string    // full resolved path (forward-slash normalised)
	FileName  string    // just the filename
	IsDir     bool      // from FileAttributes & FILE_ATTRIBUTE_DIRECTORY
	Reason    uint32    // USN_REASON_* flags
	Timestamp time.Time // record timestamp
}

// USNReader polls the NTFS USN Journal for file change records.
type USNReader struct {
	volume       string         // e.g. "C:"
	volumeHandle windows.Handle // \\.\C:
	journalID    uint64
	nextUSN      int64
	pollInterval time.Duration
	logger       *slog.Logger

	// Path cache: FileReferenceNumber → parent directory path.
	pathCacheMu sync.RWMutex
	pathCache   map[uint64]string
}

// NewUSNReader opens the volume's USN Journal. Returns an error if the journal
// is unavailable (non-admin, non-NTFS, etc.) — callers should degrade gracefully.
func NewUSNReader(volume string, pollInterval time.Duration, logger *slog.Logger) (*USNReader, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if pollInterval == 0 {
		pollInterval = 500 * time.Millisecond
	}

	// Open volume handle: \\.\C:
	volumePath, err := syscall.UTF16PtrFromString(`\\.\` + volume)
	if err != nil {
		return nil, fmt.Errorf("usn: invalid volume %q: %w", volume, err)
	}
	handle, err := windows.CreateFile(
		volumePath,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("usn: open volume %s: %w", volume, err)
	}

	r := &USNReader{
		volume:       volume,
		volumeHandle: handle,
		pollInterval: pollInterval,
		logger:       logger,
		pathCache:    make(map[uint64]string, 8192),
	}

	// Query the journal to get journalID and current USN.
	if err := r.queryJournal(); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}

	logger.Info("USN Journal reader initialised",
		"volume", volume,
		"journal_id", r.journalID,
		"start_usn", r.nextUSN,
	)
	return r, nil
}

// queryJournal calls FSCTL_QUERY_USN_JOURNAL to get journal metadata.
func (r *USNReader) queryJournal() error {
	// USN_JOURNAL_DATA_V0: UsnJournalID (u64), FirstUsn (i64), NextUsn (i64), ...
	var buf [64]byte
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		r.volumeHandle,
		fsctlQueryUSNJournal,
		nil, 0,
		&buf[0], uint32(len(buf)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		return fmt.Errorf("usn: FSCTL_QUERY_USN_JOURNAL: %w", err)
	}

	r.journalID = binary.LittleEndian.Uint64(buf[0:8])
	// Start reading from current position (skip historical records).
	r.nextUSN = int64(binary.LittleEndian.Uint64(buf[16:24])) // NextUsn
	return nil
}

// Run polls the USN Journal and sends events to the provided channel.
// Blocks until ctx is cancelled.
func (r *USNReader) Run(ctx context.Context, out chan<- USNEvent) {
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()

	// Read buffer — 64KB per poll.
	buf := make([]byte, 64*1024)

	var totalRecords, totalDirs, totalEmitted uint64

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("USN reader stopping",
				"total_records", totalRecords,
				"total_dirs", totalDirs,
				"total_emitted", totalEmitted,
			)
			windows.CloseHandle(r.volumeHandle)
			return
		case <-ticker.C:
			records := r.readRecords(buf)
			for _, rec := range records {
				totalRecords++
				if rec.IsDir {
					totalDirs++
					continue // skip directory records natively
				}
				if rec.Reason&interestingReasons == 0 {
					continue // not a change we care about
				}
				totalEmitted++
				select {
				case out <- rec:
				default:
					// Channel full — drop rather than block
				}
			}
		}
	}
}

// readRecords reads new USN records from the journal.
func (r *USNReader) readRecords(buf []byte) []USNEvent {
	// READ_USN_JOURNAL_DATA_V0 input structure:
	//   StartUsn   int64   (0-7)
	//   ReasonMask uint32  (8-11)
	//   ReturnOnlyOnClose uint32 (12-15)
	//   Timeout    uint64  (16-23)
	//   BytesToWaitFor    uint64 (24-31)
	//   UsnJournalID      uint64 (32-39)
	var input [40]byte
	binary.LittleEndian.PutUint64(input[0:8], uint64(r.nextUSN))
	binary.LittleEndian.PutUint32(input[8:12], 0xFFFFFFFF) // all reasons
	binary.LittleEndian.PutUint32(input[12:16], 0)         // don't wait for close
	binary.LittleEndian.PutUint64(input[16:24], 0)         // no timeout
	binary.LittleEndian.PutUint64(input[24:32], 0)         // don't wait for bytes
	binary.LittleEndian.PutUint64(input[32:40], r.journalID)

	var bytesReturned uint32
	err := windows.DeviceIoControl(
		r.volumeHandle,
		fsctlReadUSNJournal,
		&input[0], uint32(len(input)),
		&buf[0], uint32(len(buf)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		// ERROR_HANDLE_EOF (38) means no new records — normal.
		if err == syscall.Errno(38) || err == windows.ERROR_HANDLE_EOF {
			return nil
		}
		r.logger.Warn("USN read failed", "error", err)
		return nil
	}

	if bytesReturned < 8 {
		return nil
	}

	// First 8 bytes = next USN to read from.
	r.nextUSN = int64(binary.LittleEndian.Uint64(buf[0:8]))

	// Parse USN_RECORD_V2 records starting at offset 8.
	var records []USNEvent
	offset := uint32(8)
	for offset < bytesReturned {
		if offset+4 > bytesReturned {
			break
		}
		recordLen := binary.LittleEndian.Uint32(buf[offset : offset+4])
		if recordLen < 60 || offset+recordLen > bytesReturned {
			break
		}

		rec := r.parseV2Record(buf[offset : offset+recordLen])
		if rec != nil {
			records = append(records, *rec)
		}
		offset += recordLen
	}
	return records
}

// parseV2Record parses a USN_RECORD_V2 from raw bytes.
// Layout (V2, 64-bit):
//
//	  0: RecordLength     uint32
//	  4: MajorVersion     uint16
//	  6: MinorVersion     uint16
//	  8: FileReferenceNumber uint64
//	 16: ParentFileReferenceNumber uint64
//	 24: Usn              int64
//	 32: TimeStamp        int64  (FILETIME)
//	 40: Reason           uint32
//	 44: SourceInfo       uint32
//	 48: SecurityId       uint32
//	 52: FileAttributes   uint32
//	 56: FileNameLength   uint16
//	 58: FileNameOffset   uint16
//	 60: FileName         [...]uint16
func (r *USNReader) parseV2Record(data []byte) *USNEvent {
	if len(data) < 60 {
		return nil
	}

	majorVersion := binary.LittleEndian.Uint16(data[4:6])
	if majorVersion != 2 {
		return nil // only handle V2
	}

	parentRef := binary.LittleEndian.Uint64(data[16:24])
	fileTimestamp := binary.LittleEndian.Uint64(data[32:40])
	reason := binary.LittleEndian.Uint32(data[40:44])
	fileAttrs := binary.LittleEndian.Uint32(data[52:56])
	fileNameLen := binary.LittleEndian.Uint16(data[56:58])
	fileNameOff := binary.LittleEndian.Uint16(data[58:60])

	isDir := fileAttrs&fileAttrDirectory != 0

	// Extract filename (UTF-16LE).
	if int(fileNameOff)+int(fileNameLen) > len(data) {
		return nil
	}
	fileName := decodeUTF16(data[fileNameOff : fileNameOff+fileNameLen])

	// Resolve full path from parent reference.
	parentPath := r.resolveParentPath(parentRef)
	var fullPath string
	if parentPath != "" {
		fullPath = parentPath + "/" + fileName
	} else {
		fullPath = fileName
	}

	// Update path cache on renames.
	if reason&usnReasonRenameNewName != 0 && isDir {
		fileRef := binary.LittleEndian.Uint64(data[8:16])
		r.pathCacheMu.Lock()
		r.pathCache[fileRef] = fullPath
		r.pathCacheMu.Unlock()
	}

	// Convert FILETIME (100ns since 1601) to Go time.
	ts := filetimeToTime(fileTimestamp)

	return &USNEvent{
		FilePath:  fullPath,
		FileName:  fileName,
		IsDir:     isDir,
		Reason:    reason,
		Timestamp: ts,
	}
}

// resolveParentPath resolves a NTFS FileReferenceNumber to a directory path.
// Uses a cache; on miss, uses OpenFileById + GetFinalPathNameByHandle.
func (r *USNReader) resolveParentPath(ref uint64) string {
	// Mask out the sequence number (top 16 bits) to get the MFT index.
	mftRef := ref & 0x0000FFFFFFFFFFFF

	r.pathCacheMu.RLock()
	if p, ok := r.pathCache[mftRef]; ok {
		r.pathCacheMu.RUnlock()
		return p
	}
	r.pathCacheMu.RUnlock()

	// Open file by ID to resolve the path.
	path := r.openByID(mftRef)
	if path != "" {
		r.pathCacheMu.Lock()
		r.pathCache[mftRef] = path
		r.pathCacheMu.Unlock()
	}
	return path
}

// openByID opens a file by its MFT reference number and resolves the full path.
func (r *USNReader) openByID(mftRef uint64) string {
	// FILE_ID_DESCRIPTOR for OpenFileById.
	// dwSize (4) + Type (4) + FileId (8) = 16 bytes
	var idDesc [16]byte
	binary.LittleEndian.PutUint32(idDesc[0:4], 16) // dwSize
	binary.LittleEndian.PutUint32(idDesc[4:8], 0)  // FileIdType = FileIdType (0)
	binary.LittleEndian.PutUint64(idDesc[8:16], mftRef)

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	openFileByID := kernel32.NewProc("OpenFileById")
	getFinalPath := kernel32.NewProc("GetFinalPathNameByHandleW")

	handle, _, err := openFileByID.Call(
		uintptr(r.volumeHandle),
		uintptr(unsafe.Pointer(&idDesc[0])),
		uintptr(windows.GENERIC_READ),
		uintptr(windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE),
		0, // lpSecurityAttributes
		uintptr(windows.FILE_FLAG_BACKUP_SEMANTICS), // required for directories
	)
	if handle == uintptr(windows.InvalidHandle) || err != nil {
		return ""
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	// Get the final path name.
	var pathBuf [512]uint16
	n, _, _ := getFinalPath.Call(
		handle,
		uintptr(unsafe.Pointer(&pathBuf[0])),
		uintptr(len(pathBuf)),
		0, // VOLUME_NAME_DOS
	)
	if n == 0 || n >= uintptr(len(pathBuf)) {
		return ""
	}

	rawPath := syscall.UTF16ToString(pathBuf[:n])

	// Strip \\?\ prefix if present.
	rawPath = strings.TrimPrefix(rawPath, `\\?\`)

	// Normalise to forward slashes.
	return strings.ReplaceAll(rawPath, `\`, "/")
}

// decodeUTF16 decodes a UTF-16LE byte slice to a Go string.
func decodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16s))
}

// filetimeToTime converts a Windows FILETIME (100ns since 1601-01-01) to time.Time.
func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	// FILETIME epoch is Jan 1 1601. Unix epoch is Jan 1 1970.
	// Difference in 100ns intervals: 116444736000000000
	const epochDiff = 116444736000000000
	nsec := (int64(ft) - epochDiff) * 100
	return time.Unix(0, nsec)
}

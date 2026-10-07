package ai_pack

import "syscall"

// isWriteOpen returns true if the open flags indicate a write operation
// (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND).
// Returns false for read-only opens and when flags are not available.
func isWriteOpen(ctx map[string]any) bool {
	if ctx == nil {
		return false
	}
	raw, ok := ctx["open_flags"]
	if !ok {
		return false
	}

	var flags int
	switch v := raw.(type) {
	case int:
		flags = v
	case float64:
		flags = int(v) // JSON unmarshals numbers as float64
	case int32:
		flags = int(v)
	case int64:
		flags = int(v)
	default:
		return false
	}

	// O_RDONLY is 0, so any write-related flag being set means it's a write.
	writeMask := syscall.O_WRONLY | syscall.O_RDWR | syscall.O_CREAT | syscall.O_TRUNC | syscall.O_APPEND
	return flags&writeMask != 0
}
